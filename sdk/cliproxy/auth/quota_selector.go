package auth

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// QuotaSnapshot captures a point-in-time read of an auth's remaining
// upstream quota. Population is provider-specific — for Codex this is
// sourced from chatgpt.com/backend-api/wham/usage. Selectors use UsedPercent
// values to prefer the credential with the most headroom.
type QuotaSnapshot struct {
	// UsedPercentPrimary is the 0-100 used percent of the short (5h) window.
	// 100 means the credential cannot serve more requests until ResetAtPrimary.
	UsedPercentPrimary int
	// UsedPercentSecondary is the 0-100 used percent of the long (7d) window.
	UsedPercentSecondary int
	// LimitReached mirrors upstream rate_limit.limit_reached and forces the
	// auth out of the candidate set regardless of UsedPercent values.
	LimitReached bool
	// ResetAtPrimary is when the primary window rolls over.
	ResetAtPrimary time.Time
	// ResetAtSecondary is when the secondary window rolls over.
	ResetAtSecondary time.Time
	// FetchedAt is when the snapshot was captured. The cache evicts when the
	// age exceeds its configured TTL.
	FetchedAt time.Time
	// PlanType is the ChatGPT subscription tier reported by wham/usage
	// (e.g. "free", "plus", "team", "pro"). Empty when the response omits
	// it. Used to refresh agent-identity accounts whose on-disk plan_type
	// was frozen at registration and would otherwise keep advertising the
	// wrong model catalog after an upgrade.
	PlanType string
}

// QuotaFetcher retrieves a current QuotaSnapshot for a single auth. Returns
// ok=false when the implementation cannot service this auth (wrong provider,
// missing credential, etc.) — the selector treats that as "no quota data"
// and falls back to its inner selector. err is for transient failures
// (network, parse) that should be logged but not poison the selector.
type QuotaFetcher interface {
	Fetch(ctx context.Context, auth *Auth) (snap QuotaSnapshot, ok bool, err error)
}

// quotaCache stores per-auth QuotaSnapshots with a TTL. Reads are lock-free
// after the initial map lookup so the Pick fast-path stays cheap.
type quotaCache struct {
	mu      sync.RWMutex
	entries map[string]QuotaSnapshot
	// recordedBytes accumulates request body bytes per auth between
	// wham/usage snapshots. Wham has ~10-min latency from request to
	// updated counter, so two accounts both reporting "1% used" can
	// actually differ by tens of MBs of in-flight traffic invisible
	// to the latest snapshot. Local bytes accounting projects the
	// real "effective used %" so the selector's pick reflects what
	// upstream WILL see at the next refresh, not what it last saw.
	// Reset to zero on every PushSnapshot (the wham value is the
	// new ground truth and supersedes whatever we accumulated since
	// the previous snapshot).
	recordedBytes map[string]int64
	ttl           time.Duration
}

// BytesPerPercentPrimary maps request body bytes to projected 5h
// used-percent units. Calibrated from empirical observation of
// watanabe.rei on 2026-06-02: ~15 MB of request volume corresponded
// to ~9 percentage points of primary growth → roughly 1.5 MB per
// 1% primary. Coarse, but precise enough for tie-breaking among
// similar-quota accounts. Override callers can tune via package
// var assignment in tests / config wiring.
//
// BytesPerPercentSecondary is the same idea for the weekly window.
// Weekly aggregates ~5-7x more traffic before saturating, hence
// the higher constant.
var (
	BytesPerPercentPrimary   int64 = 1_500_000  // 1.5 MB
	BytesPerPercentSecondary int64 = 10_000_000 // 10 MB
)

func newQuotaCache(ttl time.Duration) *quotaCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &quotaCache{
		entries:       make(map[string]QuotaSnapshot),
		recordedBytes: make(map[string]int64),
		ttl:           ttl,
	}
}

func (c *quotaCache) get(authID string, now time.Time) (QuotaSnapshot, bool) {
	c.mu.RLock()
	entry, ok := c.entries[authID]
	c.mu.RUnlock()
	if !ok {
		return QuotaSnapshot{}, false
	}
	if now.Sub(entry.FetchedAt) > c.ttl {
		return entry, false
	}
	return entry, true
}

func (c *quotaCache) set(authID string, snap QuotaSnapshot) {
	c.mu.Lock()
	c.entries[authID] = snap
	// Wham is ground truth — reset the local accumulator so the
	// next CombinedQuotaScore reflects ONLY post-snapshot traffic.
	if c.recordedBytes != nil {
		delete(c.recordedBytes, authID)
	}
	c.mu.Unlock()
}

func (c *quotaCache) recordBytes(authID string, n int64) {
	if c == nil || authID == "" || n <= 0 {
		return
	}
	c.mu.Lock()
	if c.recordedBytes == nil {
		c.recordedBytes = make(map[string]int64)
	}
	c.recordedBytes[authID] += n
	c.mu.Unlock()
}

func (c *quotaCache) getBytes(authID string) int64 {
	if c == nil || authID == "" {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.recordedBytes == nil {
		return 0
	}
	return c.recordedBytes[authID]
}

// quotaFetchTimeout caps the time we will block a single Pick on outstanding
// wham/usage fetches. Picked to give a few accounts time to respond over a
// SOCKS5 proxy while still keeping the request hot path well under one
// second.
const quotaFetchTimeout = 1500 * time.Millisecond

// UnhealthyUsedPercent is the upper bound for the "healthy" tier the filter
// keeps in the candidate pool. Anything at or above this is dropped so the
// inner round-robin selector cannot land a fresh binding on a credential
// that is one or two messages away from a 429. 90 leaves a small headroom
// for the wham/usage snapshot being slightly stale relative to actual
// upstream enforcement (we have seen accounts that wham says are at 95%
// successfully serve a few more turns, but at 100% they always 429).
const UnhealthyUsedPercent = 90

// HealthyTierUsedPercent separates the preferred tier from the merely-
// usable tier when the filter buckets candidates for distribution. Picks
// drain the preferred tier first and only fall through to the stressed
// tier when no healthy candidates remain. Set at 50 because a Plus
// account that is past the half-way mark of its 5h window has materially
// less remaining capacity to absorb a long conversation than a fresh
// one — keeping new bindings off the half-spent accounts both
// distributes load more evenly across the pool and reduces the rate at
// which we accidentally lock long conversations onto credentials that
// will exhaust mid-session.
const HealthyTierUsedPercent = 50

// DefaultNeutralUsedPercent is the score assigned to a candidate that has
// no fresh cache entry while the selector is in Async mode. 50 is a
// reasonable "we don't know yet" midpoint: real-data auths with usage
// below 50% out-rank it, real-data auths above 50% rank below it. This
// keeps unknown-quota auths in the candidate set without giving them
// unearned priority.
const DefaultNeutralUsedPercent = 50

// LeastRemainingQuotaSelector picks the codex auth with the most remaining
// upstream quota. For non-codex auth pools (or when the candidate pool has
// no usable data and the selector is in sync mode) it delegates to its
// inner selector, so it is safe to wrap any existing selector.
//
// There are two operating modes, controlled by Async on the config:
//
//   - Sync mode (default): cache misses warm inline via the configured
//     QuotaFetcher with a global per-Pick deadline. Stale or missing
//     entries that fail to warm in time are skipped during selection.
//
//   - Async mode: cache misses are never warmed inline; instead they are
//     treated as "unknown quota" and enter the candidate set at the
//     neutral used-percent score. An external goroutine (typically a
//     quota.Refresher) is expected to keep the cache populated via
//     PushSnapshot. This keeps Pick latency bounded to plain cache reads
//     and prevents a slow SOCKS5 first-call from collapsing the candidate
//     pool to whichever credential happens to respond fastest.
type LeastRemainingQuotaSelector struct {
	inner              Selector
	fetcher            QuotaFetcher
	cache              *quotaCache
	async              bool
	neutralUsedPercent int
}

// LeastRemainingQuotaConfig configures the selector.
type LeastRemainingQuotaConfig struct {
	// Inner is the selector used when no quota data is available or the
	// candidate pool is not Codex. Required.
	Inner Selector
	// Fetcher loads a QuotaSnapshot for one auth at a time. Required even
	// in Async mode — used by tests and as a safety net if the caller
	// wants to fall back to inline warming for a specific selector
	// instance.
	Fetcher QuotaFetcher
	// TTL controls how long a cached snapshot is considered fresh.
	// Defaults to 5 minutes when zero.
	TTL time.Duration
	// Async, when true, disables the inline cache-warm fast path. The
	// caller takes responsibility for populating the cache via
	// PushSnapshot (see quota.Refresher). Cache misses become "unknown
	// quota" candidates that compete at the neutral score rather than
	// being dropped from the pool.
	Async bool
	// NeutralUsedPercent overrides DefaultNeutralUsedPercent. Ignored in
	// sync mode.
	NeutralUsedPercent int
}

// NewLeastRemainingQuotaSelector constructs the selector. A nil Inner or
// Fetcher panics — these are programmer errors.
func NewLeastRemainingQuotaSelector(cfg LeastRemainingQuotaConfig) *LeastRemainingQuotaSelector {
	if cfg.Inner == nil {
		panic("cliproxy auth: LeastRemainingQuotaSelector requires Inner")
	}
	if cfg.Fetcher == nil {
		panic("cliproxy auth: LeastRemainingQuotaSelector requires Fetcher")
	}
	neutral := cfg.NeutralUsedPercent
	if neutral <= 0 || neutral >= 100 {
		neutral = DefaultNeutralUsedPercent
	}
	return &LeastRemainingQuotaSelector{
		inner:              cfg.Inner,
		fetcher:            cfg.Fetcher,
		cache:              newQuotaCache(cfg.TTL),
		async:              cfg.Async,
		neutralUsedPercent: neutral,
	}
}

// PrimaryUsedPercent returns the cached UsedPercentPrimary for an auth,
// or (0, false) when no fresh snapshot is available. Used by sibling
// selectors that want a secondary score for tie-breaks without holding
// a reference to the cache directly.
func (s *LeastRemainingQuotaSelector) PrimaryUsedPercent(authID string) (int, bool) {
	if s == nil || s.cache == nil || authID == "" {
		return 0, false
	}
	snap, fresh := s.cache.get(authID, time.Now())
	if !fresh {
		return 0, false
	}
	return snap.UsedPercentPrimary, true
}

// CombinedQuotaScore returns a single comparable score that orders auths
// by EFFECTIVE used % across both windows. Smaller score = more headroom
// = preferred for the next binding.
//
// Encoding: `effective_primary * 100 + effective_secondary` where
//
//	effective_primary   = wham.UsedPercentPrimary   + recorded_bytes / BytesPerPercentPrimary
//	effective_secondary = wham.UsedPercentSecondary + recorded_bytes / BytesPerPercentSecondary
//
// Primary dominates the rank (×100 weight); secondary breaks ties cleanly
// — two accounts both at 1% primary but at 1% vs 63% weekly are correctly
// ranked. The recorded-bytes augmentation is the wham-delay compensator:
// wham updates every ~10 min but in-flight traffic accumulates faster.
// Two accounts both reporting "1% used" can differ by tens of MB of
// post-snapshot traffic; the projection makes the score reflect what the
// NEXT snapshot will likely show, not what the last one already showed.
// On every PushSnapshot the bytes counter resets so we don't double-count
// volume that wham has now absorbed into its real value.
//
// Returns (0, false) when no fresh snapshot is available — caller treats
// a missing score as neutral (fresh accounts rank with no penalty).
func (s *LeastRemainingQuotaSelector) CombinedQuotaScore(authID string) (int, bool) {
	if s == nil || s.cache == nil || authID == "" {
		return 0, false
	}
	snap, fresh := s.cache.get(authID, time.Now())
	if !fresh {
		return 0, false
	}
	bytes := s.cache.getBytes(authID)
	primaryProj := 0
	secondaryProj := 0
	if bytes > 0 {
		if BytesPerPercentPrimary > 0 {
			primaryProj = int(bytes / BytesPerPercentPrimary)
		}
		if BytesPerPercentSecondary > 0 {
			secondaryProj = int(bytes / BytesPerPercentSecondary)
		}
	}
	effectivePrimary := snap.UsedPercentPrimary + primaryProj
	effectiveSecondary := snap.UsedPercentSecondary + secondaryProj
	return effectivePrimary*100 + effectiveSecondary, true
}

// RecordRequestBytes accumulates the inbound request body size against
// the named auth's local quota counter. Called by the monitor middleware
// once an auth is picked and the request body size is known. The
// accumulated total is added to the next CombinedQuotaScore call (as a
// projected used-% delta on top of the wham snapshot) and is reset by
// PushSnapshot when wham next reflects the consumption.
//
// No-op when n is zero or negative, when the selector has no cache, or
// when authID is empty.
func (s *LeastRemainingQuotaSelector) RecordRequestBytes(authID string, n int64) {
	if s == nil || s.cache == nil {
		return
	}
	s.cache.recordBytes(authID, n)
}

// Snapshot returns the FULL cached QuotaSnapshot for the named auth and
// whether the entry is still within the cache TTL. Used by the
// management auth-files endpoint to surface the refresher's wham/usage
// data (used percent, limit_reached, reset times) so operators can read
// quota state from the same panel they use to manage credentials. Returns
// (zero, false) when the auth has no cache entry or its entry has aged
// past the TTL.
func (s *LeastRemainingQuotaSelector) Snapshot(authID string) (QuotaSnapshot, bool) {
	if s == nil || s.cache == nil || authID == "" {
		return QuotaSnapshot{}, false
	}
	return s.cache.get(authID, time.Now())
}

// PushSnapshot inserts an externally-fetched QuotaSnapshot into the
// selector's cache. The Refresher uses this to keep the cache populated
// without going through the Pick path. FetchedAt is auto-populated when
// the caller leaves it zero.
func (s *LeastRemainingQuotaSelector) PushSnapshot(authID string, snap QuotaSnapshot) {
	if s == nil || s.cache == nil || authID == "" {
		return
	}
	if snap.FetchedAt.IsZero() {
		snap.FetchedAt = time.Now()
	}
	s.cache.set(authID, snap)
}

// Pick implements Selector as a *filter* over the candidate pool: it
// removes credentials that have no remaining headroom (limit_reached
// upstream, or used_percent at/above UnhealthyUsedPercent), buckets
// the rest into a preferred and a stressed tier, and delegates the
// actual pick to the inner selector with the slimmed-down list.
//
// The previous "rank by lowest used_percent and pick the single
// minimum" policy concentrated every new binding onto whichever
// credential happened to be at 1% at the moment of the cache miss —
// the random tie-break only fired when two snapshots reported
// identical percentages, which essentially never happens with real
// wham/usage data. Across a few hours of traffic that produced 3-6
// session bindings on the freshest account while every other healthy
// credential sat idle. Returning a slimmed candidate list and letting
// the inner round-robin selector cycle through it restores actual
// load distribution while still keeping exhausted credentials out of
// rotation.
func (s *LeastRemainingQuotaSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	if s == nil || s.inner == nil {
		return nil, &Error{Code: "auth_not_found", Message: "quota selector not initialized"}
	}
	entry := selectorLogEntry(ctx)

	available, err := getAvailableAuths(auths, provider, model, time.Now())
	if err != nil {
		return nil, err
	}

	codexCandidates := filterCodexAuths(available)
	if len(codexCandidates) == 0 {
		// No Codex auths in the candidate set — quota policy does not apply.
		return s.inner.Pick(ctx, provider, model, opts, auths)
	}

	// Inline warming only happens in sync mode. In async mode the caller
	// (typically a quota.Refresher) owns cache population and we never
	// block Pick on a network round-trip — cache misses are treated as
	// "unknown, presume healthy" and stay in the pool.
	if !s.async {
		now := time.Now()
		stale := make([]*Auth, 0, len(codexCandidates))
		for _, candidate := range codexCandidates {
			if _, fresh := s.cache.get(candidate.ID, now); !fresh {
				stale = append(stale, candidate)
			}
		}
		if len(stale) > 0 {
			s.warmCache(ctx, stale, entry)
		}
	}

	now := time.Now()

	// Priority gate. Restrict the codex candidates to the highest
	// `priority` level that still has a usable (not excluded) account,
	// so operators can force a drain order: tag short-lived accounts
	// with a higher priority and every new binding lands on them until
	// they saturate, at which point the gate falls through to the next
	// level automatically — no need to disable the long-lived accounts
	// by hand. Non-codex auths always pass through (priority is a
	// codex-quota concept). When no priority is set anywhere every codex
	// auth shares level 0 and this is a no-op.
	// Hard model-support isolation (unbound path only — a bound session is
	// served by the affinity layer before it reaches here). Accounts that have
	// LEARNED they cannot serve this model (durable registry
	// model_not_supported marker, e.g. gpt-5.6-sol on a ChatGPT account that
	// lacks the entitlement) are EXCLUDED from selection, not merely
	// deprioritised: serving such a request from a different, weaker model is
	// worse than failing it, so the request must land on an account that
	// genuinely supports the requested model. When none does, surface that
	// plainly instead of silently substituting a model the caller did not ask
	// for. Reason-scoped to model_not_supported — NEVER the generic suspension
	// marker — so a transient 429/401 account is not excluded here and
	// priority fall-through stays intact.
	capable, unsupported := s.splitByModelSupport(auths, model)
	if len(unsupported) > 0 {
		if len(capable) == 0 {
			entry.Warnf("quota-selector: no account supports model %s (all %d candidates marked model_not_supported) | provider=%s", model, len(unsupported), provider)
			return nil, &Error{
				Code:       "model_not_supported",
				Message:    `{"error":{"type":"invalid_request_error","message":"No available credential supports the requested model. Pick a model your accounts are entitled to, or add an account that supports it."}}`,
				HTTPStatus: http.StatusBadRequest,
			}
		}
		entry.Debugf("quota-selector: excluding %d account(s) that cannot serve %s | provider=%s", len(unsupported), model, provider)
		return s.selectFromPool(ctx, provider, model, opts, capable, now, entry, true)
	}
	return s.selectFromPool(ctx, provider, model, opts, auths, now, entry, true)
}

// selectFromPool runs the priority gate + quota partition + inner selection
// over one candidate pool. allowExhaustedFallback controls the "everything is
// exhausted" tail: when true it mirrors the original last-ditch behaviour (let
// the inner selector try the whole pool anyway — one of the exhausted accounts
// may still serve a turn, and refusing would force a 503 when the request could
// still succeed); when false it returns (nil, nil) so a caller running a
// multi-pool preference (see Pick) can move on to the next pool instead of
// force-picking an exhausted account.
func (s *LeastRemainingQuotaSelector) selectFromPool(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, poolAuths []*Auth, now time.Time, entry *log.Entry, allowExhaustedFallback bool) (*Auth, error) {
	gated := s.gateByPriority(poolAuths, model, now)
	healthy, stressed, excluded := s.partitionByQuota(gated, model, now)

	// Pick from the healthiest tier that has any candidates. Falling back to
	// the stressed tier (50-89% used) before draining the healthy tier matches
	// the operator intent: prefer the freshest credentials for new bindings,
	// only reach into the half-spent ones when no fresh accounts remain.
	pool := healthy
	tier := "healthy"
	// Adaptive floor: with a small candidate set the hard 50%-used tier gate
	// can strand capacity (a 9%-used account soaks up all traffic while an
	// 80%-used sibling sits idle). When healthy has fewer than the floor,
	// promote the least-5h-used stressed accounts so the inner selector can
	// spread across both. With a large healthy tier this never fires.
	if len(pool) < quotaSelectorHealthyFloor && len(stressed) > 0 {
		promoted := promoteLeastUsedStressed(stressed, quotaSelectorHealthyFloor-len(pool), now, s.cache)
		if len(promoted) > 0 {
			pool = append(append(make([]*Auth, 0, len(healthy)+len(promoted)), healthy...), promoted...)
			tier = "healthy+promoted"
		}
	}
	if len(pool) == 0 {
		pool = stressed
		tier = "stressed"
	}
	if len(pool) == 0 {
		if !allowExhaustedFallback {
			return nil, nil
		}
		entry.Warnf("quota-selector: no healthy candidates | excluded=%d provider=%s model=%s", excluded, provider, model)
		return s.inner.Pick(ctx, provider, model, opts, poolAuths)
	}

	picked, errInner := s.inner.Pick(ctx, provider, model, opts, pool)
	if errInner != nil {
		return nil, errInner
	}
	if picked == nil {
		return nil, &Error{Code: "auth_not_found", Message: "inner selector returned no auth"}
	}
	pickedSnap, hasSnap := s.cache.get(picked.ID, now)
	if hasSnap {
		entry.Infof("quota-selector: picked | auth=%s tier=%s priority=%d primary_used=%d%% secondary_used=%d%% pool_size=%d excluded=%d provider=%s model=%s",
			picked.ID, tier, codexAuthPriority(picked), pickedSnap.UsedPercentPrimary, pickedSnap.UsedPercentSecondary, len(pool), excluded, provider, model)
	} else {
		entry.Infof("quota-selector: picked | auth=%s tier=%s priority=%d primary_used=unknown pool_size=%d excluded=%d provider=%s model=%s",
			picked.ID, tier, codexAuthPriority(picked), len(pool), excluded, provider, model)
	}
	return picked, nil
}

// QuotaLimitIgnored reports whether an operator forced this auth to stay
// schedulable regardless of its quota snapshot. Upstream sometimes reports
// limit_reached (or 100% used) for an account that still serves requests, and
// the snapshot then locks it out of selection until the window resets. The
// override is the inverse of ForceCooldown: instead of taking a healthy account
// out of rotation, it keeps a supposedly-exhausted one in.
//
// Overridden accounts are not treated as fresh: effectiveQuotaSnapshot clamps
// them into the stressed tier, so a genuinely healthy account is still
// preferred and the override only matters once nothing better is available.
func QuotaLimitIgnored(a *Auth) bool {
	if a == nil || a.Attributes == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(a.Attributes["ignore_quota_limit"]), "true")
}

// effectiveQuotaSnapshot applies the operator's ignore-quota-limit override to a
// snapshot before it drives selection: limit_reached is cleared and the used
// percentages are clamped just below the exclusion threshold, which keeps the
// account selectable while ranking it behind accounts with real headroom.
func effectiveQuotaSnapshot(a *Auth, snap QuotaSnapshot) QuotaSnapshot {
	if !QuotaLimitIgnored(a) {
		return snap
	}
	snap.LimitReached = false
	if snap.UsedPercentPrimary >= UnhealthyUsedPercent {
		snap.UsedPercentPrimary = UnhealthyUsedPercent - 1
	}
	if snap.UsedPercentSecondary >= UnhealthyUsedPercent {
		snap.UsedPercentSecondary = UnhealthyUsedPercent - 1
	}
	return snap
}

// splitByModelSupport partitions the candidate auths by whether a codex account
// has LEARNED it cannot serve `model` (durable registry model_not_supported
// marker). Non-codex auths and unmarked codex auths go to capable; marked codex
// auths go to unsupported and are excluded from selection for this model.
// Reason-scoped: only the model_not_supported marker moves an account to
// unsupported — a transient quota/401 suspension does NOT (that is handled by
// the ModelState-driven partition, which recovers on cooldown), so this never
// breaks priority fall-through. The marker carries a TTL, so an account
// recovers automatically if the entitlement is later granted.
func (s *LeastRemainingQuotaSelector) splitByModelSupport(auths []*Auth, model string) (capable, unsupported []*Auth) {
	reg := registry.GetGlobalRegistry()
	modelKey := canonicalModelKey(model)
	if reg == nil || modelKey == "" {
		return auths, nil
	}
	for _, a := range auths {
		if a == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(a.Provider), "codex") && reg.IsClientModelUnsupported(a.ID, modelKey) {
			unsupported = append(unsupported, a)
			continue
		}
		capable = append(capable, a)
	}
	return capable, unsupported
}

// partitionByQuota splits the inbound auth list into three groups based
// on cached wham/usage data:
//
//   - healthy:  non-codex auths AND codex auths with UsedPercentPrimary
//     below HealthyTierUsedPercent. Codex auths with no cache entry
//     (in async mode) also land here so a fresh account is not
//     penalised while the refresher is still warming up.
//   - stressed: codex auths with UsedPercentPrimary in
//     [HealthyTierUsedPercent, UnhealthyUsedPercent). Usable but not
//     preferred for new bindings.
//   - excluded count: how many candidates were dropped because the
//     credential is at or above UnhealthyUsedPercent or because
//     wham/usage reported LimitReached=true.
//
// Non-codex auths always land in healthy — quota policy does not apply
// outside the Codex pool.
func (s *LeastRemainingQuotaSelector) partitionByQuota(auths []*Auth, model string, now time.Time) (healthy []*Auth, stressed []*Auth, excluded int) {
	for _, a := range auths {
		if a == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
			healthy = append(healthy, a)
			continue
		}
		// ModelState is the real-time signal: MarkResult flips
		// Unavailable / Quota.Exceeded the instant an upstream 429
		// lands, whereas the wham/usage cache snapshot the tiers
		// below consult can lag the refresher by minutes. Honour the
		// real-time block first so an account that just 429'd is
		// excluded from the pool immediately — otherwise the priority
		// gate keeps maxPriority pinned to its level (it still looks
		// healthy in the stale cache) and every lower-priority live
		// account is locked out, starving the pool for minutes until
		// the refresher catches up.
		if blocked, _, _ := isAuthBlockedForModel(a, model, now); blocked {
			excluded++
			continue
		}
		snap, fresh := s.cache.get(a.ID, now)
		snap = effectiveQuotaSnapshot(a, snap)
		if !fresh {
			if s.async {
				// Async: no fresh data ≠ unhealthy. The refresher will
				// eventually report and re-tier her on a later Pick.
				healthy = append(healthy, a)
				continue
			}
			// Sync warm-path attempted before this call. Still no
			// data → drop from selection (consistent with the prior
			// behaviour for sync mode).
			excluded++
			continue
		}
		if snap.LimitReached {
			excluded++
			continue
		}
		if snap.UsedPercentPrimary >= UnhealthyUsedPercent {
			excluded++
			continue
		}
		if snap.UsedPercentPrimary < HealthyTierUsedPercent {
			healthy = append(healthy, a)
			continue
		}
		stressed = append(stressed, a)
	}
	return healthy, stressed, excluded
}

// quotaSelectorHealthyFloor is the minimum number of candidates the Pick
// pool tries to hold before it stops promoting stressed accounts into the
// healthy tier. 2 keeps at least one alternative in rotation so a single
// fresh account does not soak up every new binding while a half-spent
// sibling sits idle. Package var so tests (and future config wiring) can
// tune it.
var quotaSelectorHealthyFloor = 2

// gateByPriority restricts the codex auths to the highest `priority` level
// that still has a usable (not excluded) account, dropping every codex auth
// at a lower level. Non-codex auths always pass through untouched — priority
// is a codex-quota concept only.
//
// Draining semantics: an operator tags short-lived accounts with a higher
// priority; while any of them can still serve (not limit_reached, not at/above
// UnhealthyUsedPercent) they are the only codex candidates, so every new
// binding lands on them. When they all saturate, the highest usable level
// recomputes to the next priority down and the long-lived accounts take over
// — automatically, and reversibly once the high-priority accounts' short
// window resets. When no priority is configured anywhere, every codex auth
// shares level 0 and this returns the input unchanged.
func (s *LeastRemainingQuotaSelector) gateByPriority(auths []*Auth, model string, now time.Time) []*Auth {
	maxPriority := 0
	found := false
	for _, a := range auths {
		if a == nil || !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
			continue
		}
		if s.isExcludedNow(a, model, now) {
			continue
		}
		p := codexAuthPriority(a)
		if !found || p > maxPriority {
			maxPriority = p
			found = true
		}
	}
	if !found {
		// No usable codex auth at all — leave the list untouched so the
		// caller's own empty-pool fallback decides what to do.
		return auths
	}
	out := make([]*Auth, 0, len(auths))
	for _, a := range auths {
		if a == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
			out = append(out, a)
			continue
		}
		// Keep every codex auth at the winning level, even ones that are
		// currently excluded — partitionByQuota drops the excluded ones,
		// but their membership is what defines "this level still exists".
		if codexAuthPriority(a) == maxPriority {
			out = append(out, a)
		}
	}
	return out
}

// isExcludedNow reports whether an auth would be dropped by partitionByQuota
// right now. An auth is excluded when EITHER signal says it is unavailable:
//   - ModelState (real-time): MarkResult flips Unavailable / Quota.Exceeded
//     the instant an upstream 429 lands. This is the authoritative signal —
//     without it, the priority gate would keep maxPriority pinned to a
//     just-429'd account's level (the wham cache still shows it healthy) and
//     lock out every lower-priority live account for minutes until the
//     refresher catches up.
//   - quota cache snapshot (wham/usage, may lag the refresher by minutes):
//     limit_reached or 5h used at/above UnhealthyUsedPercent.
//
// No fresh snapshot is treated as usable, matching the async partition path
// the production refresher drives.
func (s *LeastRemainingQuotaSelector) isExcludedNow(a *Auth, model string, now time.Time) bool {
	if a == nil {
		return true
	}
	if blocked, _, _ := isAuthBlockedForModel(a, model, now); blocked {
		return true
	}
	snap, fresh := s.cache.get(a.ID, now)
	if !fresh {
		return false
	}
	snap = effectiveQuotaSnapshot(a, snap)
	if snap.LimitReached {
		return true
	}
	return snap.UsedPercentPrimary >= UnhealthyUsedPercent
}

// promoteLeastUsedStressed returns up to n stressed accounts with the lowest
// 5h used-percent — the ones with the most short-window headroom, hence the
// safest to add to the healthy pool when it is under the floor. A stressed
// account with no fresh snapshot ranks worst (treated as 100% used) so a
// freshly-known-half-spent account is preferred over an unknown one.
func promoteLeastUsedStressed(stressed []*Auth, n int, now time.Time, cache *quotaCache) []*Auth {
	if n <= 0 || len(stressed) == 0 {
		return nil
	}
	type scored struct {
		auth *Auth
		used int
	}
	ranked := make([]scored, 0, len(stressed))
	for _, a := range stressed {
		used := 100
		if snap, ok := cache.get(a.ID, now); ok {
			used = snap.UsedPercentPrimary
		}
		ranked = append(ranked, scored{auth: a, used: used})
	}
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].used < ranked[j].used })
	if n > len(ranked) {
		n = len(ranked)
	}
	out := make([]*Auth, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, ranked[i].auth)
	}
	return out
}

// codexAuthPriority reads the account's drain priority. Higher = drained
// first. Mirrors the auth-files list endpoint's precedence: Attributes
// (set by the config synthesizer from a JSON "priority" field) wins, else
// Metadata (set via UploadAuthFile / PatchAuthFileFields). Absent or
// unparseable → 0.
func codexAuthPriority(auth *Auth) int {
	if auth == nil {
		return 0
	}
	if auth.Attributes != nil {
		if raw := strings.TrimSpace(auth.Attributes["priority"]); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				return parsed
			}
		}
	}
	if auth.Metadata != nil {
		switch v := auth.Metadata["priority"].(type) {
		case float64:
			return int(v)
		case int:
			return v
		case int64:
			return int(v)
		case json.Number:
			if parsed, err := v.Int64(); err == nil {
				return int(parsed)
			}
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return parsed
			}
		}
	}
	return 0
}

// warmCache fetches snapshots for the given auths concurrently with a
// global timeout. Results are stored in the cache; any failures are
// logged at debug level and treated as "no data" by the caller.
func (s *LeastRemainingQuotaSelector) warmCache(ctx context.Context, auths []*Auth, entry *log.Entry) {
	fetchCtx, cancel := context.WithTimeout(ctx, quotaFetchTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, target := range auths {
		auth := target
		if auth == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap, ok, fetchErr := s.fetcher.Fetch(fetchCtx, auth)
			if fetchErr != nil {
				entry.Debugf("quota-selector: fetch failed | auth=%s err=%v", auth.ID, fetchErr)
				return
			}
			if !ok {
				return
			}
			if snap.FetchedAt.IsZero() {
				snap.FetchedAt = time.Now()
			}
			s.cache.set(auth.ID, snap)
		}()
	}
	wg.Wait()
}

// pickLowest returns the auth with the smallest primary used-percent among
// the candidate pool, along with the snapshot used for ranking and a flag
// indicating whether that snapshot came from cached real data. Ties on
// primary are broken by secondary used-percent, and final ties are
// broken by a uniform random choice so equal-load credentials see
// balanced traffic.
//
// In sync mode, candidates without a fresh cache entry are dropped (the
// caller has already attempted to warm them). In async mode, missing
// entries enter the pool at the neutral used-percent score so they
// remain selectable while the background refresher catches up; this
// prevents a slow first wham/usage from permanently collapsing the
// candidate pool to whichever credential responded fastest.
func (s *LeastRemainingQuotaSelector) pickLowest(auths []*Auth, now time.Time) (*Auth, QuotaSnapshot, bool) {
	type candidate struct {
		auth    *Auth
		snap    QuotaSnapshot
		hasData bool
	}
	neutralSnap := QuotaSnapshot{
		UsedPercentPrimary:   s.neutralUsedPercent,
		UsedPercentSecondary: s.neutralUsedPercent,
	}
	candidates := make([]candidate, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		snap, fresh := s.cache.get(auth.ID, now)
		snap = effectiveQuotaSnapshot(auth, snap)
		if !fresh {
			if !s.async {
				continue
			}
			// Async mode: include at the neutral score. We do not import
			// LimitReached / ResetAt fields from the stale entry — only the
			// most recent successful fetch should drive that decision, and
			// missing data must not lock the auth out.
			candidates = append(candidates, candidate{auth: auth, snap: neutralSnap, hasData: false})
			continue
		}
		if snap.LimitReached {
			continue
		}
		candidates = append(candidates, candidate{auth: auth, snap: snap, hasData: true})
	}
	if len(candidates) == 0 {
		return nil, QuotaSnapshot{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].snap.UsedPercentPrimary != candidates[j].snap.UsedPercentPrimary {
			return candidates[i].snap.UsedPercentPrimary < candidates[j].snap.UsedPercentPrimary
		}
		if candidates[i].snap.UsedPercentSecondary != candidates[j].snap.UsedPercentSecondary {
			return candidates[i].snap.UsedPercentSecondary < candidates[j].snap.UsedPercentSecondary
		}
		return candidates[i].auth.ID < candidates[j].auth.ID
	})
	// Group all candidates that share the minimum (primary, secondary) tuple
	// and return a uniformly-random one. With several brand-new auths all
	// reading 0/0 — or several async candidates all at the neutral score —
	// this keeps the first request from each new conversation from always
	// landing on the same alphabetically-first credential.
	best := candidates[0]
	tieEnd := 1
	for tieEnd < len(candidates) &&
		candidates[tieEnd].snap.UsedPercentPrimary == best.snap.UsedPercentPrimary &&
		candidates[tieEnd].snap.UsedPercentSecondary == best.snap.UsedPercentSecondary {
		tieEnd++
	}
	if tieEnd == 1 {
		return best.auth, best.snap, best.hasData
	}
	chosen := candidates[rand.IntN(tieEnd)]
	return chosen.auth, chosen.snap, chosen.hasData
}

func filterCodexAuths(auths []*Auth) []*Auth {
	out := make([]*Auth, 0, len(auths))
	for _, a := range auths {
		if a == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
			out = append(out, a)
		}
	}
	return out
}
