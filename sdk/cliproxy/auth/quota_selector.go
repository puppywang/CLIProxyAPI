package auth

import (
	"context"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

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
	ttl     time.Duration
}

func newQuotaCache(ttl time.Duration) *quotaCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &quotaCache{
		entries: make(map[string]QuotaSnapshot),
		ttl:     ttl,
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
	c.mu.Unlock()
}

// quotaFetchTimeout caps the time we will block a single Pick on outstanding
// wham/usage fetches. Picked to give a few accounts time to respond over a
// SOCKS5 proxy while still keeping the request hot path well under one
// second.
const quotaFetchTimeout = 1500 * time.Millisecond

// LeastRemainingQuotaSelector picks the codex auth with the most remaining
// upstream quota. For non-codex auth pools (or when no quota data is
// available) it delegates to its inner selector, so it is safe to wrap any
// existing selector.
//
// Per-auth snapshots are cached for the selector's configured TTL. On every
// Pick we warm any stale or missing entries in parallel with a global
// quotaFetchTimeout — the request hot path never blocks for more than that
// regardless of how many auths are in the pool.
type LeastRemainingQuotaSelector struct {
	inner   Selector
	fetcher QuotaFetcher
	cache   *quotaCache
}

// LeastRemainingQuotaConfig configures the selector.
type LeastRemainingQuotaConfig struct {
	// Inner is the selector used when no quota data is available or the
	// candidate pool is not Codex. Required.
	Inner Selector
	// Fetcher loads a QuotaSnapshot for one auth at a time. Required.
	Fetcher QuotaFetcher
	// TTL controls how long a cached snapshot is considered fresh.
	// Defaults to 5 minutes when zero.
	TTL time.Duration
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
	return &LeastRemainingQuotaSelector{
		inner:   cfg.Inner,
		fetcher: cfg.Fetcher,
		cache:   newQuotaCache(cfg.TTL),
	}
}

// Pick implements Selector. See the type comment for the policy summary.
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

	now = time.Now()
	picked := s.pickLowest(codexCandidates, now)
	if picked == nil {
		// Cold cache or all fetches failed — let the inner selector decide.
		// The async path will populate the cache for the next Pick.
		return s.inner.Pick(ctx, provider, model, opts, auths)
	}

	// Only return the quota-picked auth when it is part of the original
	// `available` list (it always is by construction here, but check guards
	// against a future refactor that filters codexCandidates further).
	for _, candidate := range available {
		if candidate.ID == picked.ID {
			snap, _ := s.cache.get(picked.ID, now)
			entry.Infof("quota-selector: picked | auth=%s primary_used=%d%% secondary_used=%d%% provider=%s model=%s",
				picked.ID, snap.UsedPercentPrimary, snap.UsedPercentSecondary, provider, model)
			return picked, nil
		}
	}
	return s.inner.Pick(ctx, provider, model, opts, auths)
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
// those that have a fresh, non-limit-reached cache entry. Ties on primary
// are broken by secondary used-percent, and final ties are broken by a
// uniform random choice so equal-load credentials see balanced traffic.
func (s *LeastRemainingQuotaSelector) pickLowest(auths []*Auth, now time.Time) *Auth {
	type candidate struct {
		auth *Auth
		snap QuotaSnapshot
	}
	candidates := make([]candidate, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		snap, fresh := s.cache.get(auth.ID, now)
		if !fresh {
			continue
		}
		if snap.LimitReached {
			continue
		}
		candidates = append(candidates, candidate{auth: auth, snap: snap})
	}
	if len(candidates) == 0 {
		return nil
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
	// reading 0/0, this keeps the first request from each new conversation
	// from always landing on the same alphabetically-first credential.
	best := candidates[0]
	tieEnd := 1
	for tieEnd < len(candidates) &&
		candidates[tieEnd].snap.UsedPercentPrimary == best.snap.UsedPercentPrimary &&
		candidates[tieEnd].snap.UsedPercentSecondary == best.snap.UsedPercentSecondary {
		tieEnd++
	}
	if tieEnd == 1 {
		return best.auth
	}
	return candidates[rand.IntN(tieEnd)].auth
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
