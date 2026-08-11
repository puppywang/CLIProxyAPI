// Package quota provides per-credential quota lookups for the auth selectors.
//
// This file implements Refresher, a background loop that periodically calls
// the Fetcher for every codex auth and pushes the resulting snapshot into
// the LeastRemainingQuotaSelector's cache. Moving the wham/usage lookups
// off the request hot path lets us:
//
//   - tolerate the slow first request through a freshly built SOCKS5
//     transport without timing out the credential selection;
//   - bound concurrent wham/usage calls (default 2) instead of fanning out
//     one per candidate, which previously caused the SOCKS5 dialer to
//     contend with itself and produce a cluster of context-deadline
//     failures for everything but the fastest-completing call;
//   - apply per-auth exponential backoff when a credential's wham/usage
//     keeps failing, so a broken token does not get hammered on every
//     cycle.
package quota

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// AuthLister returns the current auth pool. The refresher copies the
// slice on each cycle so callers may safely mutate the underlying store
// between calls.
type AuthLister func() []*coreauth.Auth

// SnapshotPusher delivers a fresh QuotaSnapshot to the selector's cache.
// Implementations must be safe for concurrent calls.
type SnapshotPusher func(authID string, snap coreauth.QuotaSnapshot)

// Default operational parameters. Exported for tests and for callers that
// want to mirror the defaults when constructing custom configurations.
// DefaultRefreshInterval is both the regular per-auth refresh cadence
// and the cap on consecutive-failure exponential backoff. 10 minutes is
// the right scale: scheduling decisions tolerate quota data that's a
// few minutes stale, OpenAI's account-wide rate-limit windows roll over
// at the minutes scale, and we never want to wait beyond this for a
// retry even if many fetches have failed in a row.
const (
	DefaultRefreshInterval = 10 * time.Minute
	DefaultConcurrency     = 2
	MaxBackoff             = 10 * time.Minute
	// quotaCooldownProbeInterval is how often the refresher re-checks an
	// auth sitting in a cooldown. Normally a cooldown parks the auth until
	// its advertised reset_at; but wham can roll the window over EARLIER
	// (the account recovers before the cooldown deadline), so we keep a
	// slow probe to catch the early reset promptly instead of discovering
	// it hours later.
	quotaCooldownProbeInterval = 30 * time.Minute
)

// Refresher periodically refreshes per-auth quota snapshots in the
// background. It is started via Start(ctx) and stopped via Stop().
//
// The zero value is not usable; call NewRefresher.
type Refresher struct {
	fetcher        coreauth.QuotaFetcher
	lister         AuthLister
	pusher         SnapshotPusher
	staleCleaner   StaleCooldownClearer
	limitReachedFn LimitReachedSetter
	planUpdater    PlanUpdater
	probeFn        ProbePinFunc
	interval       time.Duration
	concurrency    int

	mu       sync.Mutex
	backoffs map[string]*backoffState
	cancel   context.CancelFunc
	done     chan struct{}
	triggers chan string
	started  bool

	// snapshots remembers the last successful snapshot per auth so the
	// refresher can detect a *floating* quota window: an account that has
	// never made a real request reports reset_at ≈ fetched_at + 7d on
	// every fetch (the window never starts counting). Two consecutive
	// observations of a near-full window + zero usage trigger a probe so
	// the window gets anchored. Guarded by mu.
	snapshots map[string]coreauth.QuotaSnapshot
	// probedAt records the last probe attempt per auth so a failed or
	// ineffective probe is not retried more often than quotaProbeMinInterval.
	probedAt map[string]time.Time

	// deadMu guards dead. dead records auths whose most recent fetch
	// returned a terminal "account unusable" upstream signal (see
	// classifyDeadAccount). It is purely informational — surfaced to the
	// monitor quota panel so an operator can spot and delete dead
	// credentials — and never gates selection. Entries clear on the next
	// successful fetch (the account recovered).
	deadMu sync.RWMutex
	dead   map[string]deadMarker
}

type backoffState struct {
	nextAt   time.Time
	failures int
}

// deadMarker records why and when an auth was last observed permanently
// unusable by the quota fetcher.
type deadMarker struct {
	reason string
	since  time.Time
}

// StaleCooldownClearer is the optional hook the refresher invokes when a
// successful wham/usage fetch shows the auth is healthy upstream (no
// limit_reached). The cliproxy Service wires this to
// coreauth.Manager.ClearCooldown so an account that's stuck on a stale
// in-memory cooldown (NextRetryAfter in the past, never cleared because
// the next-success-call path could not fire — see the
// t.yamada.takashi case where model_registry.SuspendedClients kept her
// out of the candidate pool, blocking any chance of a successful call
// that would auto-clear it) gets re-admitted.
//
// Returning an error is logged but does not stop the next refresh
// cycle. ctx is the refresh tick's context — implementations should
// honour cancellation but not introduce their own timeouts beyond it.
type StaleCooldownClearer func(ctx context.Context, authID string) error

// LimitReachedSetter is the optional hook the refresher invokes when a
// successful wham/usage fetch shows the auth's quota is exhausted —
// either via the explicit limit_reached flag or the >=100% used_percent
// saturation heuristic in parseWhamUsage. The cliproxy Service wires
// this to coreauth.Manager.ForceCooldown so the auth gets pulled out
// of rotation immediately, instead of waiting for the next user
// request to hit an upstream 429 (which may not arrive at all — the
// observed case was wham reporting secondary_used=100 while the
// failure surfaced inside a model response body, not as a top-level
// HTTP 429, so the conductor's existing 429 path never fired).
//
// Implementations should be idempotent: the hook fires on every
// refresh tick while the auth is over the limit; a no-op when the
// auth is already covered by an equivalent or longer cooldown is the
// desired behaviour.
type LimitReachedSetter func(ctx context.Context, authID string, snap coreauth.QuotaSnapshot) error

// PlanUpdater is the optional hook the refresher invokes after a
// successful wham/usage fetch that includes a non-empty plan_type.
// The cliproxy Service wires this to rewrite the auth's stored
// plan_type (Metadata + Attributes) and re-register the codex model
// catalog so a free→plus upgrade is reflected without re-importing
// the credential file. Implementations must be idempotent: same plan
// is a no-op.
type PlanUpdater func(ctx context.Context, auth *coreauth.Auth, planType string) error

// ProbePinFunc is the optional hook the refresher invokes when it detects
// a *floating* quota window — an account that has never made a real
// request, so wham/usage keeps reporting reset_at ≈ fetched_at + 7d and
// the daily allowance is wasted. Firing one minimal generation request
// anchors the window (see CodexWhamFetcher.ProbePin). Implementations
// must be safe for concurrent calls and should return quickly (the
// refresher invokes it synchronously inside the refresh cycle).
type ProbePinFunc func(ctx context.Context, auth *coreauth.Auth) error

// Quota window drift detection parameters. A fresh account's wham/usage
// reports a full 7d window on every fetch; an account that has made at
// least one request reports a window that started counting at that
// moment, so reset_at stays fixed. quotaWindowDriftFloor is how close
// reset_at must be to fetched_at + 7d to count as "window not started".
const (
	// quotaWindowFull is the codex primary window length.
	quotaWindowFull = 7 * 24 * time.Hour
	// quotaWindowDriftFloor: reset_at within this margin of fetched_at +
	// 7d means the window has not started counting yet (floating).
	quotaWindowDriftFloor = 7*24*time.Hour - 30*time.Minute
	// quotaProbeMinInterval: minimum gap between probe attempts for the
	// same auth, so a failing probe is retried at most once per hour.
	quotaProbeMinInterval = 1 * time.Hour
)

// RefresherOption tunes a Refresher at construction. Use the WithX helpers
// rather than poking the struct directly.
type RefresherOption func(*Refresher)

// WithStaleCooldownClearer registers the hook that auto-recovers an auth
// stuck on stale cooldown markers once wham reports it healthy. Pass nil
// or omit the option to disable auto-recovery (the legacy behaviour: an
// admin must click the Clear button in the cooldowns panel).
func WithStaleCooldownClearer(fn StaleCooldownClearer) RefresherOption {
	return func(r *Refresher) {
		r.staleCleaner = fn
	}
}

// WithLimitReachedSetter registers the hook that auto-marks an auth as
// cooled-down whenever a wham fetch reports limit_reached (including
// the >=100% used_percent saturation case). Pass nil or omit the
// option to disable this — the legacy behaviour was to wait for an
// upstream 429 on the next user request to trigger the marker.
func WithLimitReachedSetter(fn LimitReachedSetter) RefresherOption {
	return func(r *Refresher) {
		r.limitReachedFn = fn
	}
}

// WithPlanUpdater registers the hook that rewrites an auth's stored
// plan_type from the live wham/usage response. Pass nil or omit to
// leave plan_type frozen at registration time (legacy behaviour for
// agent-identity credentials).
func WithPlanUpdater(fn PlanUpdater) RefresherOption {
	return func(r *Refresher) {
		r.planUpdater = fn
	}
}

// WithProbePin registers the hook that anchors a floating quota window by
// firing one minimal generation request when the refresher detects an
// account whose wham/usage reset_at keeps sliding (never made a request).
// Pass nil or omit to disable window anchoring (the legacy behaviour).
func WithProbePin(fn ProbePinFunc) RefresherOption {
	return func(r *Refresher) {
		r.probeFn = fn
	}
}

// WithInterval overrides the periodic refresh interval. Non-positive
// values are ignored so callers can pass through optional config without
// guarding for zeros.
func WithInterval(d time.Duration) RefresherOption {
	return func(r *Refresher) {
		if d > 0 {
			r.interval = d
		}
	}
}

// WithConcurrency overrides the maximum number of in-flight wham/usage
// fetches. Values <= 0 are ignored.
func WithConcurrency(n int) RefresherOption {
	return func(r *Refresher) {
		if n > 0 {
			r.concurrency = n
		}
	}
}

// NewRefresher constructs a Refresher. fetcher, lister, and pusher are
// required; passing nil for any of them panics — these are programmer
// errors and the refresher would silently do nothing otherwise.
func NewRefresher(fetcher coreauth.QuotaFetcher, lister AuthLister, pusher SnapshotPusher, opts ...RefresherOption) *Refresher {
	if fetcher == nil {
		panic("quota: Refresher requires a non-nil fetcher")
	}
	if lister == nil {
		panic("quota: Refresher requires a non-nil lister")
	}
	if pusher == nil {
		panic("quota: Refresher requires a non-nil pusher")
	}
	r := &Refresher{
		fetcher:     fetcher,
		lister:      lister,
		pusher:      pusher,
		interval:    DefaultRefreshInterval,
		concurrency: DefaultConcurrency,
		backoffs:    map[string]*backoffState{},
		triggers:    make(chan string, 32),
		dead:        map[string]deadMarker{},
		snapshots:   map[string]coreauth.QuotaSnapshot{},
		probedAt:    map[string]time.Time{},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Start kicks off the refresh loop and returns immediately. Calling Start
// more than once is a no-op. The loop terminates when the provided ctx
// is cancelled or Stop is called.
func (r *Refresher) Start(ctx context.Context) {
	if r == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.cancel = cancel
	r.done = done
	r.mu.Unlock()

	// Pass done as a parameter so the loop owns a local reference. Stop
	// may clear r.done before the deferred close runs, so we cannot rely
	// on re-reading it from the struct.
	go r.loop(loopCtx, done)
}

// Stop terminates the refresh loop and waits for it to exit. Safe to call
// multiple times; safe to call before Start (no-op).
func (r *Refresher) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	cancel := r.cancel
	done := r.done
	r.cancel = nil
	r.done = nil
	r.started = false
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// RefreshNow performs a SYNCHRONOUS out-of-cycle fetch for the named auth
// and returns the resulting snapshot. Used by the management API's
// per-auth "manual refresh" button so operators get immediate feedback
// instead of waiting for the next periodic tick.
//
// Unlike Trigger (which fire-and-forgets to the trigger channel), this
// call performs the wham/usage HTTP round-trip inline and pushes the
// result through the same r.pusher path that the periodic loop uses,
// so the selector cache and recorded backoff state stay consistent.
//
// ok=false means the auth is not eligible (nil, missing, disabled, or
// non-codex). err covers transient failures (network, parse, 5xx); the
// caller should display these to the operator rather than silently
// retrying.
func (r *Refresher) RefreshNow(ctx context.Context, authID string) (coreauth.QuotaSnapshot, bool, error) {
	if r == nil {
		return coreauth.QuotaSnapshot{}, false, fmt.Errorf("refresher: nil receiver")
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return coreauth.QuotaSnapshot{}, false, fmt.Errorf("refresher: empty auth ID")
	}
	auths := r.lister()
	var target *coreauth.Auth
	for _, a := range auths {
		if a != nil && a.ID == authID {
			target = a
			break
		}
	}
	if target == nil {
		return coreauth.QuotaSnapshot{}, false, fmt.Errorf("refresher: auth %q not found", authID)
	}
	if target.Disabled {
		return coreauth.QuotaSnapshot{}, false, fmt.Errorf("refresher: auth %q is disabled", authID)
	}
	if !strings.EqualFold(strings.TrimSpace(target.Provider), "codex") {
		return coreauth.QuotaSnapshot{}, false, fmt.Errorf("refresher: auth %q is not a codex provider", authID)
	}
	snap, ok, err := r.fetcher.Fetch(ctx, target)
	r.noteFetchOutcome(authID, ok, err)
	if err != nil {
		r.recordFailure(authID)
		return coreauth.QuotaSnapshot{}, false, err
	}
	if !ok {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	if snap.FetchedAt.IsZero() {
		snap.FetchedAt = time.Now()
	}
	r.pusher(authID, snap)
	// Out-of-cycle: clear failure count but do not push the regular
	// cadence forward. The next scheduled tick handles long-term
	// scheduling.
	r.recordSuccessKeepingSchedule(authID)
	r.maybeUpdatePlan(ctx, target, snap)
	// Manual refreshes participate in floating-window detection too — the
	// operator's "refresh now" button may be the only activity an account
	// sees before its 7d window slides away.
	r.maybeProbeFloatingWindow(ctx, target, snap)
	return snap, true, nil
}

// Trigger requests an out-of-cycle refresh for a single auth. Use this
// after auth lifecycle events (add / re-login / proxy change) to avoid
// waiting up to the next periodic tick before the auth is selectable
// based on real quota data. Drops the request silently if the trigger
// queue is full — the periodic loop will catch up.
func (r *Refresher) Trigger(authID string) {
	if r == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	r.mu.Lock()
	ch := r.triggers
	started := r.started
	r.mu.Unlock()
	if !started || ch == nil {
		return
	}
	select {
	case ch <- authID:
	default:
	}
}

func (r *Refresher) loop(ctx context.Context, done chan struct{}) {
	defer close(done)

	// Small randomized initial delay so multiple proxy hosts restarting at
	// once do not all hammer chatgpt.com in the same millisecond.
	jitter := time.Duration(rand.Int64N(int64(time.Second)))
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
	}

	r.runOnce(ctx)

	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.runOnce(ctx)
		case authID := <-r.triggers:
			r.refreshByID(ctx, authID)
		}
	}
}

// runOnce refreshes every eligible codex auth in a single cycle, honoring
// the concurrency cap. Disabled auths and auths under backoff are skipped.
//
// When the conductor has already recorded a future NextRetryAfter for an
// auth (set from upstream's `resets_at` / `resets_in_seconds`), the
// refresher pulls that auth's nextAt back to the cooldown end so it
// refreshes exactly when upstream says the credential is unblocked,
// rather than waiting for the next regular tick. This implements the
// "next_refresh = min(interval, resets_at)" scheduling rule: the
// regular cadence covers steady-state polling; the resets_at signal
// covers known recovery moments. Refresh is never skipped entirely —
// the scheduler still needs periodic data for quota-based ranking.
func (r *Refresher) runOnce(ctx context.Context) {
	auths := r.lister()
	if len(auths) == 0 {
		return
	}
	now := time.Now()
	targets := make([]*coreauth.Auth, 0, len(auths))
	for _, a := range auths {
		if a == nil || a.Disabled || a.ID == "" {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
			continue
		}
		if cd := knownCooldownEnd(a, now); !cd.IsZero() {
			r.alignCooldownEnd(a.ID, cd, now)
		}
		if !r.allowed(a.ID, now) {
			continue
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		return
	}

	concurrency := r.concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, target := range targets {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(a *coreauth.Auth) {
			defer wg.Done()
			defer func() { <-sem }()
			r.refresh(ctx, a, true)
		}(target)
	}
	wg.Wait()
}

// refreshByID looks up the named auth in the current pool and refreshes it.
// Used by Trigger to honour out-of-cycle requests without touching the
// rest of the pool. Scheduled=false so an event-driven Trigger does
// not bump the cycle cadence forward (see recordSuccessKeepingSchedule
// for the motivating bug).
func (r *Refresher) refreshByID(ctx context.Context, authID string) {
	auths := r.lister()
	for _, a := range auths {
		if a == nil || a.ID != authID {
			continue
		}
		if a.Disabled {
			return
		}
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
			return
		}
		r.refresh(ctx, a, false)
		return
	}
}

// refresh performs one fetch and pushes the snapshot to the selector on
// success. Failures bump per-auth backoff; ok=false (wrong provider /
// missing token) is silently ignored and does not count as a failure.
//
// Successful fetches log at debug level so an operator can verify the
// refresher is actually keeping the cache warm. Without this log the
// only externally-visible signal of refresher activity was "fetch
// failed" lines — making it impossible to tell whether silence meant
// "all healthy" or "refresher quietly broken" (we hit the latter once
// when a backoff overflow parked an auth, and again when a stale-cache
// gap made every Pick fall back to neutral 50%).
// refresh performs the fetch and pushes the snapshot. scheduleNext=true
// means this is the regular cycle path and the per-auth nextAt should
// advance by one interval on success; scheduleNext=false is the
// out-of-cycle path (Trigger / manual refresh) where the cadence is
// owned by the cycle and should not be perturbed.
func (r *Refresher) refresh(ctx context.Context, a *coreauth.Auth, scheduleNext bool) {
	snap, ok, err := r.fetcher.Fetch(ctx, a)
	r.noteFetchOutcome(a.ID, ok, err)
	if err != nil {
		r.recordFailure(a.ID)
		log.Debugf("quota-refresher: fetch failed | auth=%s err=%v", a.ID, err)
		return
	}
	if !ok {
		return
	}
	if snap.FetchedAt.IsZero() {
		snap.FetchedAt = time.Now()
	}
	r.pusher(a.ID, snap)
	if scheduleNext {
		r.recordSuccess(a.ID)
	} else {
		r.recordSuccessKeepingSchedule(a.ID)
	}
	log.Debugf("quota-refresher: fetch ok | auth=%s primary_used=%d%% secondary_used=%d%% limit_reached=%t",
		a.ID, snap.UsedPercentPrimary, snap.UsedPercentSecondary, snap.LimitReached)

	// Floating-window anchor: an account that has never made a real
	// request reports reset_at ≈ fetched_at + 7d on EVERY wham/usage
	// fetch — the window never starts counting, so reset_at keeps
	// sliding forward and the account permanently wastes its daily
	// allowance (100/7 ≈ 15 points/day on a fresh plus account). Two
	// consecutive near-full-window observations with zero usage means
	// the window is floating; fire one minimal probe request to pin it.
	r.maybeProbeFloatingWindow(ctx, a, snap)

	// Auto-recovery: when wham reports the auth is healthy
	// (limit_reached=false) AND the in-memory state still carries an
	// error marker, drop the stale cooldown so the next pick can use
	// this credential. Without this guard a stuck auth can stay
	// excluded forever — the existing recovery path only fires on a
	// successful API call, but a stuck auth often gets filtered out
	// of the candidate pool so the success never happens. The pre-
	// check (Status / Unavailable / per-model error) keeps healthy
	// auths from being needlessly hit by ClearCooldown every cycle.
	if !snap.LimitReached && r.staleCleaner != nil && hasErrorMarker(a) {
		if errClean := r.staleCleaner(ctx, a.ID); errClean != nil {
			log.WithError(errClean).Warnf("quota-refresher: stale cooldown cleanup failed | auth=%s", a.ID)
		} else {
			log.Infof("quota-refresher: cleared stale cooldown | auth=%s primary_used=%d%% secondary_used=%d%%",
				a.ID, snap.UsedPercentPrimary, snap.UsedPercentSecondary)
		}
	}

	// Auto-set: mirror of the above. When wham reports the auth is
	// over its limit (explicit flag OR >=100% used_percent via the
	// parseWhamUsage saturation heuristic), notify the manager so the
	// auth gets a cooldown marker immediately — without this, the
	// account stays in the candidate pool until a user request happens
	// to hit it and the error surfaces as a top-level 429. In the
	// observed wham-secondary=100% case the failure showed up inside
	// a streamed response body, not as an HTTP 429, so the conductor's
	// 429 path never fired and the account kept getting picked.
	if snap.LimitReached && r.limitReachedFn != nil {
		if errSet := r.limitReachedFn(ctx, a.ID, snap); errSet != nil {
			log.WithError(errSet).Warnf("quota-refresher: limit-reached setter failed | auth=%s", a.ID)
		}
	}
	r.maybeUpdatePlan(ctx, a, snap)
}

// maybeUpdatePlan rewrites the auth's stored plan_type from the live
// wham/usage response when a PlanUpdater is configured. No-op when the
// snapshot omits plan_type or the hook is nil.
func (r *Refresher) maybeUpdatePlan(ctx context.Context, a *coreauth.Auth, snap coreauth.QuotaSnapshot) {
	if r == nil || r.planUpdater == nil || a == nil {
		return
	}
	plan := strings.TrimSpace(snap.PlanType)
	if plan == "" {
		return
	}
	if err := r.planUpdater(ctx, a, plan); err != nil {
		log.WithError(err).Warnf("quota-refresher: plan_type update failed | auth=%s plan=%s", a.ID, plan)
	}
}

// floatingWindow reports whether a snapshot looks like a quota window that
// has never started counting: the API-declared reset_at sits at (or beyond)
// fetched_at + 7d - quotaWindowDriftFloor, and the window is unused. Fresh
// accounts behave this way — every fetch slides reset_at forward by 7d.
func floatingWindow(snap coreauth.QuotaSnapshot) bool {
	if snap.ResetAtPrimary.IsZero() || snap.FetchedAt.IsZero() {
		return false
	}
	if snap.LimitReached || snap.UsedPercentPrimary > 5 {
		// The window is either exhausted or in use — not a floating fresh one.
		return false
	}
	remaining := snap.ResetAtPrimary.Sub(snap.FetchedAt)
	return remaining >= quotaWindowDriftFloor
}

// maybeProbeFloatingWindow detects a fresh account whose wham/usage window
// keeps floating (reset_at ≈ fetched_at + 7d on consecutive fetches) and
// fires one minimal probe request to anchor the window, so the full 7-day
// budget becomes usable instead of sliding away day by day. Requires:
//
//   - the previous snapshot also looked floating (two consecutive
//     observations — one could be a stale cache artifact), and
//   - the account is not over limit / in use, and
//   - at least quotaProbeMinInterval has passed since the last attempt.
//
// The probe runs synchronously inside the refresh cycle; its cost is a
// single tiny generation request (max_output_tokens=1 on the cheapest
// model). Failures are logged and throttled, never fatal.
func (r *Refresher) maybeProbeFloatingWindow(ctx context.Context, a *coreauth.Auth, snap coreauth.QuotaSnapshot) {
	if r == nil || a == nil || r.probeFn == nil {
		return
	}
	if !floatingWindow(snap) {
		r.mu.Lock()
		delete(r.snapshots, a.ID)
		r.mu.Unlock()
		return
	}

	r.mu.Lock()
	prev, sawPrev := r.snapshots[a.ID]
	lastProbe, sawProbe := r.probedAt[a.ID]
	r.snapshots[a.ID] = snap
	r.mu.Unlock()

	if !sawPrev || !floatingWindow(prev) {
		// First observation (or the previous one was not floating):
		// remember and wait for the next cycle to confirm.
		return
	}
	if sawProbe && time.Since(lastProbe) < quotaProbeMinInterval {
		// Already attempted recently — the next cycle will re-check
		// whether reset_at finally stopped sliding.
		return
	}

	r.mu.Lock()
	r.probedAt[a.ID] = time.Now()
	r.mu.Unlock()

	log.Infof("quota-refresher: floating window detected | auth=%s reset_at=%s fetched_at=%s used=%d%% — firing probe to anchor the 7d window",
		a.ID, snap.ResetAtPrimary.Format(time.RFC3339), snap.FetchedAt.Format(time.RFC3339), snap.UsedPercentPrimary)
	if err := r.probeFn(ctx, a); err != nil {
		log.WithError(err).Warnf("quota-refresher: window anchor probe failed | auth=%s", a.ID)
		return
	}
	log.Infof("quota-refresher: window anchor probe ok | auth=%s — reset_at should now be fixed", a.ID)
}

// hasErrorMarker reports whether the auth (or any of its per-model
// states) is in a non-healthy state worth clearing — saves a no-op
// ClearCooldown round-trip on every healthy auth every cycle.
func hasErrorMarker(a *coreauth.Auth) bool {
	if a == nil {
		return false
	}
	if a.Status == coreauth.StatusError || a.Unavailable {
		return true
	}
	if a.Quota.Exceeded {
		return true
	}
	for _, state := range a.ModelStates {
		if state == nil {
			continue
		}
		if state.Status == coreauth.StatusError || state.Unavailable || state.Quota.Exceeded {
			return true
		}
	}
	return false
}

// allowed reports whether the auth is currently outside its backoff window.
func (r *Refresher) allowed(authID string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.backoffs[authID]
	if !ok {
		return true
	}
	return !now.Before(state.nextAt)
}

// knownCooldownEnd returns the latest in-the-future NextRetryAfter the
// conductor has recorded for this auth, looking at both the auth-level
// field and every per-model state. Zero means no conductor cooldown is
// currently active — the refresher then follows its regular cadence.
//
// We take the latest (not earliest) cooldown end across model states
// because account-wide rate-limit data exposed by wham/usage cannot
// usefully change until every per-model lock has cleared. Refreshing
// earlier would mostly observe the same "limit reached" state.
func knownCooldownEnd(a *coreauth.Auth, now time.Time) time.Time {
	if a == nil {
		return time.Time{}
	}
	latest := time.Time{}
	if a.NextRetryAfter.After(now) {
		latest = a.NextRetryAfter
	}
	for _, st := range a.ModelStates {
		if st == nil {
			continue
		}
		if !st.NextRetryAfter.After(now) {
			continue
		}
		if latest.IsZero() || st.NextRetryAfter.After(latest) {
			latest = st.NextRetryAfter
		}
	}
	return latest
}

// alignCooldownEnd pulls the auth's next refresh deadline to
// cooldownEnd if that is sooner than the currently scheduled nextAt.
// This implements the resets_at side of the "next_refresh = min(interval,
// resets_at)" rule: when upstream told us the cooldown ends earlier than
// our regular tick would fire, refresh exactly at the cooldown end so
// the quota cache reflects the recovery moment. nextAt never moves
// later from this call — backoff and the regular cadence still bound it
// from above.
//
// Additionally, while a cooldown is active the refresher keeps probing at
// quotaCooldownProbeInterval instead of going dark until the cooldown
// end: the window can roll over EARLIER than the advertised reset_at
// (observed: wham swapped a cooldown account's reset_at from 08-16 to
// 08-18 after a real rollover at 08:02, hours before the cooldown was
// due). Without the probe the reset would go undetected for the whole
// cooldown duration.
func (r *Refresher) alignCooldownEnd(authID string, cooldownEnd time.Time, now time.Time) {
	if cooldownEnd.IsZero() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.backoffs[authID]
	if state == nil {
		state = &backoffState{}
		r.backoffs[authID] = state
	}
	// During the cooldown keep a slow probe cadence; when the cooldown end
	// arrives, refresh exactly then.
	next := cooldownEnd
	if probeAt := now.Add(quotaCooldownProbeInterval); probeAt.Before(next) {
		next = probeAt
	}
	if state.nextAt.IsZero() || next.Before(state.nextAt) {
		state.nextAt = next
	}
}

// maxBackoffExponent caps the doubling factor so the delay calculation
// stays in well-defined int64 territory regardless of how many
// consecutive failures an auth racks up. With the default 30s interval
// 2^20 already exceeds any sane real-world wait, and the explicit
// MaxBackoff cap below brings the result back to 5 minutes anyway.
// Without this clamp, math.Pow would eventually return +Inf, the
// float-to-time.Duration conversion is implementation-defined for
// overflow, and on amd64 in practice the result wraps to a negative
// duration — which makes nextAt land in the distant past on some
// failures and the distant future on others, effectively silencing the
// refresher for that auth indefinitely.
const maxBackoffExponent = 20

// noteFetchOutcome updates the per-auth dead-account marker from a fetch
// result. A terminal upstream signal (classifyDeadAccount) records/refreshes
// the marker; any successful fetch clears it (the account recovered). Callers
// pass err from the fetch — a non-terminal error leaves an existing marker
// untouched (a throttled dead account keeps its flag across transient blips)
// but never creates one.
func (r *Refresher) noteFetchOutcome(authID string, ok bool, err error) {
	if err != nil {
		reason, dead := classifyDeadAccount(err)
		if !dead {
			return
		}
		r.deadMu.Lock()
		if _, exists := r.dead[authID]; !exists {
			r.dead[authID] = deadMarker{reason: reason, since: time.Now()}
		} else {
			// Keep the original "since" but refresh the reason label.
			m := r.dead[authID]
			m.reason = reason
			r.dead[authID] = m
		}
		r.deadMu.Unlock()
		return
	}
	if !ok {
		return
	}
	r.deadMu.Lock()
	delete(r.dead, authID)
	r.deadMu.Unlock()
}

// DeadMarker reports whether authID's most recent quota fetch signalled a
// terminal "account unusable" condition, returning the reason label and the
// time the marker was first set. ok=false when the account is not flagged.
// Purely informational: the monitor uses it to badge dead credentials for
// cleanup; it does not influence credential selection.
func (r *Refresher) DeadMarker(authID string) (string, time.Time, bool) {
	if r == nil {
		return "", time.Time{}, false
	}
	r.deadMu.RLock()
	defer r.deadMu.RUnlock()
	m, ok := r.dead[authID]
	if !ok {
		return "", time.Time{}, false
	}
	return m.reason, m.since, true
}

// recordFailure increments the auth's failure count and pushes the next
// allowed time forward exponentially: 30s, 60s, 120s, 240s ... capped at
// MaxBackoff. The first failure does not delay the next attempt — we let
// transient network blips retry on the very next cycle.
func (r *Refresher) recordFailure(authID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.backoffs[authID]
	if state == nil {
		state = &backoffState{}
		r.backoffs[authID] = state
	}
	state.failures++
	if state.failures < 2 {
		state.nextAt = time.Time{}
		return
	}
	// Use integer shifts rather than math.Pow on a growing float so the
	// arithmetic stays exact and never overflows. n is clamped to
	// maxBackoffExponent so we cannot reach the int64 limit even after
	// thousands of consecutive failures.
	n := state.failures - 2
	if n > maxBackoffExponent {
		n = maxBackoffExponent
	}
	delay := r.interval * time.Duration(uint64(1)<<uint(n))
	if delay > MaxBackoff || delay < 0 {
		delay = MaxBackoff
	}
	state.nextAt = time.Now().Add(delay)
}

// recordSuccess clears any prior backoff for the auth and schedules the
// next refresh one full interval ahead. With the per-auth cadence
// enforced here rather than implicitly via the loop ticker, the loop
// ticker can fire more often (and pick up cooldown-end alignments
// promptly) without producing extra fetches against healthy auths.
func (r *Refresher) recordSuccess(authID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.backoffs[authID]
	if state == nil {
		state = &backoffState{}
		r.backoffs[authID] = state
	}
	state.failures = 0
	state.nextAt = time.Now().Add(r.interval)
}

// recordSuccessKeepingSchedule clears backoff failures without touching
// the next scheduled fetch time. Used by trigger / manual-refresh paths
// so an out-of-cycle fetch does not push the regular cadence forward.
// Without this, a flood of Trigger() calls at startup (one per
// applyCoreAuthUpdate) overlapping with the initial runOnce would set
// every auth's nextAt to ~startup+10min — barely after the first
// ticker fire, causing the entire next-cycle runOnce to skip every
// auth with "len(targets)==0" and silently return. Net effect: the
// cycle after a restart fires 20min later instead of 10min later,
// and a flaky auth (like tanaka under wham backend stress) sits with
// no fresh quota data for the entire UI-visible TTL.
func (r *Refresher) recordSuccessKeepingSchedule(authID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.backoffs[authID]
	if state == nil {
		// Nothing to reset; out-of-cycle fetch on a healthy auth that
		// has never been touched by recordFailure / recordSuccess.
		return
	}
	state.failures = 0
}
