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
const (
	DefaultRefreshInterval = 30 * time.Second
	DefaultConcurrency     = 2
	MaxBackoff             = 5 * time.Minute
)

// Refresher periodically refreshes per-auth quota snapshots in the
// background. It is started via Start(ctx) and stopped via Stop().
//
// The zero value is not usable; call NewRefresher.
type Refresher struct {
	fetcher     coreauth.QuotaFetcher
	lister      AuthLister
	pusher      SnapshotPusher
	interval    time.Duration
	concurrency int

	mu       sync.Mutex
	backoffs map[string]*backoffState
	cancel   context.CancelFunc
	done     chan struct{}
	triggers chan string
	started  bool
}

type backoffState struct {
	nextAt   time.Time
	failures int
}

// RefresherOption tunes a Refresher at construction. Use the WithX helpers
// rather than poking the struct directly.
type RefresherOption func(*Refresher)

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
			r.refresh(ctx, a)
		}(target)
	}
	wg.Wait()
}

// refreshByID looks up the named auth in the current pool and refreshes it.
// Used by Trigger to honour out-of-cycle requests without touching the
// rest of the pool.
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
		r.refresh(ctx, a)
		return
	}
}

// refresh performs one fetch and pushes the snapshot to the selector on
// success. Failures bump per-auth backoff; ok=false (wrong provider /
// missing token) is silently ignored and does not count as a failure.
func (r *Refresher) refresh(ctx context.Context, a *coreauth.Auth) {
	snap, ok, err := r.fetcher.Fetch(ctx, a)
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
	r.recordSuccess(a.ID)
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

// recordSuccess clears any prior backoff for the auth.
func (r *Refresher) recordSuccess(authID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.backoffs, authID)
}
