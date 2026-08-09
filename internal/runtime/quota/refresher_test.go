package quota

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// TestFloatingWindowDetector verifies the fresh-account floating-window
// detection and the probe trigger:
//
//   - an account whose reset_at sits at fetched_at + 7d (window never
//     started counting) with zero usage is "floating";
//   - two consecutive floating observations fire exactly one probe;
//   - once the window is anchored (reset_at no longer sliding), no more
//     probes fire;
//   - the probe is throttled: a failed probe is not retried within
//     quotaProbeMinInterval.
func TestFloatingWindowDetector(t *testing.T) {
	now := time.Now()
	fetcher := newFakeFetcher()
	// First fetch: floating (reset_at = fetched + 7d, unused).
	fetcher.fixtures["floating-1"] = fakeFixture{snap: coreauth.QuotaSnapshot{
		UsedPercentPrimary:   0,
		UsedPercentSecondary: 0,
		FetchedAt:            now,
		ResetAtPrimary:       now.Add(7 * 24 * time.Hour),
	}}

	var probeCalls atomic.Int64
	pusher := func(authID string, snap coreauth.QuotaSnapshot) {}
	refresher := NewRefresher(fetcher, func() []*coreauth.Auth {
		return []*coreauth.Auth{{ID: "floating-1", Provider: "codex"}}
	}, pusher, WithProbePin(func(ctx context.Context, a *coreauth.Auth) error {
		probeCalls.Add(1)
		return nil
	}))

	auth := &coreauth.Auth{ID: "floating-1", Provider: "codex"}

	// Cycle 1: first floating observation — remember, do not probe yet.
	snap1, _, _ := fetcher.Fetch(context.Background(), auth)
	refresher.maybeProbeFloatingWindow(context.Background(), auth, snap1)
	if probeCalls.Load() != 0 {
		t.Fatalf("cycle 1: expected no probe, got %d", probeCalls.Load())
	}

	// Cycle 2: second floating observation — fire one probe.
	fetcher.fixtures["floating-1"] = fakeFixture{snap: coreauth.QuotaSnapshot{
		UsedPercentPrimary:   0,
		UsedPercentSecondary: 0,
		FetchedAt:            now.Add(10 * time.Minute),
		ResetAtPrimary:       now.Add(10*time.Minute + 7*24*time.Hour),
	}}
	snap2, _, _ := fetcher.Fetch(context.Background(), auth)
	refresher.maybeProbeFloatingWindow(context.Background(), auth, snap2)
	if probeCalls.Load() != 1 {
		t.Fatalf("cycle 2: expected 1 probe, got %d", probeCalls.Load())
	}

	// Cycle 3: anchored now (reset_at no longer sliding) — no probe.
	fetcher.fixtures["floating-1"] = fakeFixture{snap: coreauth.QuotaSnapshot{
		UsedPercentPrimary:   1,
		UsedPercentSecondary: 0,
		FetchedAt:            now.Add(20 * time.Minute),
		ResetAtPrimary:       now.Add(10*time.Minute + 7*24*time.Hour),
	}}
	snap3, _, _ := fetcher.Fetch(context.Background(), auth)
	refresher.maybeProbeFloatingWindow(context.Background(), auth, snap3)
	if probeCalls.Load() != 1 {
		t.Fatalf("cycle 3 (anchored): expected no new probe, got %d", probeCalls.Load())
	}
}

// TestFloatingWindowThrottle verifies that a probe attempt is throttled:
// consecutive floating observations within quotaProbeMinInterval do not
// re-fire the probe (e.g. after a failure).
func TestFloatingWindowThrottle(t *testing.T) {
	now := time.Now()
	fetcher := newFakeFetcher()
	var probeCalls atomic.Int64
	refresher := NewRefresher(fetcher, func() []*coreauth.Auth { return nil }, func(authID string, snap coreauth.QuotaSnapshot) {},
		WithProbePin(func(ctx context.Context, a *coreauth.Auth) error {
			probeCalls.Add(1)
			return errors.New("probe failed")
		}))

	auth := &coreauth.Auth{ID: "floating-2", Provider: "codex"}
	fixture := fakeFixture{snap: coreauth.QuotaSnapshot{
		UsedPercentPrimary: 0,
		FetchedAt:          now,
		ResetAtPrimary:     now.Add(7 * 24 * time.Hour),
	}}
	fetcher.fixtures["floating-2"] = fixture

	// Two cycles fire the first probe (which fails).
	snap1, _, _ := fetcher.Fetch(context.Background(), auth)
	refresher.maybeProbeFloatingWindow(context.Background(), auth, snap1)
	snap2, _, _ := fetcher.Fetch(context.Background(), auth)
	refresher.maybeProbeFloatingWindow(context.Background(), auth, snap2)
	if probeCalls.Load() != 1 {
		t.Fatalf("expected 1 probe after 2 cycles, got %d", probeCalls.Load())
	}

	// Third cycle within the throttle window: no new probe.
	fetcher.fixtures["floating-2"] = fakeFixture{snap: coreauth.QuotaSnapshot{
		UsedPercentPrimary: 0,
		FetchedAt:          now.Add(10 * time.Minute),
		ResetAtPrimary:     now.Add(10*time.Minute + 7*24*time.Hour),
	}}
	snap3, _, _ := fetcher.Fetch(context.Background(), auth)
	refresher.maybeProbeFloatingWindow(context.Background(), auth, snap3)
	if probeCalls.Load() != 1 {
		t.Fatalf("expected throttled probe (still 1), got %d", probeCalls.Load())
	}
}

// TestFloatingWindowNotTriggeredForInUseOrLimited verifies that accounts
// with usage or limit_reached never look floating.
func TestFloatingWindowNotTriggeredForInUseOrLimited(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		snap coreauth.QuotaSnapshot
	}{
		{"in-use", coreauth.QuotaSnapshot{UsedPercentPrimary: 40, FetchedAt: now, ResetAtPrimary: now.Add(7 * 24 * time.Hour)}},
		{"limit-reached", coreauth.QuotaSnapshot{UsedPercentPrimary: 100, LimitReached: true, FetchedAt: now, ResetAtPrimary: now.Add(7 * 24 * time.Hour)}},
		{"no-reset-at", coreauth.QuotaSnapshot{UsedPercentPrimary: 0, FetchedAt: now}},
	}
	for _, tc := range cases {
		if floatingWindow(tc.snap) {
			t.Fatalf("%s: expected not floating, got floating", tc.name)
		}
	}

	// A genuinely floating fresh window must be detected.
	floating := coreauth.QuotaSnapshot{UsedPercentPrimary: 0, FetchedAt: now, ResetAtPrimary: now.Add(7 * 24 * time.Hour)}
	if !floatingWindow(floating) {
		t.Fatal("fresh unused window: expected floating, got not floating")
	}
}

// fakeFetcher implements coreauth.QuotaFetcher with deterministic
// behaviour driven by per-auth fixtures. Each Fetch call increments a
// counter so tests can assert how many times each auth was refreshed.
type fakeFetcher struct {
	mu          sync.Mutex
	fixtures    map[string]fakeFixture
	calls       map[string]*atomic.Int64
	maxInFlight atomic.Int32
	inFlight    atomic.Int32
}

type fakeFixture struct {
	snap coreauth.QuotaSnapshot
	ok   bool
	err  error
	// hold delays the Fetch return so concurrency-cap tests can observe
	// overlapping calls without racing on real network I/O.
	hold time.Duration
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{
		fixtures: map[string]fakeFixture{},
		calls:    map[string]*atomic.Int64{},
	}
}

func (f *fakeFetcher) setFixture(id string, fx fakeFixture) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fixtures[id] = fx
	if _, ok := f.calls[id]; !ok {
		f.calls[id] = &atomic.Int64{}
	}
}

func (f *fakeFetcher) callsFor(id string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	counter, ok := f.calls[id]
	if !ok {
		return 0
	}
	return counter.Load()
}

func (f *fakeFetcher) Fetch(ctx context.Context, auth *coreauth.Auth) (coreauth.QuotaSnapshot, bool, error) {
	if auth == nil {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	// Track concurrency: bump current, latch max-seen, bump call count.
	cur := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		seen := f.maxInFlight.Load()
		if cur <= seen {
			break
		}
		if f.maxInFlight.CompareAndSwap(seen, cur) {
			break
		}
	}

	f.mu.Lock()
	fx, ok := f.fixtures[auth.ID]
	counter := f.calls[auth.ID]
	if counter == nil {
		counter = &atomic.Int64{}
		f.calls[auth.ID] = counter
	}
	f.mu.Unlock()
	counter.Add(1)
	if !ok {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	if fx.hold > 0 {
		select {
		case <-ctx.Done():
			return coreauth.QuotaSnapshot{}, false, ctx.Err()
		case <-time.After(fx.hold):
		}
	}
	return fx.snap, fx.ok, fx.err
}

// pushRecorder captures snapshots delivered by the refresher so tests can
// verify that successful fetches actually reach the selector cache.
type pushRecorder struct {
	mu    sync.Mutex
	saved map[string]coreauth.QuotaSnapshot
}

func newPushRecorder() *pushRecorder {
	return &pushRecorder{saved: map[string]coreauth.QuotaSnapshot{}}
}

func (p *pushRecorder) push(id string, snap coreauth.QuotaSnapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saved[id] = snap
}

func (p *pushRecorder) snapshot(id string) (coreauth.QuotaSnapshot, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	snap, ok := p.saved[id]
	return snap, ok
}

func (p *pushRecorder) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.saved)
}

// waitFor polls cond until it returns true or the deadline expires. Test
// helpers use this instead of fixed sleeps so the suite stays fast on
// healthy machines and still tolerates loaded CI runners.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

// TestRefresher_PeriodicRefreshesAllCodexAuths verifies the happy path:
// every codex auth in the pool is fetched once per cycle, and the
// resulting snapshots reach the pusher.
func TestRefresher_PeriodicRefreshesAllCodexAuths(t *testing.T) {
	t.Parallel()

	fetcher := newFakeFetcher()
	fetcher.setFixture("a", fakeFixture{snap: coreauth.QuotaSnapshot{UsedPercentPrimary: 10}, ok: true})
	fetcher.setFixture("b", fakeFixture{snap: coreauth.QuotaSnapshot{UsedPercentPrimary: 20}, ok: true})

	auths := []*coreauth.Auth{
		{ID: "a", Provider: "codex"},
		{ID: "b", Provider: "codex"},
		// non-codex must be ignored
		{ID: "c", Provider: "claude"},
	}
	recorder := newPushRecorder()
	r := NewRefresher(
		fetcher,
		func() []*coreauth.Auth { return auths },
		recorder.push,
		WithInterval(20*time.Millisecond),
		WithConcurrency(2),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	defer r.Stop()

	waitFor(t, time.Second, func() bool { return recorder.count() == 2 })
	if _, ok := recorder.snapshot("a"); !ok {
		t.Fatalf("auth 'a' snapshot not pushed")
	}
	if _, ok := recorder.snapshot("b"); !ok {
		t.Fatalf("auth 'b' snapshot not pushed")
	}
	if _, ok := recorder.snapshot("c"); ok {
		t.Fatalf("non-codex auth 'c' was refreshed but should have been skipped")
	}
	if fetcher.callsFor("c") != 0 {
		t.Fatalf("fetcher invoked %d times for non-codex auth, want 0", fetcher.callsFor("c"))
	}
}

// TestRefresher_TriggerForcesImmediateRefresh verifies that out-of-cycle
// Trigger calls refresh the named auth without waiting for the next tick.
// Used by the service to warm a freshly added auth (re-login flow).
func TestRefresher_TriggerForcesImmediateRefresh(t *testing.T) {
	t.Parallel()

	fetcher := newFakeFetcher()
	fetcher.setFixture("a", fakeFixture{snap: coreauth.QuotaSnapshot{UsedPercentPrimary: 5}, ok: true})

	auths := []*coreauth.Auth{{ID: "a", Provider: "codex"}}
	recorder := newPushRecorder()
	// 1 hour interval so the periodic tick cannot interfere with the
	// trigger-only assertion.
	r := NewRefresher(
		fetcher,
		func() []*coreauth.Auth { return auths },
		recorder.push,
		WithInterval(time.Hour),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	defer r.Stop()

	// The Start path always runs one initial cycle. Wait for that to
	// complete before issuing the trigger so we can assert it produced
	// an *additional* fetch.
	waitFor(t, time.Second, func() bool { return fetcher.callsFor("a") >= 1 })
	priorCalls := fetcher.callsFor("a")

	r.Trigger("a")
	waitFor(t, time.Second, func() bool { return fetcher.callsFor("a") > priorCalls })
}

// TestRefresher_BackoffSkipsFailingAuth verifies that after a fetch error
// the refresher does not retry that auth until the backoff window has
// passed, while still refreshing healthy peers each cycle.
func TestRefresher_BackoffSkipsFailingAuth(t *testing.T) {
	t.Parallel()

	fetcher := newFakeFetcher()
	fetcher.setFixture("good", fakeFixture{snap: coreauth.QuotaSnapshot{UsedPercentPrimary: 1}, ok: true})
	fetcher.setFixture("bad", fakeFixture{err: errors.New("boom")})

	auths := []*coreauth.Auth{
		{ID: "good", Provider: "codex"},
		{ID: "bad", Provider: "codex"},
	}
	recorder := newPushRecorder()
	r := NewRefresher(
		fetcher,
		func() []*coreauth.Auth { return auths },
		recorder.push,
		WithInterval(10*time.Millisecond),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	defer r.Stop()

	// After many cycles, "good" should have far more calls than "bad" —
	// bad's exponential backoff pushes retries 20ms, 40ms, 80ms ... apart
	// while good runs every 10ms. Waiting for goodCalls>=30 (~300ms) gives
	// the exponential plenty of room to dominate before we measure the
	// gap, which keeps the assertion stable on loaded CI runners.
	waitFor(t, 3*time.Second, func() bool { return fetcher.callsFor("good") >= 30 })

	goodCalls := fetcher.callsFor("good")
	badCalls := fetcher.callsFor("bad")
	if badCalls*4 >= goodCalls {
		t.Fatalf("bad auth was retried %d times vs %d for good — backoff did not suppress retries", badCalls, goodCalls)
	}
}

// TestRefresher_SuccessClearsBackoff verifies recovery: once a previously
// failing auth starts succeeding, its backoff clears and it returns to
// the regular refresh cadence.
func TestRefresher_SuccessClearsBackoff(t *testing.T) {
	t.Parallel()

	fetcher := newFakeFetcher()
	// Start as failing.
	fetcher.setFixture("a", fakeFixture{err: errors.New("temp")})

	auths := []*coreauth.Auth{{ID: "a", Provider: "codex"}}
	recorder := newPushRecorder()
	r := NewRefresher(
		fetcher,
		func() []*coreauth.Auth { return auths },
		recorder.push,
		WithInterval(10*time.Millisecond),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	defer r.Stop()

	// Wait for the first failure to register backoff.
	waitFor(t, time.Second, func() bool { return fetcher.callsFor("a") >= 2 })

	// Heal the fixture and trigger an immediate refresh so we do not
	// have to wait out the backoff.
	fetcher.setFixture("a", fakeFixture{snap: coreauth.QuotaSnapshot{UsedPercentPrimary: 7}, ok: true})
	r.Trigger("a")

	waitFor(t, time.Second, func() bool {
		snap, ok := recorder.snapshot("a")
		return ok && snap.UsedPercentPrimary == 7
	})

	priorCalls := fetcher.callsFor("a")
	// Subsequent cycles should now refresh "a" again on the regular tick.
	waitFor(t, time.Second, func() bool { return fetcher.callsFor("a") > priorCalls })
}

// TestRefresher_ConcurrencyCap verifies that no more than the configured
// number of fetches are in flight simultaneously, even when many auths
// are eligible.
func TestRefresher_ConcurrencyCap(t *testing.T) {
	t.Parallel()

	fetcher := newFakeFetcher()
	const N = 6
	const cap = 2
	auths := make([]*coreauth.Auth, 0, N)
	for i := 0; i < N; i++ {
		id := string(rune('a' + i))
		auths = append(auths, &coreauth.Auth{ID: id, Provider: "codex"})
		// 30ms hold so the workers overlap even on slow CI.
		fetcher.setFixture(id, fakeFixture{ok: true, hold: 30 * time.Millisecond})
	}

	recorder := newPushRecorder()
	r := NewRefresher(
		fetcher,
		func() []*coreauth.Auth { return auths },
		recorder.push,
		WithInterval(time.Hour), // rely on the Start-time initial cycle
		WithConcurrency(cap),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	defer r.Stop()

	waitFor(t, 5*time.Second, func() bool { return recorder.count() == N })
	if got := fetcher.maxInFlight.Load(); int(got) > cap {
		t.Fatalf("max in-flight = %d, want <= %d", got, cap)
	}
}

// TestRefresher_BackoffSurvivesHighFailureCount is the regression guard
// for the silent-stuck bug observed on 2026-06-02: after ~50 consecutive
// failures the previous math.Pow-based delay formula overflowed the
// float-to-time.Duration conversion, producing wildly out-of-range
// nextAt values that effectively pinned the auth out of the refresher
// rotation for the lifetime of the process.
//
// At 1000 simulated failures, recordFailure must still leave nextAt at
// a time strictly within (now, now+MaxBackoff]. If it lands further out
// or in the past, the refresher will either give up on the auth or busy
// loop on it — both regressions we've actually shipped before.
func TestRefresher_BackoffSurvivesHighFailureCount(t *testing.T) {
	t.Parallel()

	r := NewRefresher(
		newFakeFetcher(),
		func() []*coreauth.Auth { return nil },
		func(string, coreauth.QuotaSnapshot) {},
		WithInterval(30*time.Second),
	)

	authID := "stuck-account"
	before := time.Now()
	for i := 0; i < 1000; i++ {
		r.recordFailure(authID)
	}
	after := time.Now()

	r.mu.Lock()
	state := r.backoffs[authID]
	r.mu.Unlock()
	if state == nil {
		t.Fatal("no backoff state recorded after 1000 failures")
	}

	// nextAt must be within (call window, call window + MaxBackoff] —
	// the floor guards against negative-duration wraparound, the ceiling
	// against runaway exponentiation.
	earliestExpected := before
	latestExpected := after.Add(MaxBackoff + time.Second)
	if state.nextAt.Before(earliestExpected) {
		t.Fatalf("nextAt = %v is before the call window start %v (negative-duration wraparound bug)", state.nextAt, earliestExpected)
	}
	if state.nextAt.After(latestExpected) {
		t.Fatalf("nextAt = %v is more than MaxBackoff (%v) past the call window end %v (overflow bug)", state.nextAt, MaxBackoff, latestExpected)
	}

	// And allowed() at the future "after backoff" point should return
	// true — the auth must still be reachable on the regular cadence,
	// not silently quarantined.
	if !r.allowed(authID, after.Add(MaxBackoff+time.Second)) {
		t.Fatalf("allowed=false after MaxBackoff window — high-failure auth got permanently parked")
	}
}

// TestRefresher_AlignCooldownEndPullsNextAtForward verifies the
// "next_refresh = min(interval, resets_at)" scheduling rule: when the
// conductor has already recorded a future cooldown end (from upstream's
// resets_at), the refresher's per-auth nextAt is pulled back to that
// moment so the regular tick fires the refresh exactly when upstream
// says the credential is unblocked, rather than waiting out the full
// interval.
func TestRefresher_AlignCooldownEndPullsNextAtForward(t *testing.T) {
	t.Parallel()

	r := NewRefresher(
		newFakeFetcher(),
		func() []*coreauth.Auth { return nil },
		func(string, coreauth.QuotaSnapshot) {},
		WithInterval(10*time.Minute),
	)
	const authID = "a"

	// Seed a "just refreshed, next due in 10 minutes" state.
	r.recordSuccess(authID)
	r.mu.Lock()
	originalNext := r.backoffs[authID].nextAt
	r.mu.Unlock()
	if originalNext.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("recordSuccess should schedule ~10min ahead, got nextAt=%v", originalNext)
	}

	// Conductor reports a cooldown ending in 2 minutes — earlier than
	// the next scheduled refresh.
	cooldownEnd := time.Now().Add(2 * time.Minute)
	r.alignCooldownEnd(authID, cooldownEnd)
	r.mu.Lock()
	aligned := r.backoffs[authID].nextAt
	r.mu.Unlock()
	if !aligned.Equal(cooldownEnd) {
		t.Fatalf("alignCooldownEnd should pull nextAt back to cooldownEnd; got %v, want %v", aligned, cooldownEnd)
	}

	// And a later "cooldown end" must NOT push the refresh further out
	// — the regular cadence still bounds nextAt from above.
	r.alignCooldownEnd(authID, time.Now().Add(1*time.Hour))
	r.mu.Lock()
	stillAligned := r.backoffs[authID].nextAt
	r.mu.Unlock()
	if !stillAligned.Equal(cooldownEnd) {
		t.Fatalf("alignCooldownEnd must not move nextAt later; got %v, want %v", stillAligned, cooldownEnd)
	}
}

// TestKnownCooldownEnd_ReadsAuthAndModelStates verifies the per-auth /
// per-model unification: knownCooldownEnd returns the LATEST future
// NextRetryAfter across both the auth-level field and every model
// state, so the refresher only pulls forward to the moment when all
// known per-model locks have cleared (account-wide rate-limit data
// cannot usefully change before then).
func TestKnownCooldownEnd_ReadsAuthAndModelStates(t *testing.T) {
	t.Parallel()
	now := time.Now()
	short := now.Add(2 * time.Minute)
	long := now.Add(20 * time.Minute)

	cases := []struct {
		name string
		auth *coreauth.Auth
		want time.Time
	}{
		{"nil auth", nil, time.Time{}},
		{"no cooldown anywhere", &coreauth.Auth{}, time.Time{}},
		{
			"only auth-level cooldown",
			&coreauth.Auth{NextRetryAfter: short},
			short,
		},
		{
			"only per-model cooldown",
			&coreauth.Auth{
				ModelStates: map[string]*coreauth.ModelState{
					"gpt-5.5": {NextRetryAfter: short},
				},
			},
			short,
		},
		{
			"multiple model cooldowns — latest wins",
			&coreauth.Auth{
				ModelStates: map[string]*coreauth.ModelState{
					"a": {NextRetryAfter: short},
					"b": {NextRetryAfter: long},
				},
			},
			long,
		},
		{
			"auth-level vs model-level — latest wins",
			&coreauth.Auth{
				NextRetryAfter: short,
				ModelStates: map[string]*coreauth.ModelState{
					"a": {NextRetryAfter: long},
				},
			},
			long,
		},
		{
			"past cooldown ignored",
			&coreauth.Auth{
				NextRetryAfter: now.Add(-1 * time.Minute),
				ModelStates: map[string]*coreauth.ModelState{
					"a": {NextRetryAfter: short},
				},
			},
			short,
		},
		{
			"nil model state entries are skipped",
			&coreauth.Auth{
				ModelStates: map[string]*coreauth.ModelState{
					"a": nil,
					"b": {NextRetryAfter: short},
				},
			},
			short,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := knownCooldownEnd(tc.auth, now)
			if !got.Equal(tc.want) {
				t.Fatalf("knownCooldownEnd = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRefresher_StopIsIdempotentAndSafeBeforeStart guards against the
// service shutting down before the refresher ever started, and against
// double-Stop calls from defensive callers.
func TestRefresher_StopIsIdempotentAndSafeBeforeStart(t *testing.T) {
	t.Parallel()

	r := NewRefresher(
		newFakeFetcher(),
		func() []*coreauth.Auth { return nil },
		func(string, coreauth.QuotaSnapshot) {},
	)
	r.Stop() // before Start
	r.Start(context.Background())
	r.Stop()
	r.Stop() // double-stop
}
