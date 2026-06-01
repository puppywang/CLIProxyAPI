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
