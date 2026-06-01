package auth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// fakeQuotaFetcher returns the snapshots provided per auth ID and counts
// invocations so tests can verify caching behaviour.
type fakeQuotaFetcher struct {
	mu        sync.Mutex
	responses map[string]QuotaSnapshot
	missing   map[string]struct{} // auths the fetcher reports as ok=false
	calls     atomic.Int64
}

func newFakeQuotaFetcher(responses map[string]QuotaSnapshot) *fakeQuotaFetcher {
	return &fakeQuotaFetcher{responses: responses, missing: map[string]struct{}{}}
}

func (f *fakeQuotaFetcher) Fetch(_ context.Context, auth *Auth) (QuotaSnapshot, bool, error) {
	f.calls.Add(1)
	if auth == nil {
		return QuotaSnapshot{}, false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.missing[auth.ID]; ok {
		return QuotaSnapshot{}, false, nil
	}
	snap, ok := f.responses[auth.ID]
	if !ok {
		return QuotaSnapshot{}, false, nil
	}
	if snap.FetchedAt.IsZero() {
		snap.FetchedAt = time.Now()
	}
	return snap, true, nil
}

// TestLeastRemainingQuotaSelector_PicksLowestUsedPercent verifies the core
// selection rule: among codex candidates with cached quota, the one whose
// primary window used_percent is smallest wins.
func TestLeastRemainingQuotaSelector_PicksLowestUsedPercent(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
		{ID: "auth-c", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(map[string]QuotaSnapshot{
		"auth-a": {UsedPercentPrimary: 75},
		"auth-b": {UsedPercentPrimary: 12},
		"auth-c": {UsedPercentPrimary: 40},
	})
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
	})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-b" {
		t.Fatalf("picked %q, want auth-b (lowest primary used_percent)", got.ID)
	}
}

// TestLeastRemainingQuotaSelector_LimitReachedSkipsAuth verifies that an auth
// whose snapshot says limit_reached=true is excluded from selection even if
// its used_percent would otherwise rank it first.
func TestLeastRemainingQuotaSelector_LimitReachedSkipsAuth(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(map[string]QuotaSnapshot{
		"auth-a": {UsedPercentPrimary: 0, LimitReached: true}, // would win on used_percent
		"auth-b": {UsedPercentPrimary: 90},
	})
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
	})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-b" {
		t.Fatalf("picked %q, want auth-b (auth-a is limit_reached)", got.ID)
	}
}

// TestLeastRemainingQuotaSelector_DelegatesForNonCodexProviders verifies the
// graceful-degradation path: a non-codex pool flows through to the inner
// selector without any wham/usage fetches happening.
func TestLeastRemainingQuotaSelector_DelegatesForNonCodexProviders(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "claude"},
		{ID: "auth-b", Provider: "claude"},
	}
	fetcher := newFakeQuotaFetcher(nil)
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"claude:claude-3": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
	})

	got, err := selector.Pick(context.Background(), "claude", "claude-3", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-a" {
		t.Fatalf("picked %q, want auth-a (inner RR cursor=0, alpha-first)", got.ID)
	}
	if calls := fetcher.calls.Load(); calls != 0 {
		t.Fatalf("fetcher invoked %d times for a non-codex pool, expected 0", calls)
	}
}

// TestLeastRemainingQuotaSelector_CachesAcrossPicks verifies that a second
// Pick within the TTL window does not re-fetch quotas, keeping the per-pick
// wham/usage volume bounded.
func TestLeastRemainingQuotaSelector_CachesAcrossPicks(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(map[string]QuotaSnapshot{
		"auth-a": {UsedPercentPrimary: 10},
		"auth-b": {UsedPercentPrimary: 90},
	})
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Hour,
	})

	for i := 0; i < 5; i++ {
		got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick #%d error = %v", i, err)
		}
		if got.ID != "auth-a" {
			t.Fatalf("Pick #%d = %q, want auth-a", i, got.ID)
		}
	}
	// 2 auths × 1 fetch (only the first Pick warms; subsequent Picks hit cache).
	if calls := fetcher.calls.Load(); calls != 2 {
		t.Fatalf("fetcher invoked %d times across 5 Picks, expected 2 (one warm per auth)", calls)
	}
}

// TestLeastRemainingQuotaSelector_FallsBackWhenAllFetchesMissing verifies
// the cold-start path: when no candidate has quota data the selector
// transparently delegates to inner rather than blocking the caller.
func TestLeastRemainingQuotaSelector_FallsBackWhenAllFetchesMissing(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(nil) // every Fetch returns ok=false
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
	})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-a" {
		t.Fatalf("picked %q, want auth-a (inner RR cursor=0)", got.ID)
	}
}

// TestLeastRemainingQuotaSelector_AsyncSkipsInlineWarming verifies that
// the async mode never invokes the Fetcher during Pick — the request
// hot path must stay free of wham/usage I/O. An external refresher
// (production: quota.Refresher) owns cache population.
func TestLeastRemainingQuotaSelector_AsyncSkipsInlineWarming(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
	}
	// Configure the fetcher with non-zero data so that, IF it were
	// invoked, the assertion below would clearly catch the violation
	// rather than silently allowing ok=false to mask it.
	fetcher := newFakeQuotaFetcher(map[string]QuotaSnapshot{
		"auth-a": {UsedPercentPrimary: 1},
		"auth-b": {UsedPercentPrimary: 2},
	})
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
		Async:   true,
	})

	// Pre-populate one entry via the external push API so Pick has at
	// least one candidate with real data. The other candidate goes
	// through the neutral path.
	selector.PushSnapshot("auth-b", QuotaSnapshot{UsedPercentPrimary: 90, FetchedAt: time.Now()})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	// auth-b is at 90 (real); auth-a sits at the neutral score (50,
	// default). 50 < 90 so auth-a wins.
	if got.ID != "auth-a" {
		t.Fatalf("picked %q, want auth-a (neutral 50%% beats real 90%%)", got.ID)
	}
	if calls := fetcher.calls.Load(); calls != 0 {
		t.Fatalf("fetcher invoked %d times in async mode, expected 0", calls)
	}
}

// TestLeastRemainingQuotaSelector_AsyncRealDataBeatsNeutral verifies the
// inverse case: when an auth has real cached data below the neutral
// score, it is preferred over peers with no data.
func TestLeastRemainingQuotaSelector_AsyncRealDataBeatsNeutral(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(nil)
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
		Async:   true,
	})

	// auth-a has real data at 5% used; auth-b has no cache entry, so it
	// sits at the neutral 50%. auth-a should win comfortably.
	selector.PushSnapshot("auth-a", QuotaSnapshot{UsedPercentPrimary: 5, FetchedAt: time.Now()})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-a" {
		t.Fatalf("picked %q, want auth-a (real 5%% beats neutral 50%%)", got.ID)
	}
}

// TestLeastRemainingQuotaSelector_AsyncDistributesAcrossNeutralCandidates
// verifies the "no real data anywhere" case: when every candidate is at
// the neutral score, the tie-breaker spreads load uniformly rather than
// collapsing to one credential. This is the key regression guard against
// the suzukiyuki2003 monopoly that motivated this work — when SOCKS5
// quota timeouts left only one credential with data, the entire pool
// piled onto that single auth.
func TestLeastRemainingQuotaSelector_AsyncDistributesAcrossNeutralCandidates(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
		{ID: "auth-c", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(nil)
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
		Async:   true,
	})

	// 300 picks across 3 candidates: pure-random would land each in
	// roughly 100 ± noise. Assert that each candidate is picked at
	// least 50 times, which excludes the previous monopoly behaviour
	// without making the test flaky on a healthy RNG.
	counts := map[string]int{}
	for i := 0; i < 300; i++ {
		got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick #%d error = %v", i, err)
		}
		counts[got.ID]++
	}
	for _, id := range []string{"auth-a", "auth-b", "auth-c"} {
		if counts[id] < 50 {
			t.Fatalf("auth %q picked only %d/300 times — neutral tie-break is not distributing", id, counts[id])
		}
	}
}

// TestLeastRemainingQuotaSelector_PushSnapshotPopulatesCache verifies the
// external-population API used by quota.Refresher: pushed snapshots
// drive Pick without any Fetcher invocation.
func TestLeastRemainingQuotaSelector_PushSnapshotPopulatesCache(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(nil) // any Fetch call must fail this test
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
		Async:   true,
	})

	selector.PushSnapshot("auth-a", QuotaSnapshot{UsedPercentPrimary: 10})
	selector.PushSnapshot("auth-b", QuotaSnapshot{UsedPercentPrimary: 80})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-a" {
		t.Fatalf("picked %q, want auth-a (pushed snapshot 10%% < 80%%)", got.ID)
	}
	if calls := fetcher.calls.Load(); calls != 0 {
		t.Fatalf("fetcher invoked %d times despite externally-populated cache", calls)
	}
}

// TestLeastRemainingQuotaSelector_AsyncLimitReachedStillExcludes verifies
// that even in async mode an auth flagged limit_reached is dropped from
// the candidate pool — the neutral fallback applies only to *missing*
// data, never to known-bad credentials.
func TestLeastRemainingQuotaSelector_AsyncLimitReachedStillExcludes(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(nil)
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: fetcher,
		TTL:     time.Minute,
		Async:   true,
	})
	// auth-a's real data says limit reached; auth-b has no entry (neutral 50).
	selector.PushSnapshot("auth-a", QuotaSnapshot{UsedPercentPrimary: 0, LimitReached: true})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-b" {
		t.Fatalf("picked %q, want auth-b (auth-a is limit_reached)", got.ID)
	}
}
