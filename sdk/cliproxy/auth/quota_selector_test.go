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

// TestLeastRemainingQuotaSelector_DropsStressedFromHealthyPool verifies the
// tiered-filter behaviour: candidates with UsedPercentPrimary in the
// healthy band (< HealthyTierUsedPercent) form the preferred pool that the
// inner selector is asked to choose from. Stressed and unhealthy candidates
// must not appear in that pool — even when one of them happens to be the
// alphabetically-first input. The actual within-pool order is RR's job.
func TestLeastRemainingQuotaSelector_DropsStressedFromHealthyPool(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
		{ID: "auth-c", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(map[string]QuotaSnapshot{
		"auth-a": {UsedPercentPrimary: 75}, // stressed (50-90)
		"auth-b": {UsedPercentPrimary: 12}, // healthy (<50)
		"auth-c": {UsedPercentPrimary: 40}, // healthy (<50)
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
	// auth-a is stressed → must be excluded from the healthy pool the
	// inner selector sees. The RR cursor pins index 0, so the pool is
	// [auth-b, auth-c] and we land on auth-b.
	if got.ID == "auth-a" {
		t.Fatalf("picked %q, but auth-a is stressed and should not appear in the healthy pool", got.ID)
	}
	if got.ID != "auth-b" {
		t.Fatalf("picked %q, want auth-b (RR cursor=0 against healthy pool [auth-b, auth-c])", got.ID)
	}
}

// TestLeastRemainingQuotaSelector_LimitReachedSkipsAuth verifies that an auth
// whose snapshot says limit_reached=true is excluded from selection even
// when its used_percent would otherwise look attractive. The remaining
// candidate is in the stressed tier (70%) — still usable, so the filter
// keeps her and the inner RR returns her.
func TestLeastRemainingQuotaSelector_LimitReachedSkipsAuth(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-a", Provider: "codex"},
		{ID: "auth-b", Provider: "codex"},
	}
	fetcher := newFakeQuotaFetcher(map[string]QuotaSnapshot{
		"auth-a": {UsedPercentPrimary: 0, LimitReached: true},
		"auth-b": {UsedPercentPrimary: 70}, // stressed but usable (< UnhealthyUsedPercent)
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

// TestLeastRemainingQuotaSelector_PriorityGateDrainsHighFirst verifies that
// when accounts carry different `priority` values, only the highest usable
// level is offered to the inner selector — even when a lower-priority
// account is equally healthy. This is the "drain short-lived accounts
// first" behaviour: a fresh long-lived account must not steal bindings
// while a high-priority account can still serve.
func TestLeastRemainingQuotaSelector_PriorityGateDrainsHighFirst(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-hi", Provider: "codex", Attributes: map[string]string{"priority": "100"}},
		{ID: "auth-lo", Provider: "codex"}, // priority 0 (long-lived reserve)
	}
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: newFakeQuotaFetcher(nil),
		TTL:     time.Minute,
		Async:   true,
	})
	// Both healthy; auth-lo is even fresher. Without the gate the inner RR
	// would happily rotate onto auth-lo — the gate must keep it out.
	selector.PushSnapshot("auth-hi", QuotaSnapshot{UsedPercentPrimary: 40, UsedPercentSecondary: 40})
	selector.PushSnapshot("auth-lo", QuotaSnapshot{UsedPercentPrimary: 1, UsedPercentSecondary: 1})

	for i := 0; i < 5; i++ {
		got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick error = %v", err)
		}
		if got.ID != "auth-hi" {
			t.Fatalf("pick %d: got %q, want auth-hi (higher priority must drain first)", i, got.ID)
		}
	}
}

// TestLeastRemainingQuotaSelector_PrioritySpillsWhenHighExhausted verifies
// the auto-spill: once every account at the top priority level is excluded
// (limit_reached / >= UnhealthyUsedPercent), the gate falls through to the
// next level down without any manual intervention.
func TestLeastRemainingQuotaSelector_PrioritySpillsWhenHighExhausted(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-hi", Provider: "codex", Attributes: map[string]string{"priority": "100"}},
		{ID: "auth-lo", Provider: "codex"},
	}
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: newFakeQuotaFetcher(nil),
		TTL:     time.Minute,
		Async:   true,
	})
	// High-priority account is saturated; must spill to the long-lived one.
	selector.PushSnapshot("auth-hi", QuotaSnapshot{UsedPercentPrimary: 0, LimitReached: true})
	selector.PushSnapshot("auth-lo", QuotaSnapshot{UsedPercentPrimary: 20, UsedPercentSecondary: 5})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-lo" {
		t.Fatalf("got %q, want auth-lo (auth-hi exhausted, gate must spill down a level)", got.ID)
	}
}

// TestLeastRemainingQuotaSelector_PrioritySpillsOnModelStateQuotaExceeded
// is the regression test for the 2026-07-02 production incident: a
// high-priority account (priority=100) hits an upstream 429, MarkResult
// flips its ModelState to Unavailable + Quota.Exceeded in real time, but
// the wham/usage cache snapshot still shows it as healthy (1% used) because
// the refresher lags by minutes. Before the fix, gateByPriority consulted
// only the stale quota cache, kept maxPriority=100, and locked out every
// priority=0 live account — starving the pool and returning 500 for ~4
// minutes until the refresher caught up. After the fix, isExcludedNow /
// partitionByQuota also consult ModelState, so the just-429'd account is
// excluded immediately and the gate spills to the priority=0 reserve.
func TestLeastRemainingQuotaSelector_PrioritySpillsOnModelStateQuotaExceeded(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auths := []*Auth{
		{
			ID:         "auth-hi",
			Provider:   "codex",
			Attributes: map[string]string{"priority": "100"},
			// ModelState reflects the real-time 429: MarkResult marked
			// this model Unavailable with a quota-exceeded cooldown.
			ModelStates: map[string]*ModelState{
				"gpt-5.5": {
					Unavailable:    true,
					Status:         StatusError,
					NextRetryAfter: now.Add(5 * time.Minute),
					Quota: QuotaState{
						Exceeded:      true,
						Reason:        "quota",
						NextRecoverAt: now.Add(5 * time.Minute),
					},
				},
			},
		},
		{ID: "auth-lo", Provider: "codex"}, // priority 0 (long-lived reserve)
	}
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: newFakeQuotaFetcher(nil),
		TTL:     time.Minute,
		Async:   true,
	})
	// Stale quota cache: auth-hi still looks healthy (1%), auth-lo is
	// usable. This is the exact production state that caused the incident.
	selector.PushSnapshot("auth-hi", QuotaSnapshot{UsedPercentPrimary: 1, UsedPercentSecondary: 0})
	selector.PushSnapshot("auth-lo", QuotaSnapshot{UsedPercentPrimary: 20, UsedPercentSecondary: 5})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v (expected spill to auth-lo whose ModelState is clean)", err)
	}
	if got.ID != "auth-lo" {
		t.Fatalf("got %q, want auth-lo (auth-hi ModelState says quota-excluded even though stale cache shows 1%%; gate must spill to priority=0)", got.ID)
	}
}

// TestLeastRemainingQuotaSelector_ModelStateExcludedEvenAtSamePriority
// verifies the partitionByQuota ModelState check in isolation: two
// same-priority accounts, one with a ModelState quota-exceeded marker, the
// other clean. The clean one must be picked — the stale quota cache would
// have put both in the healthy tier without the ModelState guard.
func TestLeastRemainingQuotaSelector_ModelStateExcludedEvenAtSamePriority(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auths := []*Auth{
		{
			ID:       "auth-429",
			Provider: "codex",
			ModelStates: map[string]*ModelState{
				"gpt-5.5": {
					Unavailable:    true,
					Status:         StatusError,
					NextRetryAfter: now.Add(5 * time.Minute),
					Quota:          QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: now.Add(5 * time.Minute)},
				},
			},
		},
		{ID: "auth-ok", Provider: "codex"},
	}
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 0}},
		Fetcher: newFakeQuotaFetcher(nil),
		TTL:     time.Minute,
		Async:   true,
	})
	// Both look healthy in the stale cache; only ModelState distinguishes them.
	selector.PushSnapshot("auth-429", QuotaSnapshot{UsedPercentPrimary: 1})
	selector.PushSnapshot("auth-ok", QuotaSnapshot{UsedPercentPrimary: 10})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-ok" {
		t.Fatalf("got %q, want auth-ok (auth-429 has ModelState quota-exceeded; must be excluded despite stale 1%% cache)", got.ID)
	}
}

// TestLeastRemainingQuotaSelector_AdaptiveFloorPromotesStressed verifies the
// small-pool fix: with one healthy and one stressed account at the same
// priority, the stressed account is promoted so the pool holds both — the
// stressed one is therefore reachable, whereas the old hard tier gate would
// have hidden it entirely behind the single healthy candidate.
func TestLeastRemainingQuotaSelector_AdaptiveFloorPromotesStressed(t *testing.T) {
	t.Parallel()

	auths := []*Auth{
		{ID: "auth-fresh", Provider: "codex"},
		{ID: "auth-stressed", Provider: "codex"},
	}
	selector := NewLeastRemainingQuotaSelector(LeastRemainingQuotaConfig{
		// Cursor 1 targets the second pool slot; the pool is built as
		// healthy (auth-fresh) + promoted (auth-stressed), so index 1 is
		// the promoted stressed account. If promotion did NOT happen the
		// pool would be size 1 and 1%1==0 would land on auth-fresh.
		Inner:   &RoundRobinSelector{cursors: map[string]int{"codex:gpt-5.5": 1}},
		Fetcher: newFakeQuotaFetcher(nil),
		TTL:     time.Minute,
		Async:   true,
	})
	selector.PushSnapshot("auth-fresh", QuotaSnapshot{UsedPercentPrimary: 9, UsedPercentSecondary: 1})
	selector.PushSnapshot("auth-stressed", QuotaSnapshot{UsedPercentPrimary: 80, UsedPercentSecondary: 20})

	got, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick error = %v", err)
	}
	if got.ID != "auth-stressed" {
		t.Fatalf("got %q, want auth-stressed (adaptive floor should promote it into the pool)", got.ID)
	}
}

// TestCodexAuthPriority_ReadsBothSources checks the precedence and the
// several JSON shapes a Metadata-sourced priority can arrive in.
func TestCodexAuthPriority_ReadsBothSources(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		auth *Auth
		want int
	}{
		{"nil", nil, 0},
		{"unset", &Auth{}, 0},
		{"attributes-string", &Auth{Attributes: map[string]string{"priority": "7"}}, 7},
		{"metadata-float64", &Auth{Metadata: map[string]any{"priority": float64(5)}}, 5},
		{"metadata-int", &Auth{Metadata: map[string]any{"priority": 3}}, 3},
		{"metadata-string", &Auth{Metadata: map[string]any{"priority": "9"}}, 9},
		{
			"attributes-wins-over-metadata",
			&Auth{Attributes: map[string]string{"priority": "100"}, Metadata: map[string]any{"priority": float64(1)}},
			100,
		},
		{"attributes-unparseable-falls-through", &Auth{Attributes: map[string]string{"priority": "abc"}, Metadata: map[string]any{"priority": 4}}, 4},
	}
	for _, tc := range cases {
		if got := codexAuthPriority(tc.auth); got != tc.want {
			t.Errorf("%s: codexAuthPriority = %d, want %d", tc.name, got, tc.want)
		}
	}
}
