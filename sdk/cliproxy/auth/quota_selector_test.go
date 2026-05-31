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
