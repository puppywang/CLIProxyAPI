package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// TestLeastBoundSelector_PickFewestBindings verifies the basic ranking:
// the auth with the lowest binding count wins, regardless of input order.
func TestLeastBoundSelector_PickFewestBindings(t *testing.T) {
	t.Parallel()

	counts := map[string]int{
		"a": 3,
		"b": 1,
		"c": 5,
	}
	selector := NewLeastBoundSelector(func(id string) int { return counts[id] }, nil)
	auths := []*Auth{{ID: "a"}, {ID: "b"}, {ID: "c"}}

	got, err := selector.Pick(context.Background(), "mixed", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "b" {
		t.Fatalf("Pick() = %v, want auth b", got)
	}
}

// TestLeastBoundSelector_SecondaryScoreTiebreak verifies that when binding
// counts tie, the secondary score (used_percent) breaks the tie with the
// lower score winning.
func TestLeastBoundSelector_SecondaryScoreTiebreak(t *testing.T) {
	t.Parallel()

	counts := map[string]int{
		"a": 0,
		"b": 0,
		"c": 0,
	}
	scores := map[string]int{
		"a": 60,
		"b": 10,
		"c": 40,
	}
	selector := NewLeastBoundSelector(
		func(id string) int { return counts[id] },
		func(id string) int { return scores[id] },
	)
	auths := []*Auth{{ID: "a"}, {ID: "b"}, {ID: "c"}}

	got, err := selector.Pick(context.Background(), "mixed", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "b" {
		t.Fatalf("Pick() = %v, want auth b (lowest score)", got)
	}
}

// TestLeastBoundSelector_IDTiebreak verifies the deterministic ID-order
// tiebreak when both binding count and secondary score are equal.
func TestLeastBoundSelector_IDTiebreak(t *testing.T) {
	t.Parallel()

	selector := NewLeastBoundSelector(
		func(id string) int { return 0 },
		func(id string) int { return 0 },
	)
	auths := []*Auth{{ID: "c"}, {ID: "a"}, {ID: "b"}}

	got, err := selector.Pick(context.Background(), "mixed", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "a" {
		t.Fatalf("Pick() = %v, want auth a (alphabetically first)", got)
	}
}

// TestLeastBoundSelector_BindingSnapshotOverride verifies that an in-
// context binding snapshot trumps the installed counter callback. This
// is how SessionAffinitySelector hands a lock-consistent view down.
func TestLeastBoundSelector_BindingSnapshotOverride(t *testing.T) {
	t.Parallel()

	staleCounts := map[string]int{"a": 0, "b": 0, "c": 0}
	selector := NewLeastBoundSelector(
		func(id string) int { return staleCounts[id] },
		nil,
	)
	auths := []*Auth{{ID: "a"}, {ID: "b"}, {ID: "c"}}

	// Inject a "fresh" snapshot that says b has 5 bindings. The selector
	// should ignore staleCounts in favour of the snapshot and pick a (the
	// lowest in the snapshot with the alphabetically earliest id).
	ctx := WithBindingSnapshot(context.Background(), map[string]int{
		"a": 0, "b": 5, "c": 0,
	})
	got, err := selector.Pick(ctx, "mixed", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "a" {
		t.Fatalf("Pick() = %v, want auth a (snapshot beats stale counter)", got)
	}
}

// TestSessionAffinitySelector_ConcurrentCacheMissAtomicClaim is the
// regression test for the production bug. It simulates N parallel
// first-turn requests into a fresh cache: when bindings start at
// (0, 0, 0), the atomic-claim path under the cache write lock must
// distribute each request onto a distinct auth — pre-fix, the
// candidate with the lexicographically smallest ID won every call
// because all snapshots showed it at 0 bindings.
func TestSessionAffinitySelector_ConcurrentCacheMissAtomicClaim(t *testing.T) {
	t.Parallel()

	auths := []*Auth{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	inner := NewLeastBoundSelector(nil, nil)

	cfg := SessionAffinityConfig{
		Fallback: inner,
		TTL:      time.Minute,
	}
	selector := NewSessionAffinitySelectorWithConfig(cfg)
	t.Cleanup(selector.Stop)

	const n = 3
	var (
		wg      sync.WaitGroup
		results = make([]string, n)
	)
	for i := 0; i < n; i++ {
		idx := i
		// Each call carries a distinct session id so the cache misses
		// for every request and goes through the atomic-claim path.
		sessionID := "session-" + string(rune('a'+idx))
		opts := cliproxyexecutor.Options{
			Headers: map[string][]string{
				"X-Codex-Turn-Metadata": {`{"session_id":"` + sessionID + `","thread_id":"` + sessionID + `","turn_id":"t","thread_source":"user"}`},
			},
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := selector.Pick(context.Background(), "mixed", "gpt-5.5", opts, auths)
			if err != nil {
				t.Errorf("Pick() #%d error = %v", idx, err)
				return
			}
			if got == nil {
				t.Errorf("Pick() #%d returned nil auth", idx)
				return
			}
			results[idx] = got.ID
		}()
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for _, id := range results {
		if id == "" {
			continue
		}
		seen[id] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d distinct auths under atomic claim, got %d: results=%v", n, len(seen), results)
	}
}
