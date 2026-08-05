package auth

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// BindingCounter returns the current live session-affinity binding count
// for an auth ID. Implementations must be safe for concurrent reads. The
// LeastBoundSelector consults this on every Pick to break the new-binding
// tie in favour of credentials that have the fewest existing sessions
// attached. Returning 0 for an unknown auth is fine.
type BindingCounter func(authID string) int

// LeastBoundSelector chooses the candidate auth that currently has the
// fewest live session-affinity bindings, with ties broken by an injected
// secondary signal (used_percent) and finally by ID. It replaces the
// per-pool RoundRobinSelector for codex traffic so a fresh window is
// always pinned to the credential carrying the lightest load — without
// this, the inner RR's cursor cycling could (and did) re-bind a 4th
// window to an account already serving three while another account sat
// idle.
//
// The selector is intentionally allocation-light. It expects:
//   - bindingCounter: snapshot of auth_id → binding count taken under
//     the session cache's write lock so the count is consistent with
//     the bind-or-no-bind decision the caller is about to commit.
//     When nil (e.g. unit tests), every candidate is treated as having
//     zero bindings.
//   - secondaryScore: optional helper that returns a comparable score
//     for an auth (lower is preferred). LeastRemainingQuotaSelector
//     wires this to the cached used_percent so 0-binding ties prefer
//     the freshest account. When nil all candidates score identically.
//
// Concurrency contract: Pick is safe for concurrent callers. The atomic
// "count → pick → write" contract is the responsibility of the
// SessionAffinitySelector (which holds the cache write lock around the
// nested Pick call); LeastBoundSelector itself owns no shared state.
type LeastBoundSelector struct {
	// mu guards the optional counter/score callbacks against installation
	// races. Pick reads the callbacks under RLock so swapping them at
	// runtime is safe.
	mu             sync.RWMutex
	bindingCounter BindingCounter
	secondaryScore func(authID string) int
}

// NewLeastBoundSelector constructs a selector. Either callback may be nil;
// the selector falls back to treating all auths as zero-bindings /
// equal-score when the corresponding callback is unset.
func NewLeastBoundSelector(counter BindingCounter, secondary func(authID string) int) *LeastBoundSelector {
	return &LeastBoundSelector{
		bindingCounter: counter,
		secondaryScore: secondary,
	}
}

// SetBindingCounter installs (or replaces) the binding counter callback.
// Safe to call at runtime — Pick is read-locked on the callback fields.
func (s *LeastBoundSelector) SetBindingCounter(counter BindingCounter) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.bindingCounter = counter
	s.mu.Unlock()
}

// SetSecondaryScore installs (or replaces) the secondary-score callback.
func (s *LeastBoundSelector) SetSecondaryScore(secondary func(authID string) int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.secondaryScore = secondary
	s.mu.Unlock()
}

// bindingCountContextKey carries a pre-snapshotted binding count map
// through to a nested Pick. Used by SessionAffinitySelector when it has
// already taken the cache write lock and wants the inner selector to
// see exactly the snapshot the lock captured. Falls back to the
// installed callback when no map is on the context.
type bindingCountContextKey struct{}

// WithBindingSnapshot attaches a pre-computed binding count snapshot to
// ctx. Inside LeastBoundSelector.Pick this snapshot wins over the
// installed BindingCounter callback so the caller can guarantee the
// count is consistent with the lock-protected critical section.
func WithBindingSnapshot(ctx context.Context, bindings map[string]int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if bindings == nil {
		return ctx
	}
	return context.WithValue(ctx, bindingCountContextKey{}, bindings)
}

func bindingSnapshotFromContext(ctx context.Context) map[string]int {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(bindingCountContextKey{}).(map[string]int)
	return v
}

// Pick implements Selector. The candidate pool is sorted by:
//
//  1. live binding count (ascending — pick the credential with the
//     fewest existing sessions),
//  2. injected secondary score (ascending — typically used_percent),
//  3. ID (ascending — deterministic tiebreak).
//
// Ranking is stable across processes for the same input — sort.Stable
// preserves the slimming order the upstream selector chain produced.
// The first element after sort is returned.
func (s *LeastBoundSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	available, err := getAvailableAuths(auths, provider, model, time.Now())
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	return s.pickFromPool(ctx, available)
}

// pickFromPool runs the ranking algorithm against an already-filtered list
// of candidates. Exported for the session-affinity selector to call into
// once it has snapshotted the binding map under the cache write lock —
// avoiding a second blocking-availability check inside the critical
// section.
func (s *LeastBoundSelector) pickFromPool(ctx context.Context, pool []*Auth) (*Auth, error) {
	if len(pool) == 0 {
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available"}
	}

	snapshot := bindingSnapshotFromContext(ctx)
	s.mu.RLock()
	counter := s.bindingCounter
	secondary := s.secondaryScore
	s.mu.RUnlock()

	count := func(id string) int {
		if snapshot != nil {
			return snapshot[id]
		}
		if counter != nil {
			return counter(id)
		}
		return 0
	}
	score := func(id string) int {
		if secondary == nil {
			return 0
		}
		return secondary(id)
	}

	indexed := make([]int, len(pool))
	for i := range indexed {
		indexed[i] = i
	}
	// Sort priority changed 2026-06-03 from (binding_count, score, ID) to
	// (score, binding_count, ID). The earlier ordering treated binding
	// count as the primary signal — but with local-bytes accumulation
	// folded into the score (see CombinedQuotaScore), every pick lifts
	// the chosen auth's effective score and the next pick rotates
	// naturally. Binding count was only ever a proxy for "this auth got
	// picked recently"; with the score itself reflecting that, the proxy
	// is redundant and was actively wrong in the operator-reported case
	// (tanaka 1%/1% lost to suzukiyuki 1%/53% because tanaka had 2 stale
	// cache rows from a 1.5h-old hermes session). Binding count stays as
	// a tiebreak for the rare case where two accounts share an identical
	// effective score (e.g. both at neutral because neither has fresh
	// wham data yet).
	sort.SliceStable(indexed, func(i, j int) bool {
		a := pool[indexed[i]]
		b := pool[indexed[j]]
		sa, sb := score(a.ID), score(b.ID)
		if sa != sb {
			return sa < sb
		}
		ca, cb := count(a.ID), count(b.ID)
		if ca != cb {
			return ca < cb
		}
		return strings.Compare(a.ID, b.ID) < 0
	})
	return pool[indexed[0]], nil
}
