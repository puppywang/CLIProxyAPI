package monitor

import (
	"testing"
	"time"
)

// TestQuotaHistoryResetMarking verifies that primary-window resets are
// detected and tagged on the new sample:
//
//   - a collapse from a real usage level to near zero counts as a reset even
//     when the drop is small (7% -> 0% is a reset, the old >=25-point drop
//     threshold would have missed it);
//   - the reset is "passive" when the quota API hands back a NEW reset_at a
//     full window away (7d/30d) from the observation — the server restarted
//     the window at the rollover (a true CD-cooldown reset);
//   - the reset is "active" when a new reset_at comes back but is not a full
//     window away (early rollover / account switch / anomaly);
//   - noise around zero (3% -> 0%) is not a reset.
func TestQuotaHistoryResetMarking(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	// 1. 100% -> 0% and the API hands back a fresh 7d window:
	// passive (true CD cooldown).
	resetAt := base.Add(10 * time.Minute)
	s.record("acct-1", 100, 30, false, resetAt, base)
	s.record("acct-1", 0, 30, false, base.Add(7*24*time.Hour), resetAt)
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("100%%->0%% with fresh 7d window: expected passive mark, got %q", series[1].R)
	}

	// 2. 7% -> 0% with a fresh 7d window: passive (small drop still a reset).
	resetAt2 := base.Add(12 * time.Minute)
	s.record("acct-2", 7, 20, false, resetAt2, base)
	s.record("acct-2", 0, 20, false, base.Add(7*24*time.Hour), resetAt2)
	series = s.data["acct-2"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-2, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("7%%->0%% with fresh 7d window: expected passive mark, got %q", series[1].R)
	}

	// 3. 30d window (free account): passive too.
	resetAt3 := base.Add(14 * time.Minute)
	s.record("acct-3", 80, 40, false, resetAt3, base)
	s.record("acct-3", 0, 40, false, base.Add(30*24*time.Hour), resetAt3)
	series = s.data["acct-3"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-3, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("80%%->0%% with fresh 30d window: expected passive mark, got %q", series[1].R)
	}

	// 4. 100% -> 0% but the new reset_at is NOT a full window away
	// (e.g. only 4h — an early/manual rollover): active.
	s.record("acct-4", 100, 30, false, base.Add(4*time.Hour), base)
	s.record("acct-4", 0, 30, false, base.Add(4*time.Hour+30*time.Minute), base.Add(10*time.Minute))
	series = s.data["acct-4"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-4, got %d", len(series))
	}
	if series[1].R != "a" {
		t.Fatalf("100%%->0%% with non-window reset_at: expected active mark, got %q", series[1].R)
	}

	// 5. 3% -> 0%: noise near zero, not a reset.
	s.record("acct-5", 3, 10, false, base.Add(10*time.Minute), base)
	s.record("acct-5", 0, 10, false, base.Add(20*time.Minute), base.Add(10*time.Minute))
	series = s.data["acct-5"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-5, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("3%%->0%%: expected no reset mark, got %q", series[1].R)
	}

	// 6. 100% -> 90%: gradual change, not a reset.
	s.record("acct-6", 100, 30, false, base.Add(10*time.Minute), base)
	s.record("acct-6", 90, 30, false, base.Add(10*time.Minute), base.Add(10*time.Minute))
	series = s.data["acct-6"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-6, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("100%%->90%%: expected no reset mark, got %q", series[1].R)
	}

	// 7. Steady state after a reset (0% -> 0%): no duplicate RESET MARK.
	// (Unchanged samples still append for curve continuity when >1min apart,
	// but a burst within 1min is deduped and 0%->0% never re-marks.)
	s.record("acct-1", 0, 30, false, resetAt.Add(10*time.Hour), resetAt.Add(20*time.Minute))
	series = s.data["acct-1"]
	if len(series) != 3 {
		t.Fatalf("unchanged 0%% after 10min: expected curve sample appended, got %d samples", len(series))
	}
	if series[2].R != "" {
		t.Fatalf("0%%->0%%: expected no reset mark on steady sample, got %q", series[2].R)
	}
	n := len(series)
	s.record("acct-1", 0, 30, false, resetAt.Add(10*time.Hour), resetAt.Add(20*time.Minute+30*time.Second))
	if got := len(s.data["acct-1"]); got != n {
		t.Fatalf("unchanged 0%% within 1min: expected dedupe (%d), got %d", n, got)
	}
}

// TestQuotaHistoryResetMarking_LegacyNoResetAt verifies the legacy-sample
// behaviour: when the previous sample has no recorded API reset_at (ra=0)
// AND the new sample brings no reset_at either, the reset type CANNOT be
// determined — the mark stays empty ("unknown"). A reset that lands after
// the OLD window's declared rollover is passive even without a new reset_at.
func TestQuotaHistoryResetMarking_LegacyNoResetAt(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	// Saturated 100% -> 0% with no ra anywhere: detected as a reset but
	// the type is unknown (no mark).
	s.record("acct-1", 100, 40, false, time.Time{}, base)
	s.record("acct-1", 0, 40, false, time.Time{}, base.Add(10*time.Minute))
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("legacy 100%%->0%%: expected unknown (empty) mark, got %q", series[1].R)
	}

	// Old window's reset_at already passed + new sample carries no reset_at:
	// the drop IS that rollover → passive.
	resetAt := base.Add(10 * time.Minute)
	s.record("acct-2", 100, 40, false, resetAt, base)               // old ra = +10min
	s.record("acct-2", 0, 40, false, time.Time{}, base.Add(2*time.Hour)) // reset after old ra passed
	series = s.data["acct-2"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-2, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("reset after old rollover passed: expected passive mark, got %q", series[1].R)
	}

	// Old window's reset_at NOT yet passed + no new reset_at: unknown.
	s.record("acct-3", 100, 40, false, base.Add(10*time.Hour), base) // old ra = +10h (future)
	s.record("acct-3", 0, 40, false, time.Time{}, base.Add(2*time.Hour))
	series = s.data["acct-3"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-3, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("reset before old rollover with no new ra: expected unknown mark, got %q", series[1].R)
	}
}

// TestQuotaHistoryResetMarking_PartialReset verifies that a collapse that
// still leaves the window above the floor (e.g. 60% -> 15%) is NOT marked —
// only collapses to (near) zero are resets.
func TestQuotaHistoryResetMarking_PartialReset(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	s.record("acct-1", 60, 40, false, base.Add(10*time.Minute), base)
	s.record("acct-1", 15, 40, false, base.Add(20*time.Minute), base.Add(10*time.Minute))
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("60%%->15%%: expected no reset mark, got %q", series[1].R)
	}
}

// TestQuotaHistoryResetMarking_SecondaryOnly verifies that a collapse in the
// secondary window alone (primary unchanged) is not marked as a primary reset.
func TestQuotaHistoryResetMarking_SecondaryOnly(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	s.record("acct-1", 50, 100, false, base.Add(10*time.Minute), base)
	s.record("acct-1", 50, 0, false, base.Add(20*time.Minute), base.Add(10*time.Minute))
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("secondary-only collapse: expected no primary reset mark, got %q", series[1].R)
	}
}

// TestQuotaHistoryResetAtCaptured verifies that the API-declared reset time
// is stored on each sample and used for the passive/active classification.
func TestQuotaHistoryResetAtCaptured(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()
	resetAt := base.Add(10 * time.Minute)

	s.record("acct-1", 42, 10, false, resetAt, base)
	series := s.data["acct-1"]
	if len(series) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(series))
	}
	if series[0].RA != resetAt.Unix() {
		t.Fatalf("reset_at not captured: got %d want %d", series[0].RA, resetAt.Unix())
	}
	if got := series[0].ResetAt().Unix(); got != resetAt.Unix() {
		t.Fatalf("ResetAt() mismatch: got %d want %d", got, resetAt.Unix())
	}

	// Zero reset_at: stored as 0 and never classified passive or active —
	// the type is unknown.
	s.record("acct-2", 42, 10, false, time.Time{}, base)
	if s.data["acct-2"][0].RA != 0 {
		t.Fatalf("zero reset_at should store 0, got %d", s.data["acct-2"][0].RA)
	}
	s.record("acct-2", 0, 10, false, time.Time{}, base.Add(10*time.Minute))
	if got := s.data["acct-2"][1].R; got != "" {
		t.Fatalf("unknown reset_at drop: expected unknown (empty) mark, got %q", got)
	}
}
