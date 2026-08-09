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
//   - the reset is "passive" when the quota API's declared reset time
//     (reset_at captured on the previous sample) falls within
//     quotaPassiveSlack of the observation — a true CD-cooldown rollover;
//   - the reset is "active" when it happens well before the declared reset
//     time (manual reset / account switch / anomaly);
//   - noise around zero (3% -> 0%) is not a reset.
func TestQuotaHistoryResetMarking(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	// 1. 100% -> 0% and the API had declared the reset at this very moment:
	// passive (true CD cooldown).
	resetAt := base.Add(10 * time.Minute)
	s.record("acct-1", 100, 30, false, resetAt, base)
	s.record("acct-1", 0, 30, false, resetAt.Add(5*time.Hour), resetAt)
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("100%%->0%% at declared reset time: expected passive mark, got %q", series[1].R)
	}

	// 2. 7% -> 0% with the API declaring the reset at the same moment:
	// passive (small drop still a reset, and it IS the declared rollover).
	resetAt2 := base.Add(12 * time.Minute)
	s.record("acct-2", 7, 20, false, resetAt2, base)
	s.record("acct-2", 0, 20, false, resetAt2.Add(5*time.Hour), resetAt2)
	series = s.data["acct-2"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-2, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("7%%->0%% at declared reset time: expected passive mark, got %q", series[1].R)
	}

	// 3. 100% -> 0% but the API says the reset is hours away: active.
	s.record("acct-3", 100, 30, false, base.Add(4*time.Hour), base)
	s.record("acct-3", 0, 30, false, base.Add(4*time.Hour+30*time.Minute), base.Add(10*time.Minute))
	series = s.data["acct-3"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-3, got %d", len(series))
	}
	if series[1].R != "a" {
		t.Fatalf("100%%->0%% before declared reset time: expected active mark, got %q", series[1].R)
	}

	// 4. 3% -> 0%: noise near zero, not a reset.
	s.record("acct-4", 3, 10, false, base.Add(10*time.Minute), base)
	s.record("acct-4", 0, 10, false, base.Add(20*time.Minute), base.Add(10*time.Minute))
	series = s.data["acct-4"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-4, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("3%%->0%%: expected no reset mark, got %q", series[1].R)
	}

	// 5. 100% -> 90%: gradual change, not a reset.
	s.record("acct-5", 100, 30, false, base.Add(10*time.Minute), base)
	s.record("acct-5", 90, 30, false, base.Add(10*time.Minute), base.Add(10*time.Minute))
	series = s.data["acct-5"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-5, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("100%%->90%%: expected no reset mark, got %q", series[1].R)
	}

	// 6. Steady state after a reset (0% -> 0%): no duplicate RESET MARK.
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
// behaviour: when the previous sample has no recorded API reset_at (ra=0),
// the reset type CANNOT be determined — the mark stays empty ("unknown")
// rather than guessing passive from a saturated window. Only samples with
// a known reset_at get a p/a classification.
func TestQuotaHistoryResetMarking_LegacyNoResetAt(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	// Saturated 100% -> 0% with no ra on the previous sample: detected as
	// a reset but the type is unknown (no mark).
	s.record("acct-1", 100, 40, false, time.Time{}, base)
	s.record("acct-1", 0, 40, false, time.Time{}, base.Add(10*time.Minute))
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("legacy 100%%->0%%: expected unknown (empty) mark, got %q", series[1].R)
	}

	// Low 7% -> 0% with no ra: also unknown.
	s.record("acct-2", 7, 10, false, time.Time{}, base)
	s.record("acct-2", 0, 10, false, time.Time{}, base.Add(10*time.Minute))
	series = s.data["acct-2"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-2, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("legacy 7%%->0%%: expected unknown (empty) mark, got %q", series[1].R)
	}

	// With a known reset_at the classification works (passive at rollover).
	resetAt := base.Add(10 * time.Minute)
	s.record("acct-3", 100, 40, false, resetAt, base)
	s.record("acct-3", 0, 40, false, resetAt.Add(5*time.Hour), resetAt)
	series = s.data["acct-3"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-3, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("known reset_at rollover: expected passive mark, got %q", series[1].R)
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
