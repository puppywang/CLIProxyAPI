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
//   - a recent previous sample (within quotaPassiveGap) marks the reset
//     "passive" (observed live through a continuous refresh cadence);
//   - a gap before the drop marks it "active" (exact reset time uncertain);
//   - noise around zero (3% -> 0%) is not a reset.
func TestQuotaHistoryResetMarking(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	// 1. 100% -> 0% with a normal 10-min cadence: passive reset.
	s.record("acct-1", 100, 30, false, base)
	s.record("acct-1", 0, 30, false, base.Add(10*time.Minute))
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("100%%->0%% at 10min gap: expected passive mark, got %q", series[1].R)
	}

	// 2. 7% -> 0% with a normal cadence: passive reset (small drop still a reset).
	s.record("acct-2", 7, 20, false, base)
	s.record("acct-2", 0, 20, false, base.Add(12*time.Minute))
	series = s.data["acct-2"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-2, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("7%%->0%% at 12min gap: expected passive mark, got %q", series[1].R)
	}

	// 3. 100% -> 0% across a long gap: active reset (refresher was down).
	s.record("acct-3", 100, 30, false, base)
	s.record("acct-3", 0, 30, false, base.Add(4*time.Hour))
	series = s.data["acct-3"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-3, got %d", len(series))
	}
	if series[1].R != "a" {
		t.Fatalf("100%%->0%% after 4h gap: expected active mark, got %q", series[1].R)
	}

	// 4. 3% -> 0%: noise near zero, not a reset.
	s.record("acct-4", 3, 10, false, base)
	s.record("acct-4", 0, 10, false, base.Add(10*time.Minute))
	series = s.data["acct-4"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-4, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("3%%->0%%: expected no reset mark, got %q", series[1].R)
	}

	// 5. 100% -> 90%: gradual change, not a reset.
	s.record("acct-5", 100, 30, false, base)
	s.record("acct-5", 90, 30, false, base.Add(10*time.Minute))
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
	s.record("acct-1", 0, 30, false, base.Add(20*time.Minute))
	series = s.data["acct-1"]
	if len(series) != 3 {
		t.Fatalf("unchanged 0%% after 10min: expected curve sample appended, got %d samples", len(series))
	}
	if series[2].R != "" {
		t.Fatalf("0%%->0%%: expected no reset mark on steady sample, got %q", series[2].R)
	}
	n := len(series)
	s.record("acct-1", 0, 30, false, base.Add(20*time.Minute+30*time.Second))
	if got := len(s.data["acct-1"]); got != n {
		t.Fatalf("unchanged 0%% within 1min: expected dedupe (%d), got %d", n, got)
	}
}

// TestQuotaHistoryResetMarking_PartialReset verifies that a collapse that
// still leaves the window above the floor (e.g. 60% -> 15%) is NOT marked —
// only collapses to (near) zero are resets.
func TestQuotaHistoryResetMarking_PartialReset(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	s.record("acct-1", 60, 40, false, base)
	s.record("acct-1", 15, 40, false, base.Add(10*time.Minute))
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

	s.record("acct-1", 50, 100, false, base)
	s.record("acct-1", 50, 0, false, base.Add(10*time.Minute))
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "" {
		t.Fatalf("secondary-only collapse: expected no primary reset mark, got %q", series[1].R)
	}
}
