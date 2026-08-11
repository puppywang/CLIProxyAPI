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
//   - the reset is "passive" when it is observed at (about) the reset time
//     the quota API had been continuously advertising on the PREVIOUS
//     sample (last.RA) — a true CD-cooldown rollover;
//   - the reset is "active" when it happens well before (or after) the
//     advertised reset time (early rollover / manual reset / account
//     switch) — even when wham hands back a fresh full window;
//   - noise around zero (3% -> 0%) is not a reset.
func TestQuotaHistoryResetMarking(t *testing.T) {
	s := newQuotaHistoryStore("")
	base := time.Now()

	// 1. 100% -> 0% observed right at the advertised reset_at (+10min):
	// passive (true CD cooldown). The fresh 7d reset_at is the normal
	// aftermath, not the passive signal.
	advertised := base.Add(10 * time.Minute)
	s.record("acct-1", 100, 30, false, advertised, base)
	s.record("acct-1", 0, 30, false, base.Add(7*24*time.Hour), advertised)
	series := s.data["acct-1"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("100%%->0%% at advertised reset_at: expected passive mark, got %q", series[1].R)
	}

	// 2. 7% -> 0% observed at the advertised reset_at: passive (small
	// drop still a reset).
	advertised2 := base.Add(12 * time.Minute)
	s.record("acct-2", 7, 20, false, advertised2, base)
	s.record("acct-2", 0, 20, false, base.Add(7*24*time.Hour), advertised2)
	series = s.data["acct-2"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-2, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("7%%->0%% at advertised reset_at: expected passive mark, got %q", series[1].R)
	}

	// 3. 100% -> 0% observed well BEFORE the advertised reset_at (e.g.
	// advertised +4h, but the reset lands at +10min): active — an early
	// rollover / manual reset. The fresh 7d reset_at does NOT make it
	// passive.
	s.record("acct-3", 100, 30, false, base.Add(4*time.Hour), base)
	s.record("acct-3", 0, 30, false, base.Add(7*24*time.Hour), base.Add(10*time.Minute))
	series = s.data["acct-3"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-3, got %d", len(series))
	}
	if series[1].R != "a" {
		t.Fatalf("100%%->0%% before advertised reset_at: expected active mark, got %q", series[1].R)
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
	s.record("acct-1", 0, 30, false, advertised.Add(10*time.Hour), advertised.Add(20*time.Minute))
	series = s.data["acct-1"]
	if len(series) != 3 {
		t.Fatalf("unchanged 0%% after 10min: expected curve sample appended, got %d samples", len(series))
	}
	if series[2].R != "" {
		t.Fatalf("0%%->0%%: expected no reset mark on steady sample, got %q", series[2].R)
	}
	n := len(series)
	s.record("acct-1", 0, 30, false, advertised.Add(10*time.Hour), advertised.Add(20*time.Minute+30*time.Second))
	if got := len(s.data["acct-1"]); got != n {
		t.Fatalf("unchanged 0%% within 1min: expected dedupe (%d), got %d", n, got)
	}
}

// TestQuotaHistoryResetMarking_LegacyNoResetAt verifies the legacy-sample
// behaviour: when the previous sample has no recorded API reset_at (ra=0),
// the reset type CANNOT be determined — the mark stays empty ("unknown").
// A reset observed at (about) the OLD advertised rollover is passive even
// when the new sample carries no reset_at.
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

	// Reset observed at the OLD advertised rollover (+10min) even though
	// the new sample carries no reset_at: passive.
	advertised := base.Add(10 * time.Minute)
	s.record("acct-2", 100, 40, false, advertised, base) // old ra = +10min
	s.record("acct-2", 0, 40, false, time.Time{}, advertised)
	series = s.data["acct-2"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-2, got %d", len(series))
	}
	if series[1].R != "p" {
		t.Fatalf("reset at old advertised rollover: expected passive mark, got %q", series[1].R)
	}

	// Reset observed long AFTER the advertised rollover (+2h) with no new
	// reset_at: the reset is late — active (not a clean CD rollover).
	s.record("acct-3", 100, 40, false, advertised, base)
	s.record("acct-3", 0, 40, false, time.Time{}, base.Add(2*time.Hour))
	series = s.data["acct-3"]
	if len(series) != 2 {
		t.Fatalf("expected 2 samples for acct-3, got %d", len(series))
	}
	if series[1].R != "a" {
		t.Fatalf("reset long after advertised rollover: expected active mark, got %q", series[1].R)
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
