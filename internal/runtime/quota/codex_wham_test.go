package quota

import "testing"

func TestParseWhamUsage_PlanType(t *testing.T) {
	body := []byte(`{
		"plan_type": "plus",
		"rate_limit": {
			"limit_reached": false,
			"primary_window": {"used_percent": 6, "reset_at": 1786220989},
			"secondary_window": {"used_percent": 0}
		}
	}`)
	snap, ok, err := parseWhamUsage(body)
	if err != nil {
		t.Fatalf("parseWhamUsage: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if snap.PlanType != "plus" {
		t.Fatalf("PlanType = %q, want plus", snap.PlanType)
	}
	if snap.UsedPercentPrimary != 6 {
		t.Fatalf("UsedPercentPrimary = %d, want 6", snap.UsedPercentPrimary)
	}
}

func TestParseWhamUsage_MissingPlanType(t *testing.T) {
	body := []byte(`{
		"rate_limit": {
			"limit_reached": false,
			"primary_window": {"used_percent": 1}
		}
	}`)
	snap, ok, err := parseWhamUsage(body)
	if err != nil || !ok {
		t.Fatalf("parseWhamUsage: ok=%v err=%v", ok, err)
	}
	if snap.PlanType != "" {
		t.Fatalf("PlanType = %q, want empty", snap.PlanType)
	}
}
