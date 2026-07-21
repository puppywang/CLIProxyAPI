package quota

import (
	"testing"
)

// Bodies captured from real grok /v1/billing responses for an account whose
// SuperGrok weekly cap is exhausted while its monthly credit pool is not.
const (
	xaiWeeklyBody  = `{"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","start":"2026-07-14T05:50:14.132220+00:00","end":"2026-07-21T05:50:14.132220+00:00"},"creditUsagePercent":100.0,"onDemandCap":{"val":0},"onDemandUsed":{"val":0},"productUsage":[{"product":"Api","usagePercent":97.0},{"product":"GrokChat","usagePercent":3.0}],"isUnifiedBillingUser":true,"prepaidBalance":{"val":0},"topUpMethod":"TOP_UP_METHOD_SAVED_PAYMENT_METHOD","billingPeriodStart":"2026-07-14T05:50:14.132220+00:00","billingPeriodEnd":"2026-07-21T05:50:14.132220+00:00"}}`
	xaiMonthlyBody = `{"config":{"monthlyLimit":{"val":20000},"used":{"val":8264},"onDemandCap":{"val":0},"billingPeriodStart":"2026-07-01T00:00:00+00:00","billingPeriodEnd":"2026-08-01T00:00:00+00:00","history":[]}}`
)

func TestParseXAIWeekly(t *testing.T) {
	pct, reset, reached, ok := parseXAIWeekly([]byte(xaiWeeklyBody))
	if !ok {
		t.Fatal("expected ok=true for a WEEKLY currentPeriod")
	}
	if pct != 100 {
		t.Errorf("pct = %d, want 100", pct)
	}
	if !reached {
		t.Error("limitReached = false, want true (creditUsagePercent 100)")
	}
	if reset.IsZero() {
		t.Error("reset is zero; want parsed currentPeriod.end")
	}
	if got := reset.UTC().Format("2006-01-02T15:04:05"); got != "2026-07-21T05:50:14" {
		t.Errorf("reset = %s, want weekly currentPeriod.end 2026-07-21T05:50:14", got)
	}
}

func TestParseXAIMonthly(t *testing.T) {
	pct, reset, reached, ok := parseXAIMonthly([]byte(xaiMonthlyBody))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if pct != 41 { // 8264 / 20000 = 41.32 -> 41
		t.Errorf("pct = %d, want 41", pct)
	}
	if reached {
		t.Error("limitReached = true, want false (monthly not exhausted)")
	}
	if got := reset.UTC().Format("2006-01-02"); got != "2026-08-01" {
		t.Errorf("reset = %s, want monthly billingPeriodEnd 2026-08-01", got)
	}
}

// A credits body whose currentPeriod is not weekly must be rejected so a schema
// change never mislabels some other window as the weekly cap.
func TestParseXAIWeekly_RejectsNonWeekly(t *testing.T) {
	body := `{"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_MONTHLY","end":"2026-08-01T00:00:00+00:00"},"creditUsagePercent":10.0}}`
	if _, _, _, ok := parseXAIWeekly([]byte(body)); ok {
		t.Error("ok = true for a non-WEEKLY currentPeriod, want false")
	}
}
