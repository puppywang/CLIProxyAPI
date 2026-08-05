package quota

import (
	"errors"
	"fmt"
	"testing"
)

func TestClassifyDeadAccount(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantDead   bool
		wantReason string
	}{
		{"nil", nil, false, ""},
		{
			"deactivated_workspace 402",
			fmt.Errorf(`wham/usage status 402: {"detail":{"code":"deactivated_workspace"}}`),
			true, "workspace deactivated",
		},
		{
			"account deactivated 401",
			errors.New("wham/usage status 401: This account has been deactivated"),
			true, "account deactivated",
		},
		{
			"account_deactivated code",
			errors.New(`{"code":"account_deactivated"}`),
			true, "account deactivated",
		},
		{
			"transient 429 is NOT dead",
			fmt.Errorf("wham/usage status 429: rate limited"),
			false, "",
		},
		{
			"5xx is NOT dead",
			fmt.Errorf("wham/usage status 503: upstream unavailable"),
			false, "",
		},
		{
			"network blip is NOT dead",
			errors.New("context deadline exceeded"),
			false, "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, dead := classifyDeadAccount(tc.err)
			if dead != tc.wantDead {
				t.Fatalf("dead = %v, want %v (err=%v)", dead, tc.wantDead, tc.err)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

func TestRefresherDeadMarkerLifecycle(t *testing.T) {
	r := &Refresher{dead: map[string]deadMarker{}}

	// Terminal error records the marker.
	r.noteFetchOutcome("acct1", false, errors.New("wham/usage status 402: deactivated_workspace"))
	reason, since, ok := r.DeadMarker("acct1")
	if !ok || reason != "workspace deactivated" || since.IsZero() {
		t.Fatalf("expected dead marker, got ok=%v reason=%q since=%v", ok, reason, since)
	}

	// A transient error does not disturb the existing marker.
	r.noteFetchOutcome("acct1", false, errors.New("wham/usage status 503: upstream"))
	if _, _, ok := r.DeadMarker("acct1"); !ok {
		t.Fatal("transient error should not clear an existing dead marker")
	}

	// A transient error on a healthy account never creates a marker.
	r.noteFetchOutcome("acct2", false, errors.New("context deadline exceeded"))
	if _, _, ok := r.DeadMarker("acct2"); ok {
		t.Fatal("transient error must not create a dead marker")
	}

	// A successful fetch clears the marker (account recovered).
	r.noteFetchOutcome("acct1", true, nil)
	if _, _, ok := r.DeadMarker("acct1"); ok {
		t.Fatal("successful fetch should clear the dead marker")
	}
}
