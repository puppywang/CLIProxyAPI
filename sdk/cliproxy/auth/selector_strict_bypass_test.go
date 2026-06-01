package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// strictBypassPayload returns a body that carries the session affinity
// signal used by extractSessionIDs — a Claude-style `user_id` containing
// `_session_<id>` is the path that matches without needing real headers.
func strictBypassPayload(sessionID string) []byte {
	return []byte(`{"metadata":{"user_id":"user_xxx_account__session_` + sessionID + `"}}`)
}

// bindStrictSession runs one Pick to install a binding for sessionID and
// returns the auth that was bound. Tests then mutate that auth (set
// cooldown / disable / etc.) to exercise the bypass.
func bindStrictSession(t *testing.T, selector *SessionAffinitySelector, auths []*Auth, sessionID string) *Auth {
	t.Helper()
	opts := cliproxyexecutor.Options{OriginalRequest: strictBypassPayload(sessionID)}
	got, err := selector.Pick(context.Background(), "claude", "claude-3", opts, auths)
	if err != nil {
		t.Fatalf("initial Pick to seed binding: %v", err)
	}
	if got == nil {
		t.Fatal("initial Pick returned nil auth")
	}
	return got
}

// TestSessionAffinitySelector_StrictBypassesCooldownForBoundAuth is the
// central regression test for the option-C fix. After a single transient
// upstream 5xx, the bound auth's model state is marked Unavailable with
// a 1-minute NextRetryAfter. Without the bypass, every subsequent
// request from this session would strict-reject with 500 for the next
// minute. With the bypass, strict honors the binding and lets the
// conductor retry upstream.
func TestSessionAffinitySelector_StrictBypassesCooldownForBoundAuth(t *testing.T) {
	t.Parallel()

	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
		Strict:   true,
	})
	defer selector.Stop()

	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}, {ID: "auth-c"}}
	bound := bindStrictSession(t, selector, auths, "bypass-cooldown-uuid")

	// Mutate the bound auth in the pool to simulate the conductor having
	// just marked it Unavailable due to a transient 5xx.
	for _, a := range auths {
		if a.ID == bound.ID {
			a.ModelStates = map[string]*ModelState{
				"claude-3": {
					Status:         StatusError,
					Unavailable:    true,
					NextRetryAfter: time.Now().Add(1 * time.Minute),
				},
			}
		}
	}

	opts := cliproxyexecutor.Options{OriginalRequest: strictBypassPayload("bypass-cooldown-uuid")}
	got, err := selector.Pick(context.Background(), "claude", "claude-3", opts, auths)
	if err != nil {
		t.Fatalf("strict Pick on cooled-but-bound auth: error = %v, want bypass success", err)
	}
	if got == nil {
		t.Fatal("strict Pick returned nil auth instead of the bound one")
	}
	if got.ID != bound.ID {
		t.Fatalf("strict Pick returned %q, want bound auth %q (bypass should honor the binding)", got.ID, bound.ID)
	}
}

// TestSessionAffinitySelector_StrictBypassesEvenWhenAllAuthsCooled
// verifies that the bypass works on the most pessimistic input: every
// auth in the pool is cooled, which would normally make
// getAvailableAuths short-circuit with a model_cooldown error before we
// ever reached the cache lookup. Strict-mode bypass must still resolve
// the binding so the conductor can attempt the bound auth.
func TestSessionAffinitySelector_StrictBypassesEvenWhenAllAuthsCooled(t *testing.T) {
	t.Parallel()

	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
		Strict:   true,
	})
	defer selector.Stop()

	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	bound := bindStrictSession(t, selector, auths, "all-cooled-uuid")

	now := time.Now()
	for _, a := range auths {
		a.ModelStates = map[string]*ModelState{
			"claude-3": {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: now.Add(5 * time.Minute),
			},
		}
	}

	opts := cliproxyexecutor.Options{OriginalRequest: strictBypassPayload("all-cooled-uuid")}
	got, err := selector.Pick(context.Background(), "claude", "claude-3", opts, auths)
	if err != nil {
		t.Fatalf("strict Pick when all auths cooled: error = %v, want bypass success", err)
	}
	if got == nil || got.ID != bound.ID {
		t.Fatalf("strict Pick returned %v, want bound auth %q", got, bound.ID)
	}
}

// TestSessionAffinitySelector_StrictRefusesWhenBoundAuthDisabled is the
// guard against an over-broad bypass: an administratively disabled auth
// must NOT be returned just because there's a cached binding to it.
// strict-refuse remains the correct behavior for permanent failures.
func TestSessionAffinitySelector_StrictRefusesWhenBoundAuthDisabled(t *testing.T) {
	t.Parallel()

	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
		Strict:   true,
	})
	defer selector.Stop()

	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	bound := bindStrictSession(t, selector, auths, "disabled-bound-uuid")

	for _, a := range auths {
		if a.ID == bound.ID {
			a.Disabled = true
		}
	}

	opts := cliproxyexecutor.Options{OriginalRequest: strictBypassPayload("disabled-bound-uuid")}
	_, err := selector.Pick(context.Background(), "claude", "claude-3", opts, auths)
	if err == nil {
		t.Fatal("strict Pick on Disabled bound auth: expected refuse, got success")
	}
	var se *Error
	if !errors.As(err, &se) || se.Code != "auth_bound_unavailable" {
		t.Fatalf("strict Pick error = %v (%T), want auth_bound_unavailable", err, err)
	}
}

// TestSessionAffinitySelector_StrictRefusesWhenBoundModelDisabled
// verifies per-model administrative disable is also respected. If the
// model was specifically disabled on this auth (rather than just
// cooled), the bypass must not silently re-attempt it.
func TestSessionAffinitySelector_StrictRefusesWhenBoundModelDisabled(t *testing.T) {
	t.Parallel()

	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
		Strict:   true,
	})
	defer selector.Stop()

	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	bound := bindStrictSession(t, selector, auths, "model-disabled-uuid")

	for _, a := range auths {
		if a.ID == bound.ID {
			a.ModelStates = map[string]*ModelState{
				"claude-3": {Status: StatusDisabled},
			}
		}
	}

	opts := cliproxyexecutor.Options{OriginalRequest: strictBypassPayload("model-disabled-uuid")}
	_, err := selector.Pick(context.Background(), "claude", "claude-3", opts, auths)
	if err == nil {
		t.Fatal("strict Pick on model-Disabled bound auth: expected refuse, got success")
	}
	var se *Error
	if !errors.As(err, &se) || se.Code != "auth_bound_unavailable" {
		t.Fatalf("strict Pick error = %v (%T), want auth_bound_unavailable", err, err)
	}
}

// TestSessionAffinitySelector_NonStrictUnchangedAfterBypass guards the
// non-strict path, which option C did NOT change. A cooled bound auth
// must still trigger fallback selection, not be returned as-is.
func TestSessionAffinitySelector_NonStrictUnchangedAfterBypass(t *testing.T) {
	t.Parallel()

	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
		Strict:   false, // non-strict
	})
	defer selector.Stop()

	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}, {ID: "auth-c"}}
	bound := bindStrictSession(t, selector, auths, "non-strict-bypass-uuid")

	for _, a := range auths {
		if a.ID == bound.ID {
			a.ModelStates = map[string]*ModelState{
				"claude-3": {
					Status:         StatusError,
					Unavailable:    true,
					NextRetryAfter: time.Now().Add(1 * time.Minute),
				},
			}
		}
	}

	opts := cliproxyexecutor.Options{OriginalRequest: strictBypassPayload("non-strict-bypass-uuid")}
	got, err := selector.Pick(context.Background(), "claude", "claude-3", opts, auths)
	if err != nil {
		t.Fatalf("non-strict Pick on cooled bound auth: error = %v, want fallback success", err)
	}
	if got == nil {
		t.Fatal("non-strict Pick returned nil auth")
	}
	if got.ID == bound.ID {
		t.Fatalf("non-strict Pick returned the cooled bound auth %q; option C must not regress this path", got.ID)
	}
}

// TestFindCacheHitAuthForStrictBypass_TableDriven exercises the helper
// directly so each branch is covered without needing the full selector
// plumbing.
func TestFindCacheHitAuthForStrictBypass_TableDriven(t *testing.T) {
	t.Parallel()

	makeAuth := func(id string, mutate func(*Auth)) *Auth {
		a := &Auth{ID: id, Status: StatusActive}
		if mutate != nil {
			mutate(a)
		}
		return a
	}

	cases := []struct {
		name      string
		id        string
		model     string
		auths     []*Auth
		wantFound bool
	}{
		{
			name:      "happy path",
			id:        "a",
			model:     "m",
			auths:     []*Auth{makeAuth("a", nil)},
			wantFound: true,
		},
		{
			name:  "cooled auth still returned (the central bypass guarantee)",
			id:    "a",
			model: "m",
			auths: []*Auth{makeAuth("a", func(a *Auth) {
				a.ModelStates = map[string]*ModelState{
					"m": {Status: StatusError, Unavailable: true, NextRetryAfter: time.Now().Add(time.Minute)},
				}
			})},
			wantFound: true,
		},
		{
			name:      "auth not in pool",
			id:        "missing",
			model:     "m",
			auths:     []*Auth{makeAuth("a", nil)},
			wantFound: false,
		},
		{
			name:  "auth.Disabled is hard-refuse",
			id:    "a",
			model: "m",
			auths: []*Auth{makeAuth("a", func(a *Auth) {
				a.Disabled = true
			})},
			wantFound: false,
		},
		{
			name:  "auth.Status=StatusDisabled is hard-refuse",
			id:    "a",
			model: "m",
			auths: []*Auth{makeAuth("a", func(a *Auth) {
				a.Status = StatusDisabled
			})},
			wantFound: false,
		},
		{
			name:  "per-model StatusDisabled is hard-refuse",
			id:    "a",
			model: "m",
			auths: []*Auth{makeAuth("a", func(a *Auth) {
				a.ModelStates = map[string]*ModelState{"m": {Status: StatusDisabled}}
			})},
			wantFound: false,
		},
		{
			name:  "per-model Unavailable but Status=StatusActive is returned",
			id:    "a",
			model: "m",
			auths: []*Auth{makeAuth("a", func(a *Auth) {
				a.ModelStates = map[string]*ModelState{
					"m": {Status: StatusActive, Unavailable: true, NextRetryAfter: time.Now().Add(time.Hour)},
				}
			})},
			wantFound: true,
		},
		{
			name:      "empty id never matches",
			id:        "",
			model:     "m",
			auths:     []*Auth{makeAuth("a", nil)},
			wantFound: false,
		},
		{
			name:      "nil auths in pool are skipped",
			id:        "a",
			model:     "m",
			auths:     []*Auth{nil, makeAuth("a", nil), nil},
			wantFound: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := findCacheHitAuthForStrictBypass(tc.auths, tc.id, tc.model)
			if tc.wantFound && got == nil {
				t.Fatalf("expected auth %q to be returned, got nil", tc.id)
			}
			if !tc.wantFound && got != nil {
				t.Fatalf("expected refusal, got auth %q", got.ID)
			}
		})
	}
}
