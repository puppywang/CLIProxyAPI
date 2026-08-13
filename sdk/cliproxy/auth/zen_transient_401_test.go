package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

// TestManager_MarkResult_ZenTransient401ShortCooldown verifies that a zen
// gateway invalid_bearer_credential 401 (the abuse-window shape that hit
// every key at once) gets a short cooldown + transient reason instead of the
// 30-minute "unauthorized" freeze, so the key pool recovers quickly.
func TestManager_MarkResult_ZenTransient401ShortCooldown(t *testing.T) {
	prev := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })

	m := NewManager(nil, nil, nil)
	auth := &Auth{ID: "zen-auth-1", Provider: "opencode"}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}
	model := "deepseek-v4-flash-free"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "opencode", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

	m.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "opencode",
		Model:    model,
		Success:  false,
		Error:    &Error{HTTPStatus: http.StatusUnauthorized, Message: "Upstream request failed: [invalid_bearer_credential] Missing or invalid bearer credential"},
	})

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("auth must be present")
	}
	state := updated.ModelStates[model]
	if state == nil {
		t.Fatal("model state must be present")
	}
	want := 1 * time.Minute
	got := time.Until(state.NextRetryAfter)
	if state.NextRetryAfter.IsZero() {
		t.Fatal("expected a cooldown, got zero NextRetryAfter")
	}
	if got > want+5*time.Second {
		t.Fatalf("zen transient 401 cooldown = %v, want ~%v (short cooldown)", got, want)
	}
	if got < 30*time.Second {
		t.Fatalf("zen transient 401 cooldown = %v, suspiciously short", got)
	}
	// transient reason should NOT be the permanent "unauthorized"
	if state.StatusMessage == "unauthorized" {
		t.Fatal("zen transient 401 must not use the permanent unauthorized reason")
	}
	if !stringsContains(state.StatusMessage, "invalid_bearer") && !stringsContains(state.StatusMessage, "unauthorized_transient") {
		t.Fatalf("status message = %q, want transient indicator", state.StatusMessage)
	}
	// registry suspension reason should be transient
	if suspended := reg.SuspendedModelsForClient(auth.ID); len(suspended) == 0 {
		t.Fatal("expected a registry suspension marker")
	}
}

// TestManager_MarkResult_Permanent401Keeps30Min verifies ordinary 401s (real
// credential death) still get the full 30-minute unauthorized cooldown.
func TestManager_MarkResult_Permanent401Keeps30Min(t *testing.T) {
	prev := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })

	m := NewManager(nil, nil, nil)
	auth := &Auth{ID: "perm-auth-1", Provider: "claude"}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}
	model := "m1"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

	m.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "claude",
		Model:    model,
		Success:  false,
		Error:    &Error{HTTPStatus: http.StatusUnauthorized, Message: "token expired"},
	})

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("auth must be present")
	}
	state := updated.ModelStates[model]
	if state == nil {
		t.Fatal("model state must be present")
	}
	if state.NextRetryAfter.IsZero() {
		t.Fatal("expected a cooldown")
	}
	got := time.Until(state.NextRetryAfter)
	if got < 20*time.Minute {
		t.Fatalf("ordinary 401 cooldown = %v, want ~30m", got)
	}
}

// TestIsZenTransientInvalidBearer covers the matcher directly.
func TestIsZenTransientInvalidBearer(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"Upstream request failed: [invalid_bearer_credential] Missing or invalid bearer credential", true},
		{"[invalid_bearer_credential] Missing or invalid bearer credential", true},
		{"invalid_bearer_credential", true},
		{"missing or invalid bearer credential", true},
		{"token expired", false},
		{"invalid api key", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isZenTransientInvalidBearer(tc.msg); got != tc.want {
			t.Errorf("isZenTransientInvalidBearer(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
