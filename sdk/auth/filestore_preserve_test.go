package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// TestFileTokenStore_Save_PreservesUserManagedFieldsOnReLogin verifies that a
// re-login (which produces a fresh Auth with empty metadata) does not wipe the
// user-managed top-level fields (proxy_url, prefix, headers, priority, note,
// websockets) that were previously written to the auth file via the
// management API.
func TestFileTokenStore_Save_PreservesUserManagedFieldsOnReLogin(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "codex-user@example.com.json")

	// Seed file as if previously saved + then patched by management API with
	// proxy_url, prefix, headers, priority, note, websockets.
	seed := map[string]any{
		"type":          "codex",
		"email":         "user@example.com",
		"access_token":  "old-access",
		"refresh_token": "old-refresh",
		"proxy_url":     "socks5://127.0.0.1:10969",
		"prefix":        "my-prefix",
		"headers":       map[string]any{"X-Foo": "bar"},
		"priority":      float64(10),
		"note":          "shared exit IP, do not break",
		"websockets":    true,
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("seed auth file: %v", err)
	}

	// Simulate re-login: a fresh Auth with new tokens, empty metadata.
	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	storage := &testTokenStorage{}

	auth := &cliproxyauth.Auth{
		ID:       "codex-user@example.com.json",
		Provider: "codex",
		FileName: "codex-user@example.com.json",
		Storage:  storage,
		Metadata: map[string]any{"type": "codex", "email": "user@example.com"},
	}

	if _, err := store.Save(ctx, auth); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(saved, &out); err != nil {
		t.Fatalf("unmarshal saved file: %v", err)
	}

	if got, _ := out["proxy_url"].(string); got != "socks5://127.0.0.1:10969" {
		t.Fatalf("proxy_url = %q, want %q (raw=%s)", got, "socks5://127.0.0.1:10969", string(saved))
	}
	if got, _ := out["prefix"].(string); got != "my-prefix" {
		t.Fatalf("prefix = %q, want %q", got, "my-prefix")
	}
	if got, _ := out["note"].(string); got != "shared exit IP, do not break" {
		t.Fatalf("note = %q, want %q", got, "shared exit IP, do not break")
	}
	if got, _ := out["priority"].(float64); got != 10 {
		t.Fatalf("priority = %v, want 10", out["priority"])
	}
	if got, _ := out["websockets"].(bool); !got {
		t.Fatalf("websockets = %v, want true", out["websockets"])
	}
	headers, _ := out["headers"].(map[string]any)
	if headers == nil || headers["X-Foo"] != "bar" {
		t.Fatalf("headers = %v, want X-Foo=bar", out["headers"])
	}

	// In-memory Auth should have ProxyURL / Prefix populated from the
	// preserved file so callers see the effective values without waiting for
	// a file-watcher reload.
	if auth.ProxyURL != "socks5://127.0.0.1:10969" {
		t.Fatalf("auth.ProxyURL = %q, want preserved value", auth.ProxyURL)
	}
	if auth.Prefix != "my-prefix" {
		t.Fatalf("auth.Prefix = %q, want preserved value", auth.Prefix)
	}
}

// TestFileTokenStore_Save_InMemoryMetadataWinsOverFile verifies that values
// the caller has explicitly set on auth.Metadata override what is on disk —
// the management API editing a field must always reach the file even if
// the file's previous value differs.
func TestFileTokenStore_Save_InMemoryMetadataWinsOverFile(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "auth.json")

	seed := map[string]any{
		"type":      "codex",
		"proxy_url": "socks5://OLD:10000",
	}
	raw, _ := json.Marshal(seed)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	storage := &testTokenStorage{}

	auth := &cliproxyauth.Auth{
		ID:       "auth.json",
		Provider: "codex",
		FileName: "auth.json",
		Storage:  storage,
		Metadata: map[string]any{"proxy_url": "socks5://NEW:20000"},
	}

	if _, err := store.Save(ctx, auth); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	saved, _ := os.ReadFile(path)
	var out map[string]any
	if err := json.Unmarshal(saved, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, _ := out["proxy_url"].(string); got != "socks5://NEW:20000" {
		t.Fatalf("proxy_url = %q, want NEW (in-memory must win)", got)
	}
}

// TestFileTokenStore_Save_NoExistingFileNoPreservation verifies the fresh-
// install path: when no file exists yet, Save must not synthesize any
// preserved fields out of thin air.
func TestFileTokenStore_Save_NoExistingFileNoPreservation(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()

	store := NewFileTokenStore()
	store.SetBaseDir(baseDir)
	storage := &testTokenStorage{}

	auth := &cliproxyauth.Auth{
		ID:       "fresh.json",
		Provider: "codex",
		FileName: "fresh.json",
		Storage:  storage,
		Metadata: map[string]any{"type": "codex"},
	}

	if _, err := store.Save(ctx, auth); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	saved, err := os.ReadFile(filepath.Join(baseDir, "fresh.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(saved, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range preservedAuthFileFields {
		if _, ok := out[key]; ok {
			t.Fatalf("unexpected key %q in saved fresh file: %v", key, out[key])
		}
	}
}
