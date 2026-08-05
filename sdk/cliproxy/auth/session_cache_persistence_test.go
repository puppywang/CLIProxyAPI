package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionCachePersistence_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	// First instance: bind a session, force a flush, stop.
	c1 := NewSessionCacheWithPersistence(time.Hour, path)
	c1.Set("conv-A", "auth-x")
	c1.Set("conv-B", "auth-y")
	c1.persistNow()
	c1.Stop()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected cache file at %s, got %v", path, err)
	}

	// Second instance: should load both bindings.
	c2 := NewSessionCacheWithPersistence(time.Hour, path)
	defer c2.Stop()

	if id, ok := c2.Get("conv-A"); !ok || id != "auth-x" {
		t.Errorf("conv-A: got (%q,%v), want (auth-x,true)", id, ok)
	}
	if id, ok := c2.Get("conv-B"); !ok || id != "auth-y" {
		t.Errorf("conv-B: got (%q,%v), want (auth-y,true)", id, ok)
	}
}

func TestSessionCachePersistence_ExpiredEntriesDroppedOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	c1 := NewSessionCacheWithPersistence(time.Hour, path)
	c1.Set("fresh", "auth-fresh")
	// Manually inject an expired entry into the in-memory map and flush.
	c1.mu.Lock()
	c1.entries["stale"] = sessionEntry{
		authID:    "auth-stale",
		expiresAt: time.Now().Add(-time.Minute),
	}
	c1.mu.Unlock()
	c1.persistNow()
	c1.Stop()

	c2 := NewSessionCacheWithPersistence(time.Hour, path)
	defer c2.Stop()

	if _, ok := c2.Get("stale"); ok {
		t.Error("expired entry should not be loaded")
	}
	if id, ok := c2.Get("fresh"); !ok || id != "auth-fresh" {
		t.Errorf("fresh entry lost on load: got (%q,%v)", id, ok)
	}
}

func TestSessionCachePersistence_DirtyFlushPicksUpSetAndInvalidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	c := NewSessionCacheWithPersistence(time.Hour, path)
	defer c.Stop()

	c.Set("conv-A", "auth-x")
	if !c.dirty.Load() {
		t.Fatal("Set should set dirty flag")
	}
	c.persistNow()
	c.dirty.Store(false)

	c.Invalidate("conv-A")
	if !c.dirty.Load() {
		t.Fatal("Invalidate should set dirty flag")
	}
	c.persistNow()

	c2 := NewSessionCacheWithPersistence(time.Hour, path)
	defer c2.Stop()
	if _, ok := c2.Get("conv-A"); ok {
		t.Error("invalidated entry should not be loaded")
	}
}

func TestSessionCachePersistence_NoPathBehavesLikeMemoryOnly(t *testing.T) {
	c := NewSessionCacheWithPersistence(time.Hour, "")
	defer c.Stop()
	c.Set("conv-X", "auth-z")
	if id, ok := c.Get("conv-X"); !ok || id != "auth-z" {
		t.Errorf("memory-only cache broke: (%q,%v)", id, ok)
	}
	// No on-disk artifacts expected.
}

func TestSessionCachePersistence_AtomicWriteViaTmpRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	c := NewSessionCacheWithPersistence(time.Hour, path)
	c.Set("conv", "auth")
	c.persistNow()
	c.Stop()

	// The .tmp file should NOT remain after a successful rename.
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error(".tmp left behind after successful persist")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("final file missing: %v", err)
	}
}

// TestSessionCache_InvalidateWindowForAuth verifies the per-conversation
// release used by the bindings popup: dropping one uuid removes BOTH the
// codex-thread and codex-window cache rows for that conversation, leaves
// other conversations on the same account alone, and never touches a
// uuid bound to a different account (stale-popup-data safety).
func TestSessionCache_InvalidateWindowForAuth(t *testing.T) {
	c := NewSessionCache(time.Hour)
	defer c.Stop()

	const authA = "auth-aaa"
	const authB = "auth-bbb"
	// Conversation 1 on auth A: the usual thread+window key pair.
	c.Set("mixed::codex-thread:conv-1", authA)
	c.Set("mixed::codex-window:conv-1", authA)
	// Conversation 2 on auth A must survive the single-release of conv-1.
	c.Set("mixed::codex-thread:conv-2", authA)
	// Conversation 3 is bound to a DIFFERENT account.
	c.Set("mixed::codex-thread:conv-3", authB)
	// A malformed/fallback key on auth A must not be matched by accident.
	c.Set("msg:not-a-uuid", authA)

	if n := c.InvalidateWindowForAuth(authA, "conv-1"); n != 2 {
		t.Fatalf("expected 2 rows removed for conv-1 on auth A, got %d", n)
	}
	if _, ok := c.Get("mixed::codex-thread:conv-1"); ok {
		t.Error("conv-1 thread row should be gone")
	}
	if _, ok := c.Get("mixed::codex-window:conv-1"); ok {
		t.Error("conv-1 window row should be gone")
	}
	// Unrelated conversations stay bound.
	if id, ok := c.Get("mixed::codex-thread:conv-2"); !ok || id != authA {
		t.Errorf("conv-2 should stay bound to auth A, got (%q,%v)", id, ok)
	}
	if id, ok := c.Get("mixed::codex-thread:conv-3"); !ok || id != authB {
		t.Errorf("conv-3 should stay bound to auth B, got (%q,%v)", id, ok)
	}
	if id, ok := c.Get("msg:not-a-uuid"); !ok || id != authA {
		t.Errorf("msg fallback key should stay bound, got (%q,%v)", id, ok)
	}

	// Wrong-account guard: releasing conv-3 via auth A removes nothing.
	if n := c.InvalidateWindowForAuth(authA, "conv-3"); n != 0 {
		t.Errorf("expected 0 rows removed for foreign uuid, got %d", n)
	}
	if id, ok := c.Get("mixed::codex-thread:conv-3"); !ok || id != authB {
		t.Errorf("foreign conversation must not be released, got (%q,%v)", id, ok)
	}

	// Idempotent: releasing an already-released uuid reports 0.
	if n := c.InvalidateWindowForAuth(authA, "conv-1"); n != 0 {
		t.Errorf("second release of conv-1 should report 0, got %d", n)
	}

	// Empty / blank arguments are no-ops.
	if n := c.InvalidateWindowForAuth("", "conv-2"); n != 0 {
		t.Errorf("blank authID should release nothing, got %d", n)
	}
	if n := c.InvalidateWindowForAuth(authA, ""); n != 0 {
		t.Errorf("blank uuid should release nothing, got %d", n)
	}
}

// TestSessionCache_SplitCacheKeyID covers the kind:id parser used by
// the single-binding release path (and the reverse-index endpoint).
func TestSessionCache_SplitCacheKeyID(t *testing.T) {
	cases := []struct {
		key string
		id  string
		ok  bool
	}{
		{"mixed::codex-thread:1f2e3d4c", "1f2e3d4c", true},
		{"mixed::codex-window:1f2e3d4c", "1f2e3d4c", true},
		{"codex::codex-thread:abc", "abc", true},
		{"msg:hash-123", "hash-123", true},
		{"mixed::codex-thread:", "", false},
		{"no-colon-here", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		id, ok := splitCacheKeyID(tc.key)
		if id != tc.id || ok != tc.ok {
			t.Errorf("splitCacheKeyID(%q) = (%q,%v), want (%q,%v)", tc.key, id, ok, tc.id, tc.ok)
		}
	}
}
