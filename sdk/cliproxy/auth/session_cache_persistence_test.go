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
