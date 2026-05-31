package auth

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// sessionEntry stores auth binding with expiration.
type sessionEntry struct {
	authID    string
	expiresAt time.Time
}

// persistedEntry is the on-disk JSON representation of a sessionEntry. Kept
// separate from sessionEntry so the in-memory type can stay unexported.
type persistedEntry struct {
	AuthID    string    `json:"auth_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// persistedSnapshot is the top-level JSON object written to disk.
type persistedSnapshot struct {
	Version int                       `json:"version"`
	Entries map[string]persistedEntry `json:"entries"`
}

// persistFlushInterval is how often the persistence goroutine checks the
// dirty flag and flushes pending changes to disk.
const persistFlushInterval = 30 * time.Second

// SessionCache provides TTL-based session to auth mapping with automatic cleanup.
//
// When constructed with NewSessionCacheWithPersistence, the cache also loads
// existing bindings from disk on startup and periodically writes any changes
// back. This preserves session-affinity across CPA restarts — without it, a
// restart causes all in-flight client conversations to be rebound to fresh
// accounts on their next request, which is exactly the cross-account scenario
// that triggers upstream risk-control on OpenAI.
type SessionCache struct {
	mu      sync.RWMutex
	entries map[string]sessionEntry
	ttl     time.Duration
	stopCh  chan struct{}

	persistPath string
	dirty       atomic.Bool
}

// NewSessionCache creates an in-memory cache with the specified TTL.
// A background goroutine periodically cleans expired entries.
func NewSessionCache(ttl time.Duration) *SessionCache {
	return NewSessionCacheWithPersistence(ttl, "")
}

// NewSessionCacheWithPersistence creates a cache that also persists its
// contents to the given file. Pass an empty path to disable persistence
// (same behaviour as NewSessionCache). Existing entries are loaded
// synchronously before this function returns; subsequent changes are
// flushed asynchronously by a background goroutine.
func NewSessionCacheWithPersistence(ttl time.Duration, path string) *SessionCache {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	c := &SessionCache{
		entries:     make(map[string]sessionEntry),
		ttl:         ttl,
		stopCh:      make(chan struct{}),
		persistPath: path,
	}
	if path != "" {
		c.load()
	}
	go c.cleanupLoop()
	if path != "" {
		go c.persistLoop()
	}
	return c
}

// Get retrieves the auth ID bound to a session, if still valid.
// Does NOT refresh the TTL on access.
func (c *SessionCache) Get(sessionID string) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	c.mu.RLock()
	entry, ok := c.entries[sessionID]
	c.mu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.entries, sessionID)
		c.mu.Unlock()
		return "", false
	}
	return entry.authID, true
}

// GetAndRefresh retrieves the auth ID bound to a session and refreshes TTL on hit.
// This extends the binding lifetime for active sessions.
func (c *SessionCache) GetAndRefresh(sessionID string) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	now := time.Now()
	c.mu.Lock()
	entry, ok := c.entries[sessionID]
	if !ok {
		c.mu.Unlock()
		return "", false
	}
	if now.After(entry.expiresAt) {
		delete(c.entries, sessionID)
		c.mu.Unlock()
		return "", false
	}
	// Refresh TTL on successful access
	entry.expiresAt = now.Add(c.ttl)
	c.entries[sessionID] = entry
	c.mu.Unlock()
	c.dirty.Store(true)
	return entry.authID, true
}

// Set binds a session to an auth ID with TTL refresh.
func (c *SessionCache) Set(sessionID, authID string) {
	if sessionID == "" || authID == "" {
		return
	}
	c.mu.Lock()
	c.entries[sessionID] = sessionEntry{
		authID:    authID,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
	c.dirty.Store(true)
}

// Invalidate removes a specific session binding.
func (c *SessionCache) Invalidate(sessionID string) {
	if sessionID == "" {
		return
	}
	c.mu.Lock()
	if _, ok := c.entries[sessionID]; ok {
		delete(c.entries, sessionID)
		c.dirty.Store(true)
	}
	c.mu.Unlock()
}

// InvalidateAuth removes all sessions bound to a specific auth ID.
// Used when an auth becomes unavailable.
func (c *SessionCache) InvalidateAuth(authID string) {
	if authID == "" {
		return
	}
	changed := false
	c.mu.Lock()
	for sid, entry := range c.entries {
		if entry.authID == authID {
			delete(c.entries, sid)
			changed = true
		}
	}
	c.mu.Unlock()
	if changed {
		c.dirty.Store(true)
	}
}

// Stop terminates the background goroutines. If persistence is enabled, a
// final flush is performed so that pending writes survive a graceful
// shutdown.
func (c *SessionCache) Stop() {
	select {
	case <-c.stopCh:
		return
	default:
		close(c.stopCh)
	}
	if c.persistPath != "" {
		c.persistNow()
	}
}

func (c *SessionCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

func (c *SessionCache) cleanup() {
	now := time.Now()
	removed := 0
	c.mu.Lock()
	for sid, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, sid)
			removed++
		}
	}
	c.mu.Unlock()
	if removed > 0 {
		c.dirty.Store(true)
	}
}

// load reads the persisted snapshot from disk (best-effort). Entries whose
// TTL has already expired are dropped during load.
func (c *SessionCache) load() {
	if c.persistPath == "" {
		return
	}
	data, err := os.ReadFile(c.persistPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.WithError(err).WithField("path", c.persistPath).
				Warn("session-affinity cache: read failed; starting empty")
		}
		return
	}
	var snap persistedSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		log.WithError(err).WithField("path", c.persistPath).
			Warn("session-affinity cache: parse failed; starting empty")
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	loaded := 0
	for sid, pe := range snap.Entries {
		if sid == "" || pe.AuthID == "" {
			continue
		}
		if now.After(pe.ExpiresAt) {
			continue
		}
		c.entries[sid] = sessionEntry{
			authID:    pe.AuthID,
			expiresAt: pe.ExpiresAt,
		}
		loaded++
	}
	log.WithField("path", c.persistPath).
		WithField("loaded", loaded).
		WithField("dropped_expired", len(snap.Entries)-loaded).
		Info("session-affinity cache: restored from disk")
}

// persistLoop flushes the cache to disk whenever the dirty flag has been
// raised since the last flush. Runs every persistFlushInterval. Exits when
// the cache is Stopped.
func (c *SessionCache) persistLoop() {
	ticker := time.NewTicker(persistFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if c.dirty.CompareAndSwap(true, false) {
				c.persistNow()
			}
		}
	}
}

// persistNow writes a fresh snapshot of the cache to disk via a tmp-file
// atomic rename. Failures are logged but never block callers.
func (c *SessionCache) persistNow() {
	if c.persistPath == "" {
		return
	}
	c.mu.RLock()
	snap := persistedSnapshot{
		Version: 1,
		Entries: make(map[string]persistedEntry, len(c.entries)),
	}
	for sid, e := range c.entries {
		snap.Entries[sid] = persistedEntry{
			AuthID:    e.authID,
			ExpiresAt: e.expiresAt,
		}
	}
	c.mu.RUnlock()

	payload, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		log.WithError(err).Warn("session-affinity cache: marshal failed")
		return
	}
	if dir := filepath.Dir(c.persistPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.WithError(err).WithField("dir", dir).
				Warn("session-affinity cache: mkdir failed")
			return
		}
	}
	tmp := c.persistPath + ".tmp"
	if err := os.WriteFile(tmp, append(payload, '\n'), 0o600); err != nil {
		log.WithError(err).WithField("path", tmp).
			Warn("session-affinity cache: tmp write failed")
		return
	}
	if err := os.Rename(tmp, c.persistPath); err != nil {
		log.WithError(err).WithField("path", c.persistPath).
			Warn("session-affinity cache: rename failed")
		return
	}
}
