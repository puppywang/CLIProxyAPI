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

// sessionEntry stores auth binding with expiration. The `closed` flag is
// set when the selector detects a Codex /new fork — the new thread carries
// a `forked_from_thread_id` field whose value identifies the OLD thread,
// which the operator UI then treats as historical rather than active. The
// flag is observe-only today: marking does NOT affect Pick or LeastBound
// behaviour. Behaviour changes (skip closed in distribution, 429 on cache
// hit) are gated to a follow-up release so the detection accuracy can be
// validated against real production traffic first.
type sessionEntry struct {
	authID    string
	expiresAt time.Time
	closed    bool
	closedAt  time.Time
	forkedTo  string // thread_id of the conversation that replaced this one
}

// persistedEntry is the on-disk JSON representation of a sessionEntry. Kept
// separate from sessionEntry so the in-memory type can stay unexported. The
// closed-marker fields use omitempty so caches written by older binaries
// load cleanly into the new struct (their entries simply have closed=false).
type persistedEntry struct {
	AuthID    string    `json:"auth_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Closed    bool      `json:"closed,omitempty"`
	ClosedAt  time.Time `json:"closed_at,omitempty"`
	ForkedTo  string    `json:"forked_to,omitempty"`
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

// BindingSnapshotEntry describes a single live cache binding for
// operator-facing views. SessionKey is the full cache key
// (`mixed::codex-thread:<uuid>` or `mixed::codex-window:<uuid>`).
// Callers that want to dedupe thread+window pairs of the same UUID
// strip the prefix and group by UUID themselves — keeping that policy
// out of the cache means future cache key conventions (Claude sessions,
// non-codex providers) work without changes here.
//
// Closed/ClosedAt/ForkedTo carry the fork-detection marker. When a
// Codex /new turn arrives carrying forked_from_thread_id=<prior tid>,
// the selector marks the prior thread's binding closed and remembers
// which thread replaced it. The marker is observe-only today — the
// LeastBoundSelector and the strict-bypass cache hit both still treat
// closed entries the same as active ones. The reverse-index endpoint
// renders the difference so operators can see how much of an
// account's "load" is actually idle history.
type BindingSnapshotEntry struct {
	SessionKey string
	AuthID     string
	ExpiresAt  time.Time
	Closed     bool
	ClosedAt   time.Time
	ForkedTo   string
}

// SnapshotByAuth returns the FULL set of live bindings grouped by
// auth_id. Expired entries are excluded. The returned map and its
// slices are freshly allocated and safe to mutate. Used by the
// /v0/management/session-affinity/bindings endpoint to render the
// reverse-index "which sessions does this account hold" view.
func (c *SessionCache) SnapshotByAuth() map[string][]BindingSnapshotEntry {
	if c == nil {
		return nil
	}
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string][]BindingSnapshotEntry, len(c.entries))
	for key, e := range c.entries {
		if now.After(e.expiresAt) {
			continue
		}
		if e.authID == "" {
			continue
		}
		out[e.authID] = append(out[e.authID], BindingSnapshotEntry{
			SessionKey: key,
			AuthID:     e.authID,
			ExpiresAt:  e.expiresAt,
			Closed:     e.closed,
			ClosedAt:   e.closedAt,
			ForkedTo:   e.forkedTo,
		})
	}
	return out
}

// MarkClosed flags the given cache key as forked-from. sessionKey is the
// full cache key (e.g. "mixed::codex-thread:<old_tid>"). replacedBy is
// the thread_id of the new conversation that replaced this one — stored
// so the operator UI can show "this thread was forked to UUID X".
// Idempotent: closing an already-closed key is a no-op. Missing or
// expired keys are silently ignored so a stale fork signal cannot
// resurrect garbage entries.
func (c *SessionCache) MarkClosed(sessionKey, replacedBy string) {
	if c == nil || sessionKey == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[sessionKey]
	if !ok {
		return
	}
	if time.Now().After(e.expiresAt) {
		return
	}
	if e.closed {
		// Idempotent — but refresh forkedTo if a newer fork target
		// is provided (e.g., user did /new twice and we get a later
		// "this used to be X" signal pointing at a different
		// replacement). The closedAt timestamp stays at the first
		// close to preserve the original observation.
		if replacedBy != "" && e.forkedTo == "" {
			e.forkedTo = replacedBy
			c.entries[sessionKey] = e
			c.dirty.Store(true)
		}
		return
	}
	e.closed = true
	e.closedAt = time.Now()
	e.forkedTo = replacedBy
	c.entries[sessionKey] = e
	c.dirty.Store(true)
}

// BindingsByAuth returns a snapshot of auth_id → live binding count.
// Expired entries are excluded so the counter reflects only currently
// honoured bindings. The returned map is freshly allocated and safe for
// the caller to mutate. Used by selectors that distribute new bindings
// inversely to existing load (LeastBoundSelector).
func (c *SessionCache) BindingsByAuth() map[string]int {
	if c == nil {
		return nil
	}
	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]int, len(c.entries))
	for _, e := range c.entries {
		if now.After(e.expiresAt) {
			continue
		}
		if e.authID == "" {
			continue
		}
		out[e.authID]++
	}
	return out
}

// WithSelectionLock executes fn while holding the cache's write lock.
// The fn body runs atomically with respect to all other cache writers,
// so a selector that wants to "count bindings → pick winner → write the
// new binding" inside a single critical section can do so by calling
// the cache's setLocked / bindingsByAuthLocked helpers via the closure.
// This is the lock-correctness primitive behind LeastBoundSelector's
// atomic-claim contract.
func (c *SessionCache) WithSelectionLock(fn func(bindings map[string]int, setLocked func(sessionID, authID string))) {
	if c == nil || fn == nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	bindings := make(map[string]int, len(c.entries))
	for _, e := range c.entries {
		if now.After(e.expiresAt) {
			continue
		}
		if e.authID == "" {
			continue
		}
		bindings[e.authID]++
	}
	setLocked := func(sessionID, authID string) {
		if sessionID == "" || authID == "" {
			return
		}
		c.entries[sessionID] = sessionEntry{
			authID:    authID,
			expiresAt: time.Now().Add(c.ttl),
		}
		c.dirty.Store(true)
	}
	fn(bindings, setLocked)
}

// PeekLocked returns the bound auth for sessionID without refreshing TTL.
// Must be called with c.mu held (e.g. inside WithSelectionLock). Returns
// "" / false when the session is missing or expired.
func (c *SessionCache) peekLocked(sessionID string) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	e, ok := c.entries[sessionID]
	if !ok {
		return "", false
	}
	if time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.authID, true
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
			closed:    pe.Closed,
			closedAt:  pe.ClosedAt,
			forkedTo:  pe.ForkedTo,
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
			Closed:    e.closed,
			ClosedAt:  e.closedAt,
			ForkedTo:  e.forkedTo,
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
