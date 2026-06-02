package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// RoundRobinSelector provides a simple provider scoped round-robin selection strategy.
type RoundRobinSelector struct {
	mu      sync.Mutex
	cursors map[string]int
	maxKeys int

	// persistPath, when non-empty, points to a JSON file where the cursor
	// state is mirrored. The cursor map is loaded from this file on startup
	// and a background goroutine writes any changes back. Without this, a
	// process restart resets every cursor to a random offset — combined with
	// the session-affinity cache persistence that DOES survive restarts, that
	// re-roll occasionally lands a freshly-bound session on the same auth as
	// an existing persisted binding, leaving N windows clustered on fewer
	// than N accounts. Persisting the cursor closes that gap.
	persistPath string
	dirty       atomic.Bool
	stopCh      chan struct{}
}

// FillFirstSelector selects the first available credential (deterministic ordering).
// This "burns" one account before moving to the next, which can help stagger
// rolling-window subscription caps (e.g. chat message limits).
type FillFirstSelector struct{}

type blockReason int

const (
	blockReasonNone blockReason = iota
	blockReasonCooldown
	blockReasonDisabled
	blockReasonOther
)

type modelCooldownError struct {
	model    string
	resetIn  time.Duration
	provider string
}

func newModelCooldownError(model, provider string, resetIn time.Duration) *modelCooldownError {
	if resetIn < 0 {
		resetIn = 0
	}
	return &modelCooldownError{
		model:    model,
		provider: provider,
		resetIn:  resetIn,
	}
}

func (e *modelCooldownError) Error() string {
	modelName := e.model
	if modelName == "" {
		modelName = "requested model"
	}
	message := fmt.Sprintf("All credentials for model %s are cooling down", modelName)
	if e.provider != "" {
		message = fmt.Sprintf("%s via provider %s", message, e.provider)
	}
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	displayDuration := e.resetIn
	if displayDuration > 0 && displayDuration < time.Second {
		displayDuration = time.Second
	} else {
		displayDuration = displayDuration.Round(time.Second)
	}
	errorBody := map[string]any{
		"code":          "model_cooldown",
		"message":       message,
		"model":         e.model,
		"reset_time":    displayDuration.String(),
		"reset_seconds": resetSeconds,
	}
	if e.provider != "" {
		errorBody["provider"] = e.provider
	}
	payload := map[string]any{"error": errorBody}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"error":{"code":"model_cooldown","message":"%s"}}`, message)
	}
	return string(data)
}

func (e *modelCooldownError) StatusCode() int {
	return http.StatusTooManyRequests
}

func (e *modelCooldownError) Headers() http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	headers.Set("Retry-After", strconv.Itoa(resetSeconds))
	return headers
}

func authPriority(auth *Auth) int {
	if auth == nil || auth.Attributes == nil {
		return 0
	}
	raw := strings.TrimSpace(auth.Attributes["priority"])
	if raw == "" {
		return 0
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return parsed
}

func canonicalModelKey(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}
	parsed := thinking.ParseSuffix(model)
	modelName := strings.TrimSpace(parsed.ModelName)
	if modelName == "" {
		return model
	}
	return modelName
}

func authWebsocketsEnabled(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed
			}
		}
	}
	if len(auth.Metadata) == 0 {
		return false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed
		}
	default:
	}
	return false
}

func preferCodexWebsocketAuths(ctx context.Context, provider string, available []*Auth) []*Auth {
	if len(available) == 0 {
		return available
	}
	if !cliproxyexecutor.DownstreamWebsocket(ctx) {
		return available
	}
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return available
	}

	wsEnabled := make([]*Auth, 0, len(available))
	for i := 0; i < len(available); i++ {
		candidate := available[i]
		if authWebsocketsEnabled(candidate) {
			wsEnabled = append(wsEnabled, candidate)
		}
	}
	if len(wsEnabled) > 0 {
		return wsEnabled
	}
	return available
}

func collectAvailableByPriority(auths []*Auth, model string, now time.Time) (available map[int][]*Auth, cooldownCount int, earliest time.Time) {
	available = make(map[int][]*Auth)
	for i := 0; i < len(auths); i++ {
		candidate := auths[i]
		blocked, reason, next := isAuthBlockedForModel(candidate, model, now)
		if !blocked {
			priority := authPriority(candidate)
			available[priority] = append(available[priority], candidate)
			continue
		}
		if reason == blockReasonCooldown {
			cooldownCount++
			if !next.IsZero() && (earliest.IsZero() || next.Before(earliest)) {
				earliest = next
			}
		}
	}
	return available, cooldownCount, earliest
}

func getAvailableAuths(auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth candidates"}
	}

	availableByPriority, cooldownCount, earliest := collectAvailableByPriority(auths, model, now)
	if len(availableByPriority) == 0 {
		if cooldownCount == len(auths) && !earliest.IsZero() {
			providerForError := provider
			if providerForError == "mixed" {
				providerForError = ""
			}
			resetIn := earliest.Sub(now)
			if resetIn < 0 {
				resetIn = 0
			}
			return nil, newModelCooldownError(model, providerForError, resetIn)
		}
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available"}
	}

	bestPriority := 0
	found := false
	for priority := range availableByPriority {
		if !found || priority > bestPriority {
			bestPriority = priority
			found = true
		}
	}

	available := availableByPriority[bestPriority]
	if len(available) > 1 {
		sort.Slice(available, func(i, j int) bool { return available[i].ID < available[j].ID })
	}
	return available, nil
}

// Pick selects the next available auth for the provider in a round-robin manner.
// For gemini-cli virtual auths (identified by the gemini_virtual_parent attribute),
// a two-level round-robin is used: first cycling across credential groups (parent
// accounts), then cycling within each group's project auths.
func (s *RoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getAvailableAuths(auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	key := provider + ":" + canonicalModelKey(model)
	s.mu.Lock()
	if s.cursors == nil {
		s.cursors = make(map[string]int)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}

	// Check if any available auth has gemini_virtual_parent attribute,
	// indicating gemini-cli virtual auths that should use credential-level polling.
	groups, parentOrder := groupByVirtualParent(available)
	if len(parentOrder) > 1 {
		// Two-level round-robin: first select a credential group, then pick within it.
		groupKey := key + "::group"
		s.ensureCursorKey(groupKey, limit)
		if _, exists := s.cursors[groupKey]; !exists {
			// Seed with a random initial offset so the starting credential is randomized.
			s.cursors[groupKey] = rand.IntN(len(parentOrder))
		}
		groupIndex := s.cursors[groupKey]
		if groupIndex >= 2_147_483_640 {
			groupIndex = 0
		}
		s.cursors[groupKey] = groupIndex + 1

		selectedParent := parentOrder[groupIndex%len(parentOrder)]
		group := groups[selectedParent]

		// Second level: round-robin within the selected credential group.
		innerKey := key + "::cred:" + selectedParent
		s.ensureCursorKey(innerKey, limit)
		innerIndex := s.cursors[innerKey]
		if innerIndex >= 2_147_483_640 {
			innerIndex = 0
		}
		s.cursors[innerKey] = innerIndex + 1
		s.mu.Unlock()
		s.dirty.Store(true)
		return group[innerIndex%len(group)], nil
	}

	// Flat round-robin for non-grouped auths.
	//
	// Seed a fresh cursor key with a random initial offset (mirroring the
	// virtual-parent branch above). Without this, every process restart wipes
	// the cursor map and every new cursor key starts at 0, which combined with
	// the deterministic alphabetical sort of `available` means the first
	// post-restart session for each provider/model always lands on the
	// alphabetically-first auth. With session-affinity persistence enabled,
	// that auth then keeps every following first-time session as well —
	// permanently overloading one credential across restarts.
	s.ensureCursorKey(key, limit)
	if _, exists := s.cursors[key]; !exists {
		s.cursors[key] = rand.IntN(len(available))
	}
	index := s.cursors[key]
	if index >= 2_147_483_640 {
		index = 0
	}
	s.cursors[key] = index + 1
	s.mu.Unlock()
	s.dirty.Store(true)
	return available[index%len(available)], nil
}

// rrCursorSnapshot is the on-disk JSON shape for persisted RR cursors.
type rrCursorSnapshot struct {
	Version int            `json:"version"`
	Cursors map[string]int `json:"cursors"`
}

const rrPersistFlushInterval = 30 * time.Second

// NewRoundRobinSelectorWithPersistence returns a RoundRobinSelector that
// mirrors its cursor state to the given file path. The cursor map is loaded
// on construction and a background goroutine flushes any changes every 30s.
// When path is empty the selector behaves identically to a zero-value
// RoundRobinSelector (in-memory only) — call Stop() when retiring the
// selector to flush a final snapshot.
func NewRoundRobinSelectorWithPersistence(path string) *RoundRobinSelector {
	s := &RoundRobinSelector{persistPath: strings.TrimSpace(path)}
	if s.persistPath == "" {
		return s
	}
	s.loadCursors()
	s.stopCh = make(chan struct{})
	go s.persistLoop()
	return s
}

// Stop terminates the background persistence goroutine and flushes a final
// snapshot to disk. Safe to call multiple times. A nil receiver or a
// selector constructed without persistence is a no-op.
func (s *RoundRobinSelector) Stop() {
	if s == nil || s.stopCh == nil {
		return
	}
	select {
	case <-s.stopCh:
		// already stopped
	default:
		close(s.stopCh)
	}
	s.persistNow()
}

func (s *RoundRobinSelector) loadCursors() {
	if s.persistPath == "" {
		return
	}
	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.WithError(err).WithField("path", s.persistPath).
				Warn("rr cursor: read failed; starting empty")
		}
		return
	}
	var snap rrCursorSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		log.WithError(err).WithField("path", s.persistPath).
			Warn("rr cursor: parse failed; starting empty")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cursors == nil {
		s.cursors = make(map[string]int, len(snap.Cursors))
	}
	for k, v := range snap.Cursors {
		if k == "" {
			continue
		}
		s.cursors[k] = v
	}
	log.WithField("path", s.persistPath).
		WithField("loaded", len(snap.Cursors)).
		Info("rr cursor: restored from disk")
}

func (s *RoundRobinSelector) persistLoop() {
	ticker := time.NewTicker(rrPersistFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			if s.dirty.CompareAndSwap(true, false) {
				s.persistNow()
			}
		}
	}
}

func (s *RoundRobinSelector) persistNow() {
	if s.persistPath == "" {
		return
	}
	s.mu.Lock()
	snap := rrCursorSnapshot{
		Version: 1,
		Cursors: make(map[string]int, len(s.cursors)),
	}
	for k, v := range s.cursors {
		snap.Cursors[k] = v
	}
	s.mu.Unlock()

	payload, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		log.WithError(err).Warn("rr cursor: marshal failed")
		return
	}
	if dir := filepath.Dir(s.persistPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.WithError(err).WithField("dir", dir).
				Warn("rr cursor: mkdir failed")
			return
		}
	}
	tmp := s.persistPath + ".tmp"
	if err := os.WriteFile(tmp, append(payload, '\n'), 0o600); err != nil {
		log.WithError(err).WithField("path", tmp).
			Warn("rr cursor: tmp write failed")
		return
	}
	if err := os.Rename(tmp, s.persistPath); err != nil {
		log.WithError(err).WithField("path", s.persistPath).
			Warn("rr cursor: rename failed")
		return
	}
}

// ensureCursorKey ensures the cursor map has capacity for the given key.
// Must be called with s.mu held.
func (s *RoundRobinSelector) ensureCursorKey(key string, limit int) {
	if _, ok := s.cursors[key]; !ok && len(s.cursors) >= limit {
		s.cursors = make(map[string]int)
	}
}

// groupByVirtualParent groups auths by their gemini_virtual_parent attribute.
// Returns a map of parentID -> auths and a sorted slice of parent IDs for stable iteration.
// Only auths with a non-empty gemini_virtual_parent are grouped; if any auth lacks
// this attribute, nil/nil is returned so the caller falls back to flat round-robin.
func groupByVirtualParent(auths []*Auth) (map[string][]*Auth, []string) {
	if len(auths) == 0 {
		return nil, nil
	}
	groups := make(map[string][]*Auth)
	for _, a := range auths {
		parent := ""
		if a.Attributes != nil {
			parent = strings.TrimSpace(a.Attributes["gemini_virtual_parent"])
		}
		if parent == "" {
			// Non-virtual auth present; fall back to flat round-robin.
			return nil, nil
		}
		groups[parent] = append(groups[parent], a)
	}
	// Collect parent IDs in sorted order for stable cursor indexing.
	parentOrder := make([]string, 0, len(groups))
	for p := range groups {
		parentOrder = append(parentOrder, p)
	}
	sort.Strings(parentOrder)
	return groups, parentOrder
}

// Pick selects the first available auth for the provider in a deterministic manner.
func (s *FillFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getAvailableAuths(auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	return available[0], nil
}

func isAuthBlockedForModel(auth *Auth, model string, now time.Time) (bool, blockReason, time.Time) {
	if auth == nil {
		return true, blockReasonOther, time.Time{}
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		return true, blockReasonDisabled, time.Time{}
	}
	if model != "" {
		if len(auth.ModelStates) > 0 {
			state, ok := auth.ModelStates[model]
			if (!ok || state == nil) && model != "" {
				baseModel := canonicalModelKey(model)
				if baseModel != "" && baseModel != model {
					state, ok = auth.ModelStates[baseModel]
				}
			}
			if ok && state != nil {
				if state.Status == StatusDisabled {
					return true, blockReasonDisabled, time.Time{}
				}
				if state.Unavailable {
					if state.NextRetryAfter.IsZero() {
						return false, blockReasonNone, time.Time{}
					}
					if state.NextRetryAfter.After(now) {
						next := state.NextRetryAfter
						if !state.Quota.NextRecoverAt.IsZero() && state.Quota.NextRecoverAt.After(now) {
							next = state.Quota.NextRecoverAt
						}
						if next.Before(now) {
							next = now
						}
						if state.Quota.Exceeded {
							return true, blockReasonCooldown, next
						}
						return true, blockReasonOther, next
					}
				}
				return false, blockReasonNone, time.Time{}
			}
		}
		return false, blockReasonNone, time.Time{}
	}
	if auth.Unavailable && auth.NextRetryAfter.After(now) {
		next := auth.NextRetryAfter
		if !auth.Quota.NextRecoverAt.IsZero() && auth.Quota.NextRecoverAt.After(now) {
			next = auth.Quota.NextRecoverAt
		}
		if next.Before(now) {
			next = now
		}
		if auth.Quota.Exceeded {
			return true, blockReasonCooldown, next
		}
		return true, blockReasonOther, next
	}
	return false, blockReasonNone, time.Time{}
}

// findCacheHitAuthForStrictBypass looks up a previously-bound auth by
// ID in the full pool, returning it even when isAuthBlockedForModel
// would currently filter it out (cooldown / 5xx / quota / 401 / etc.).
// The strict session-affinity selector uses this to honour the binding
// through a temporary upstream failure rather than amplifying a
// 1-second network hiccup into a 60-second strict-reject storm.
//
// What we still refuse to return:
//
//   - the auth is no longer in the pool (removed by admin / hot reload);
//   - the auth has been administratively disabled (auth.Disabled or
//     auth.Status == StatusDisabled);
//   - the per-model state is administratively disabled
//     (state.Status == StatusDisabled).
//
// Anything else — including a state currently in cooldown, marked
// Unavailable, or with a non-zero NextRetryAfter — is returned so the
// conductor can surface the real upstream response to the client. The
// conductor's MarkResult path will re-record any persistent failure on
// the next attempt, so we do not lose the eventual-consistency
// signalling that a truly broken auth should be avoided.
func findCacheHitAuthForStrictBypass(auths []*Auth, id, model string) *Auth {
	if id == "" {
		return nil
	}
	for _, a := range auths {
		if a == nil || a.ID != id {
			continue
		}
		if a.Disabled || a.Status == StatusDisabled {
			return nil
		}
		if model != "" && len(a.ModelStates) > 0 {
			state, ok := a.ModelStates[model]
			if (!ok || state == nil) && model != "" {
				baseModel := canonicalModelKey(model)
				if baseModel != "" && baseModel != model {
					state, ok = a.ModelStates[baseModel]
				}
			}
			if ok && state != nil && state.Status == StatusDisabled {
				return nil
			}
		}
		return a
	}
	return nil
}

// sessionPattern matches Claude Code user_id format:
// user_{hash}_account__session_{uuid}
var sessionPattern = regexp.MustCompile(`_session_([a-f0-9-]+)$`)

// SessionAffinitySelector wraps another selector with session-sticky behavior.
// It extracts session ID from multiple sources and maintains session-to-auth
// mappings. When the bound auth becomes unavailable, by default the selector
// falls back to its base selector to pick a fresh credential. Set
// SessionAffinityConfig.Strict to true to instead surface an error in that
// case (recommended when upstream risk-control treats cross-account
// continuation of one conversation as abuse).
type SessionAffinitySelector struct {
	fallback Selector
	cache    *SessionCache
	strict   bool
}

// SessionAffinityConfig configures the session affinity selector.
type SessionAffinityConfig struct {
	Fallback Selector
	TTL      time.Duration
	// PersistencePath, when non-empty, points to a JSON file where the
	// session-to-auth bindings are persisted. The cache is restored from
	// this file on startup, so existing client conversations stay bound to
	// their original auth across CPA restarts. Empty disables persistence
	// (legacy in-memory-only behaviour).
	PersistencePath string
	// Strict, when true, refuses to silently switch the bound auth if the
	// originally selected credential is no longer available. The Pick call
	// returns an error so the conductor can surface it to the client
	// instead of replaying the same conversation on a fresh credential —
	// which is the exact signal that upstream risk control flags as
	// cross-account abuse.
	Strict bool
}

// NewSessionAffinitySelector creates a new session-aware selector.
func NewSessionAffinitySelector(fallback Selector) *SessionAffinitySelector {
	return NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: fallback,
		TTL:      time.Hour,
	})
}

// NewSessionAffinitySelectorWithConfig creates a selector with custom configuration.
func NewSessionAffinitySelectorWithConfig(cfg SessionAffinityConfig) *SessionAffinitySelector {
	if cfg.Fallback == nil {
		cfg.Fallback = &RoundRobinSelector{}
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	return &SessionAffinitySelector{
		fallback: cfg.Fallback,
		cache:    NewSessionCacheWithPersistence(cfg.TTL, cfg.PersistencePath),
		strict:   cfg.Strict,
	}
}

// Pick selects an auth with session affinity when possible.
// Priority for session ID extraction:
//  1. metadata.user_id (Claude Code format with _session_{uuid}) - highest priority
//  2. X-Codex-Turn-Metadata header — thread_id/session_id JSON (Codex VSCode / CLI)
//  3. X-Session-ID header
//  4. Session_id / Session-Id header (Codex CLI legacy and upstream restored)
//  5. X-Amp-Thread-Id header (Amp CLI thread ID)
//  6. X-Client-Request-Id header (PI / Codex thread_id fallback)
//  7. metadata.user_id (non-Claude Code format)
//  8. conversation_id field in request body
//  9. Stable hash from first few messages content (fallback)
//
// The cache key is provider+session (model is intentionally NOT in the key). The
// upstream risk-control signal that drove this whole design is per-conversation,
// not per-model: replaying one conversation under multiple chatgpt_account_ids
// looks like account abuse regardless of which model each call used. Including
// the model in the key would let a single VSCode window split across two
// accounts the moment Codex switches from gpt-5.5 (chat) to codex-auto-review
// (sub-agent) — the exact signal we are trying to avoid. Per-model availability
// is still enforced downstream: `available` is already filtered to auths that
// can serve the requested model, so if the bound auth cannot serve it the
// existing "bound auth unavailable" branch fires (strict-mode error or
// fallback reselect, depending on configuration).
func (s *SessionAffinitySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (selectedAuth *Auth, retErr error) {
	entry := selectorLogEntry(ctx)
	// Temporary diagnostic: when a Codex client sends X-Codex-Turn-Metadata,
	// log the full session_id / thread_id / turn_id / model / chosen auth_id so
	// we can verify whether the sub-agent (codex-auto-review) reuses the
	// primary chat's thread_id. The answer determines whether we can safely
	// switch the affinity key from session_id (one VSCode window = one auth)
	// to thread_id (one conversation = one auth, allowing /new to redistribute).
	// Remove this log once that question is settled.
	defer logCodexTurnSample(entry, opts.Headers, provider, model, selectedAuth, retErr)
	primaryID, fallbackID, mirrorID := extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	if primaryID == "" {
		entry.Debugf("session-affinity: no session ID extracted, falling back to default selector | provider=%s model=%s", provider, model)
		return s.fallback.Pick(ctx, provider, model, opts, auths)
	}

	now := time.Now()
	cacheKey := provider + "::" + primaryID
	mirrorKey := ""
	if mirrorID != "" && mirrorID != primaryID {
		mirrorKey = provider + "::" + mirrorID
	}
	// writeBinding records the new authoritative binding under both the
	// primary key and the mirror key (when set). The mirror lets a Codex
	// sub-agent — whose lookup key is the parent's window session_id — find
	// the binding the parent thread established. Subsequent /new operations
	// on the same window mint a new thread_id, miss the primary key, and
	// overwrite the mirror so future sub-agents inherit the freshest
	// parent's binding rather than a stale one.
	writeBinding := func(authID string) {
		s.cache.Set(cacheKey, authID)
		if mirrorKey != "" {
			s.cache.Set(mirrorKey, authID)
		}
	}

	cachedAuthID, hit := s.cache.GetAndRefresh(cacheKey)

	// Strict-mode bypass: when we already have a binding for this session,
	// honor it even if the auth is currently in a temporary cooldown. The
	// conductor will surface the real upstream result; if it succeeds (the
	// usual case for transient 5xx / connection-reset) the user never sees
	// the cooldown. The original strict design — refuse fallback on
	// unavailable — was protecting against silently routing to a *different*
	// account, not against retrying the bound one through a 1-minute
	// network blip. Administratively disabled auths (Disabled flag, status
	// StatusDisabled, or per-model StatusDisabled) still trigger the
	// strict-refuse path.
	if hit && s.strict {
		bound := findCacheHitAuthForStrictBypass(auths, cachedAuthID, model)
		if bound == nil {
			entry.Warnf("session-affinity: bound auth missing or disabled, refusing fallback (strict) | session=%s bound_auth=%s provider=%s model=%s", truncateSessionID(primaryID), cachedAuthID, provider, model)
			return nil, &Error{
				Code:    "auth_bound_unavailable",
				Message: "session-bound auth is currently unavailable; start a new conversation to pick a different credential",
			}
		}
		if mirrorKey != "" {
			s.cache.Set(mirrorKey, bound.ID)
		}
		// Distinguish a normal cache hit (auth fully available) from a
		// real bypass (auth is currently in cooldown / unavailable). The
		// bypass case is the interesting one for operators investigating
		// upstream blips; the normal case should look like the
		// non-strict cache-hit log to avoid alert noise.
		if blocked, _, _ := isAuthBlockedForModel(bound, model, now); blocked {
			entry.Infof("session-affinity: cache hit (strict, bypassing cooldown) | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), bound.ID, provider, model)
		} else {
			entry.Infof("session-affinity: cache hit | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), bound.ID, provider, model)
		}
		return bound, nil
	}

	available, err := getAvailableAuths(auths, provider, model, now)
	if err != nil {
		return nil, err
	}

	if hit {
		// Non-strict cache hit: strict was handled above. Either return the
		// bound auth if it's still in the available pool, or transparently
		// reselect through the fallback selector.
		for _, auth := range available {
			if auth.ID == cachedAuthID {
				if mirrorKey != "" {
					s.cache.Set(mirrorKey, auth.ID)
				}
				entry.Infof("session-affinity: cache hit | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
				return auth, nil
			}
		}
		// Cached auth not available, reselect via fallback selector for even distribution
		auth, err := s.fallback.Pick(ctx, provider, model, opts, auths)
		if err != nil {
			return nil, err
		}
		writeBinding(auth.ID)
		entry.Infof("session-affinity: cache hit but auth unavailable, reselected | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
		return auth, nil
	}

	if fallbackID != "" && fallbackID != primaryID {
		fallbackKey := provider + "::" + fallbackID
		if cachedAuthID, ok := s.cache.Get(fallbackKey); ok {
			for _, auth := range available {
				if auth.ID == cachedAuthID {
					writeBinding(auth.ID)
					entry.Infof("session-affinity: fallback cache hit | session=%s fallback=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), auth.ID, provider, model)
					return auth, nil
				}
			}
		}
	}

	auth, err := s.fallback.Pick(ctx, provider, model, opts, auths)
	if err != nil {
		return nil, err
	}
	writeBinding(auth.ID)
	entry.Infof("session-affinity: cache miss, new binding | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
	return auth, nil
}

func selectorLogEntry(ctx context.Context) *log.Entry {
	if ctx == nil {
		return log.NewEntry(log.StandardLogger())
	}
	if reqID := logging.GetRequestID(ctx); reqID != "" {
		return log.WithField("request_id", reqID)
	}
	return log.NewEntry(log.StandardLogger())
}

// truncateSessionID shortens session ID for logging (first 8 chars + "...")
func truncateSessionID(id string) string {
	if len(id) <= 20 {
		return id
	}
	return id[:8] + "..."
}

// logCodexTurnSample emits a one-line diagnostic for every Pick that carries
// an X-Codex-Turn-Metadata header, recording the full session_id, thread_id,
// turn_id, request model, and the auth that was selected (or the error code
// when strict mode refused to fail over). The output is intentionally
// parseable: grep for "codex-turn-sample" then awk on the key=value pairs.
// This is observation-only — no behavior change — and is meant to be removed
// once we have enough samples to decide whether thread_id is a safe replacement
// for session_id as the affinity key.
func logCodexTurnSample(entry *log.Entry, headers http.Header, provider, model string, selected *Auth, retErr error) {
	if entry == nil || headers == nil {
		return
	}
	raw := strings.TrimSpace(headers.Get("X-Codex-Turn-Metadata"))
	if raw == "" {
		return
	}
	sessionID := gjson.Get(raw, "session_id").String()
	threadID := gjson.Get(raw, "thread_id").String()
	turnID := gjson.Get(raw, "turn_id").String()
	threadSource := gjson.Get(raw, "thread_source").String()
	authID := ""
	if selected != nil {
		authID = selected.ID
	}
	errCode := ""
	if retErr != nil {
		var ae *Error
		if errors.As(retErr, &ae) && ae != nil {
			errCode = ae.Code
		} else {
			errCode = "error"
		}
	}
	entry.Infof("codex-turn-sample | provider=%s model=%s session_id=%s thread_id=%s turn_id=%s thread_source=%s auth=%s err=%s",
		provider, model, sessionID, threadID, turnID, threadSource, authID, errCode)
}

// Stop releases resources held by the selector.
func (s *SessionAffinitySelector) Stop() {
	if s.cache != nil {
		s.cache.Stop()
	}
}

// InvalidateAuth removes all session bindings for a specific auth.
// Called when an auth becomes rate-limited or unavailable.
func (s *SessionAffinitySelector) InvalidateAuth(authID string) {
	if s.cache != nil {
		s.cache.InvalidateAuth(authID)
	}
}

// ExtractSessionID extracts session identifier from multiple sources.
// Priority order:
//  1. metadata.user_id (Claude Code format with _session_{uuid}) - highest priority for Claude Code clients
//  2. X-Codex-Turn-Metadata header — thread_id/session_id JSON (Codex VSCode / CLI)
//  3. X-Session-ID header
//  4. Session_id / Session-Id header (Codex CLI legacy and upstream restored)
//  5. X-Amp-Thread-Id header (Amp CLI thread ID)
//  6. X-Client-Request-Id header (PI / Codex thread_id fallback)
//  7. metadata.user_id (non-Claude Code format)
//  8. conversation_id field in request body
//  9. Stable hash from first few messages content (fallback)
func ExtractSessionID(headers http.Header, payload []byte, metadata map[string]any) string {
	primary, _, _ := extractSessionIDs(headers, payload, metadata)
	return primary
}

// extractSessionIDs returns (primaryID, fallbackID, mirrorID) for session affinity.
//
//   - primaryID: the lookup/write key for this turn's binding. Cache reads
//     consult this key first.
//   - fallbackID: a secondary key consulted on a primary cache miss
//     (legacy Claude-Code short-hash inheritance). When present and cached,
//     the existing binding is adopted onto the primary key.
//   - mirrorID: an additional key the binding is also WRITTEN under on bind
//     and on every refresh. Reads do NOT consult the mirror directly. This
//     is what lets a Codex sub-agent (which uses the window-stable session
//     id as its lookup key) inherit the parent conversation's binding while
//     /new — which mints a fresh thread_id — still misses cleanly and
//     receives a freshly-selected auth via the fallback selector.
func extractSessionIDs(headers http.Header, payload []byte, metadata map[string]any) (string, string, string) {
	// 1. metadata.user_id with Claude Code session format (highest priority)
	if len(payload) > 0 {
		userID := gjson.GetBytes(payload, "metadata.user_id").String()
		if userID != "" {
			// Old format: user_{hash}_account__session_{uuid}
			if matches := sessionPattern.FindStringSubmatch(userID); len(matches) >= 2 {
				id := "claude:" + matches[1]
				return id, "", ""
			}
			// New format: JSON object with session_id field
			// e.g. {"device_id":"...","account_uuid":"...","session_id":"uuid"}
			if len(userID) > 0 && userID[0] == '{' {
				if sid := gjson.Get(userID, "session_id").String(); sid != "" {
					return "claude:" + sid, "", ""
				}
			}
		}
	}

	// 2. X-Codex-Turn-Metadata header (Codex VSCode / CLI).
	//
	// Codex clients embed turn metadata as a JSON blob under this header,
	// e.g. {"session_id":"<window-stable uuid>","thread_id":"<per-thread>",
	//        "turn_id":"<per-message>","thread_source":"user|subagent", ...}.
	//
	// We bind on the granularity of one conversation (thread_id) so that
	// /new in the same window — which keeps session_id stable but mints a
	// fresh thread_id — naturally falls through to the quota-aware fallback
	// selector and gets a different credential. Continuing the same
	// conversation keeps the same thread_id and stays on the bound auth.
	//
	// Sub-agent calls (code review, etc.) carry their own thread_id but
	// share the parent conversation's session_id. We give them the
	// session-level key as their PRIMARY key so they look up directly
	// under the mirror that the parent's user-thread Pick writes. This is
	// essential for upstream risk-control: a sub-agent split across
	// credentials within one logical conversation looks like account
	// abuse on OpenAI's side.
	//
	// Real Codex VSCode always populates session_id; an X-Codex-Turn-Metadata
	// header without it is treated as malformed and we fall through to the
	// next extractor.
	if headers != nil {
		if meta := headers.Get("X-Codex-Turn-Metadata"); meta != "" {
			sid := strings.TrimSpace(gjson.Get(meta, "session_id").String())
			tid := strings.TrimSpace(gjson.Get(meta, "thread_id").String())
			source := strings.ToLower(strings.TrimSpace(gjson.Get(meta, "thread_source").String()))
			if sid != "" {
				if source == "subagent" {
					return "codex-window:" + sid, "", ""
				}
				if tid != "" {
					// Always write the codex-window mirror, even when
					// tid == sid (the common case on the first turn of a
					// Codex conversation — Codex reuses the session UUID
					// as the initial thread UUID). The two cache keys
					// "codex-thread:<uuid>" and "codex-window:<uuid>"
					// share a UUID but live in DIFFERENT namespaces, so
					// writing only the thread key leaves the window
					// mirror empty — which means the sub-agent's later
					// lookup (it primary-keys on "codex-window:<sid>")
					// misses and the sub-agent gets a fresh fallback
					// Pick on a different credential. That is exactly
					// the cross-account split within one conversation
					// that the anti-correlation work was built to
					// prevent.
					return "codex-thread:" + tid, "", "codex-window:" + sid
				}
				return "codex-window:" + sid, "", ""
			}
		}
	}

	// 3. X-Session-ID header
	if headers != nil {
		if sid := headers.Get("X-Session-ID"); sid != "" {
			return "header:" + sid, "", ""
		}
	}

	// 4. Session_id / Session-Id header (Codex CLI legacy + upstream restored
	// for the latest VSCode/CLI Codex clients).
	if headers != nil {
		if sid := headers.Get("Session-Id"); sid != "" {
			return "codex:" + sid, "", ""
		}
		if sid := headers.Get("Session_id"); sid != "" {
			return "codex:" + sid, "", ""
		}
	}

	// 5. X-Amp-Thread-Id header (Amp CLI thread ID)
	if headers != nil {
		if tid := headers.Get("X-Amp-Thread-Id"); tid != "" {
			return "amp:" + tid, "", ""
		}
	}

	// 6. X-Client-Request-Id header (PI; for Codex this is the thread_id —
	// which changes per sub-agent invocation. Kept as a fallback only.)
	if headers != nil {
		if rid := headers.Get("X-Client-Request-Id"); rid != "" {
			return "clientreq:" + rid, "", ""
		}
	}

	if len(payload) == 0 {
		return "", "", ""
	}

	// 7. metadata.user_id (non-Claude Code format)
	userID := gjson.GetBytes(payload, "metadata.user_id").String()
	if userID != "" {
		return "user:" + userID, "", ""
	}

	// 8. conversation_id field
	if convID := gjson.GetBytes(payload, "conversation_id").String(); convID != "" {
		return "conv:" + convID, "", ""
	}

	// 9. Hash-based fallback from message content
	primary, fb := extractMessageHashIDs(payload)
	return primary, fb, ""
}

func extractMessageHashIDs(payload []byte) (primaryID, fallbackID string) {
	var systemPrompt, firstUserMsg, firstAssistantMsg string

	// OpenAI/Claude messages format
	messages := gjson.GetBytes(payload, "messages")
	if messages.Exists() && messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			role := msg.Get("role").String()
			content := extractMessageContent(msg.Get("content"))
			if content == "" {
				return true
			}

			switch role {
			case "system":
				if systemPrompt == "" {
					systemPrompt = truncateString(content, 100)
				}
			case "user":
				if firstUserMsg == "" {
					firstUserMsg = truncateString(content, 100)
				}
			case "assistant":
				if firstAssistantMsg == "" {
					firstAssistantMsg = truncateString(content, 100)
				}
			}

			if systemPrompt != "" && firstUserMsg != "" && firstAssistantMsg != "" {
				return false
			}
			return true
		})
	}

	// Claude API: top-level "system" field (array or string)
	if systemPrompt == "" {
		topSystem := gjson.GetBytes(payload, "system")
		if topSystem.Exists() {
			if topSystem.IsArray() {
				topSystem.ForEach(func(_, part gjson.Result) bool {
					if text := part.Get("text").String(); text != "" && systemPrompt == "" {
						systemPrompt = truncateString(text, 100)
						return false
					}
					return true
				})
			} else if topSystem.Type == gjson.String {
				systemPrompt = truncateString(topSystem.String(), 100)
			}
		}
	}

	// Gemini format
	if systemPrompt == "" && firstUserMsg == "" {
		sysInstr := gjson.GetBytes(payload, "systemInstruction.parts")
		if sysInstr.Exists() && sysInstr.IsArray() {
			sysInstr.ForEach(func(_, part gjson.Result) bool {
				if text := part.Get("text").String(); text != "" && systemPrompt == "" {
					systemPrompt = truncateString(text, 100)
					return false
				}
				return true
			})
		}

		contents := gjson.GetBytes(payload, "contents")
		if contents.Exists() && contents.IsArray() {
			contents.ForEach(func(_, msg gjson.Result) bool {
				role := msg.Get("role").String()
				msg.Get("parts").ForEach(func(_, part gjson.Result) bool {
					text := part.Get("text").String()
					if text == "" {
						return true
					}
					switch role {
					case "user":
						if firstUserMsg == "" {
							firstUserMsg = truncateString(text, 100)
						}
					case "model":
						if firstAssistantMsg == "" {
							firstAssistantMsg = truncateString(text, 100)
						}
					}
					return false
				})
				if firstUserMsg != "" && firstAssistantMsg != "" {
					return false
				}
				return true
			})
		}
	}

	// OpenAI Responses API format (v1/responses)
	if systemPrompt == "" && firstUserMsg == "" {
		if instr := gjson.GetBytes(payload, "instructions").String(); instr != "" {
			systemPrompt = truncateString(instr, 100)
		}

		input := gjson.GetBytes(payload, "input")
		if input.Exists() && input.IsArray() {
			input.ForEach(func(_, item gjson.Result) bool {
				itemType := item.Get("type").String()
				if itemType == "reasoning" {
					return true
				}
				// Skip non-message typed items (function_call, function_call_output, etc.)
				// but allow items with no type that have a role (inline message format).
				if itemType != "" && itemType != "message" {
					return true
				}

				role := item.Get("role").String()
				if itemType == "" && role == "" {
					return true
				}

				// Handle both string content and array content (multimodal).
				content := item.Get("content")
				var text string
				if content.Type == gjson.String {
					text = content.String()
				} else {
					text = extractResponsesAPIContent(content)
				}
				if text == "" {
					return true
				}

				switch role {
				case "developer", "system":
					if systemPrompt == "" {
						systemPrompt = truncateString(text, 100)
					}
				case "user":
					if firstUserMsg == "" {
						firstUserMsg = truncateString(text, 100)
					}
				case "assistant":
					if firstAssistantMsg == "" {
						firstAssistantMsg = truncateString(text, 100)
					}
				}

				if firstUserMsg != "" && firstAssistantMsg != "" {
					return false
				}
				return true
			})
		}
	}

	if systemPrompt == "" && firstUserMsg == "" {
		return "", ""
	}

	shortHash := computeSessionHash(systemPrompt, firstUserMsg, "")
	if firstAssistantMsg == "" {
		return shortHash, ""
	}

	fullHash := computeSessionHash(systemPrompt, firstUserMsg, firstAssistantMsg)
	return fullHash, shortHash
}

func computeSessionHash(systemPrompt, userMsg, assistantMsg string) string {
	h := fnv.New64a()
	if systemPrompt != "" {
		h.Write([]byte("sys:" + systemPrompt + "\n"))
	}
	if userMsg != "" {
		h.Write([]byte("usr:" + userMsg + "\n"))
	}
	if assistantMsg != "" {
		h.Write([]byte("ast:" + assistantMsg + "\n"))
	}
	return fmt.Sprintf("msg:%016x", h.Sum64())
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// extractMessageContent extracts text content from a message content field.
// Handles both string content and array content (multimodal messages).
// For array content, extracts text from all text-type elements.
func extractMessageContent(content gjson.Result) string {
	// String content: "Hello world"
	if content.Type == gjson.String {
		return content.String()
	}

	// Array content: [{"type":"text","text":"Hello"},{"type":"image",...}]
	if content.IsArray() {
		var texts []string
		content.ForEach(func(_, part gjson.Result) bool {
			// Handle Claude format: {"type":"text","text":"content"}
			if part.Get("type").String() == "text" {
				if text := part.Get("text").String(); text != "" {
					texts = append(texts, text)
				}
			}
			// Handle OpenAI format: {"type":"text","text":"content"}
			// Same structure as Claude, already handled above
			return true
		})
		if len(texts) > 0 {
			return strings.Join(texts, " ")
		}
	}

	return ""
}

func extractResponsesAPIContent(content gjson.Result) string {
	if !content.IsArray() {
		return ""
	}
	var texts []string
	content.ForEach(func(_, part gjson.Result) bool {
		partType := part.Get("type").String()
		if partType == "input_text" || partType == "output_text" || partType == "text" {
			if text := part.Get("text").String(); text != "" {
				texts = append(texts, text)
			}
		}
		return true
	})
	if len(texts) > 0 {
		return strings.Join(texts, " ")
	}
	return ""
}

// extractSessionID is kept for backward compatibility.
// Deprecated: Use ExtractSessionID instead.
func extractSessionID(payload []byte) string {
	return ExtractSessionID(nil, payload, nil)
}
