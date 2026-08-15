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

	"github.com/router-for-me/CLIProxyAPI/v7/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
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

// WeightedRoundRobinSelector provides smooth weighted round-robin selection.
// Credentials with a positive `weight` attribute are selected proportionally
// to that weight; credentials with weight <= 0 are excluded entirely.
type WeightedRoundRobinSelector struct {
	mu      sync.Mutex
	states  map[string]*smoothWeightedState
	maxKeys int
}

type smoothWeightedState struct {
	current map[string]int64
	weights map[string]int64
}

type weightedSelectorStateModelKey struct{}

func withWeightedSelectorStateModel(ctx context.Context, selector Selector, routeModel string) context.Context {
	if _, ok := selector.(*WeightedRoundRobinSelector); !ok || strings.TrimSpace(routeModel) == "" {
		return ctx
	}
	return context.WithValue(ctx, weightedSelectorStateModelKey{}, routeModel)
}

func weightedSelectorStateModel(ctx context.Context, availabilityModel string) string {
	if ctx != nil {
		if routeModel, ok := ctx.Value(weightedSelectorStateModelKey{}).(string); ok && strings.TrimSpace(routeModel) != "" {
			return routeModel
		}
	}
	return availabilityModel
}

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

// authWeight resolves the credential weight from attributes or metadata.
// Weight <= 0 excludes the credential from weighted selection.
func authWeight(auth *Auth) int64 {
	if auth == nil {
		return credentialweight.Default
	}
	if rawWeight, ok := auth.Attributes[AttributeWeight]; ok && strings.TrimSpace(rawWeight) != "" {
		weight, errParse := credentialweight.ParseString(rawWeight)
		if errParse != nil {
			return 0
		}
		return weight
	}
	if rawWeight, ok := auth.Metadata[AttributeWeight]; ok {
		weight, errParse := credentialweight.ParseValue(rawWeight)
		if errParse != nil {
			return 0
		}
		return weight
	}
	return credentialweight.Default
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

func collectAvailableByPriority(ctx context.Context, auths []*Auth, model string, now time.Time) (available map[int][]*Auth, cooldownCount int, earliest time.Time) {
	available = make(map[int][]*Auth)
	for i := 0; i < len(auths); i++ {
		candidate := auths[i]
		checkModel := resolveModelForCheck(ctx, candidate, model)
		blocked, reason, next := isAuthBlockedForModel(candidate, checkModel, now)
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

func getAvailableAuths(ctx context.Context, auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth candidates"}
	}

	availableByPriority, cooldownCount, earliest := collectAvailableByPriority(ctx, auths, model, now)
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
	available, err := getAvailableAuths(ctx, auths, provider, model, now)
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

// positiveWeightAuths filters to credentials with a positive weight.
// Weight <= 0 excludes the credential from weighted selection.
func positiveWeightAuths(auths []*Auth) []*Auth {
	weightedCandidates := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if authWeight(auth) > 0 {
			weightedCandidates = append(weightedCandidates, auth)
		}
	}
	return weightedCandidates
}

// Pick selects the next available auth using smooth weighted round-robin.
func (s *WeightedRoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	available, errAvailable := getAvailableAuths(ctx, positiveWeightAuths(auths), provider, model, time.Now())
	if errAvailable != nil {
		return nil, errAvailable
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	stateModel := weightedSelectorStateModel(ctx, model)
	key := provider + ":" + canonicalModelKey(stateModel)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		s.states = make(map[string]*smoothWeightedState)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.states[key]; !ok && len(s.states) >= limit {
		s.states = make(map[string]*smoothWeightedState)
	}
	state := s.states[key]
	if state == nil {
		state = &smoothWeightedState{}
		s.states[key] = state
	}
	weights := authWeightVector(available)
	state.prepare(weights)
	picked := pickSmoothWeightedAuth(available, state.current)
	if picked == nil {
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available with positive weight"}
	}
	return picked, nil
}

func (s *smoothWeightedState) prepare(weights map[string]int64) {
	if s.current == nil || !weightVectorsEqual(s.weights, weights) {
		s.current = make(map[string]int64)
	}
	s.weights = weights
}

func weightVectorsEqual(left, right map[string]int64) bool {
	if len(left) != len(right) {
		return false
	}
	for authID, weight := range left {
		if right[authID] != weight {
			return false
		}
	}
	return true
}

func authWeightVector(auths []*Auth) map[string]int64 {
	weights := make(map[string]int64, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if weight := authWeight(auth); weight > 0 {
			weights[auth.ID] = weight
		}
	}
	return weights
}

func pickSmoothWeightedAuth(auths []*Auth, current map[string]int64) *Auth {
	active := make(map[string]struct{}, len(auths))
	var picked *Auth
	var pickedCurrent int64
	var totalWeight int64
	for _, auth := range auths {
		weight := authWeight(auth)
		if auth == nil || weight <= 0 {
			continue
		}
		active[auth.ID] = struct{}{}
		current[auth.ID] = saturatingAddInt64(current[auth.ID], weight)
		totalWeight = saturatingAddInt64(totalWeight, weight)
		if picked == nil || current[auth.ID] > pickedCurrent {
			picked = auth
			pickedCurrent = current[auth.ID]
		}
	}
	for authID := range current {
		if _, ok := active[authID]; !ok {
			delete(current, authID)
		}
	}
	if picked == nil {
		return nil
	}
	current[picked.ID] = saturatingAddInt64(current[picked.ID], -totalWeight)
	return picked
}

func saturatingAddInt64(value, delta int64) int64 {
	if delta > 0 && value > math.MaxInt64-delta {
		return math.MaxInt64
	}
	if delta < 0 && value < math.MinInt64-delta {
		return math.MinInt64
	}
	return value + delta
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
	available, err := getAvailableAuths(ctx, auths, provider, model, now)
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
// ID in the full pool, returning it for any non-admin-disabled state
// so the conductor can forward the request and let upstream surface
// the real outcome to the client.
//
// We deliberately do NOT short-circuit on quota cooldowns / 5xx
// cooldowns / NextRetryAfter timers here. The previous design tried
// to predict "this auth will 429 again, don't bother" — but a
// synthesized error from us is always a worse signal than the
// upstream 429 itself: Codex CLI has no branch for our internal
// "auth_bound_unavailable" code and just shows a generic "high
// demand" toast that masks the actual cause. Trying through and
// letting upstream return its real 429 with usage_limit_reached
// gives the Codex CLI exactly the response shape it knows how to
// render, and costs at most one extra RTT per user message. The
// conductor's MarkResult will keep updating cooldown state so the
// LAYER-2 quota filter (which acts on cache MISSES, not hits) still
// excludes exhausted credentials from new bindings.
//
// What we still refuse to return (caller falls through to
// strict-refuse and the selector raises usage_limit_reached 429):
//
//   - the auth is no longer in the pool (removed by admin / hot reload);
//   - the auth has been administratively disabled (auth.Disabled or
//     auth.Status == StatusDisabled);
//   - the per-model state is administratively disabled
//     (state.Status == StatusDisabled).
//
// These are the only states that genuinely cannot be served by
// retrying upstream — every other failure mode resolves itself
// through the natural request/response cycle.
// modelUnsupportedForAuthID reports whether this auth has LEARNED it cannot
// serve the model (durable registry model_not_supported marker set from an
// upstream entitlement rejection). Deliberately narrow: it must never consider
// the generic suspension marker, which is also set for transient 429/401 and
// would tear down bindings that strict affinity exists to preserve.
// filterModelSupported removes auths that have LEARNED they cannot serve the
// model. Returns the input untouched when nothing is marked (the common case)
// or when filtering would empty the pool — an empty candidate list produces a
// confusing "no auth" error, and leaving the pool alone lets the normal error
// path report the real upstream rejection instead.
func filterModelSupported(auths []*Auth, model string) []*Auth {
	if len(auths) == 0 {
		return auths
	}
	kept := make([]*Auth, 0, len(auths))
	for _, a := range auths {
		if a != nil && modelUnsupportedForAuthID(a.ID, model) {
			continue
		}
		kept = append(kept, a)
	}
	if len(kept) == 0 || len(kept) == len(auths) {
		return auths
	}
	return kept
}

func modelUnsupportedForAuthID(authID, model string) bool {
	reg := registry.GetGlobalRegistry()
	if reg == nil {
		return false
	}
	key := canonicalModelKey(model)
	if key == "" {
		return false
	}
	return reg.IsClientModelUnsupported(authID, key)
}

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

// ModelAliasResolver returns the per-auth model key for state lookups
// when the route model differs from the auth's actual state key (the
// OAuth alias case — antigravity / select codex models). The selector
// uses this when filtering availability so an auth with state under
// the alias target is checked against the right ModelState key.
// Returning "" means no resolution available; the caller should treat
// the route model as the lookup key.
type ModelAliasResolver func(auth *Auth, routeModel string) string

type aliasResolverKey struct{}

// WithAliasResolver attaches a per-auth model alias resolver to ctx.
// The conductor installs this when invoking the selector so the
// selector's internal availability filter can resolve aliases the same
// way as the conductor would. Without this the selector falls back to
// using the route model directly, which is fine for the common
// no-alias case but mishandles antigravity-style aliased state keys.
func WithAliasResolver(ctx context.Context, fn ModelAliasResolver) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, aliasResolverKey{}, fn)
}

func aliasResolverFromContext(ctx context.Context) ModelAliasResolver {
	if ctx == nil {
		return nil
	}
	fn, _ := ctx.Value(aliasResolverKey{}).(ModelAliasResolver)
	return fn
}

// strictBypassFlagKey carries a *bool the conductor sets before calling
// Pick. The session-affinity selector flips it to true when it returns
// an auth via the strict-bypass branch (cache hit on a bound auth that
// is currently in cooldown). The conductor reads it back after Pick so
// filterExecutionModels can decide whether to honour the binding all
// the way down (skipping per-model cooldown filter) or apply the
// normal "skip cooled-down upstream variants" behaviour. Without this
// signal, filterExecutionModels has to either always-filter (breaks
// strict-bypass — bound session loses every upstream model and the
// caller silently 429s) or always-fallback (breaks openai-compat pool
// — a bad auth with every variant cooled consumes the retry budget
// instead of being skipped).
type strictBypassFlagKey struct{}

// WithStrictBypassFlag attaches a *bool flag that the selector will
// flip to true when it returns an auth via strict-bypass. The caller
// owns the storage; nil is treated as "caller doesn't care".
func WithStrictBypassFlag(ctx context.Context, flag *bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if flag == nil {
		return ctx
	}
	return context.WithValue(ctx, strictBypassFlagKey{}, flag)
}

func markStrictBypass(ctx context.Context) {
	if ctx == nil {
		return
	}
	flag, _ := ctx.Value(strictBypassFlagKey{}).(*bool)
	if flag != nil {
		*flag = true
	}
}

// resolveModelForCheck returns the model key to use when checking an
// auth's per-model state. Falls back to routeModel when no resolver is
// installed or the resolver returns blank.
func resolveModelForCheck(ctx context.Context, auth *Auth, routeModel string) string {
	resolver := aliasResolverFromContext(ctx)
	if resolver == nil {
		return routeModel
	}
	resolved := strings.TrimSpace(resolver(auth, routeModel))
	if resolved == "" {
		return routeModel
	}
	return resolved
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
	// Drop accounts that upstream has rejected as unentitled for this model
	// (durable model_not_supported marker). Doing it here as well as in the
	// downstream selector keeps each layer independently correct: this
	// selector's fallback is not necessarily quota-aware, and honouring a
	// binding to an account that cannot serve the model would 400 every turn.
	auths = filterModelSupported(auths, model)
	primaryID, fallbackID, mirrorID := extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	if primaryID == "" {
		entry.Debugf("session-affinity: no session ID extracted, falling back to default selector | provider=%s model=%s", provider, model)
		return s.fallback.Pick(ctx, provider, model, opts, auths)
	}

	// Fork detection: when a Codex /new turn arrives, the new
	// thread_id carries forked_from_thread_id pointing at the OLD
	// thread. Mark that old binding closed in the cache so the
	// operator-facing reverse-index can distinguish abandoned
	// conversations from active ones. This is observe-only: the
	// closed marker does NOT change Pick or LeastBound behaviour
	// today — that's a follow-up release gated on confirming
	// detection accuracy in production. Done BEFORE the cache hit
	// short-circuit so the marker fires regardless of which path
	// this Pick takes.
	currentThreadID, forkedFromTid := extractCodexForkSignal(opts.Headers)
	if forkedFromTid != "" {
		forkedFromKey := provider + "::codex-thread:" + forkedFromTid
		s.cache.MarkClosed(forkedFromKey, currentThreadID)
		entry.Debugf("session-affinity: marked closed by fork | from=%s to=%s provider=%s model=%s", truncateSessionID(forkedFromTid), truncateSessionID(currentThreadID), provider, model)
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
		s.cache.SetWithModel(cacheKey, authID, model)
		if mirrorKey != "" {
			s.cache.SetWithModel(mirrorKey, authID, model)
		}
	}

	cachedAuthID, hit := s.cache.GetAndRefresh(cacheKey)
	if hit && cachedAuthID != "" {
		// Backfill the model on cache hits so bindings established before
		// the model-tracking change (or by older binaries) still show the
		// model in the operator-facing bindings panel.
		s.cache.SetWithModel(cacheKey, cachedAuthID, model)
		if mirrorKey != "" {
			s.cache.SetWithModel(mirrorKey, cachedAuthID, model)
		}
	}

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
	// A binding must not outlive the bound account's ability to serve the
	// requested model. Session affinity is about keeping ONE conversation on
	// ONE credential through transient trouble; an account that upstream has
	// rejected as unentitled for this model (durable model_not_supported
	// marker) is not transient — every turn would 400, and strict mode would
	// refuse to move, so the conversation would be permanently stuck. Drop the
	// binding for this model and let normal selection pick an entitled account
	// (which also rebinds). Reason-scoped to the entitlement marker: transient
	// quota/401 trouble still goes through the strict-bypass path below.
	if hit && cachedAuthID != "" && modelUnsupportedForAuthID(cachedAuthID, model) {
		entry.Infof("session-affinity: bound auth cannot serve %s, re-selecting | session=%s bound_auth=%s provider=%s", model, truncateSessionID(primaryID), cachedAuthID, provider)
		hit = false
	}
	if hit && s.strict {
		bound := findCacheHitAuthForStrictBypass(auths, cachedAuthID, model)
		if bound == nil {
			entry.Warnf("session-affinity: bound auth missing or disabled, refusing fallback (strict) | session=%s bound_auth=%s provider=%s model=%s", truncateSessionID(primaryID), cachedAuthID, provider, model)
			// Auto-release linkage: when auto-release-on-429 is enabled,
			// drop this auth's session bindings so the stranded conversation
			// re-picks a fresh credential on its next turn instead of being
			// permanently stuck on the missing/disabled bound auth. Without
			// this, a strict-refuse 429 never reaches the conductor's
			// MarkResult path (no upstream request happens), so the binding
			// would never be released and every turn would hard-429.
			if autoReleaseOn429.Load() {
				if released := s.InvalidateAuthBindings(cachedAuthID); released > 0 {
					entry.Infof("session-affinity: auto-release dropped %d binding(s) for missing/disabled bound auth | session=%s bound_auth=%s provider=%s model=%s", released, truncateSessionID(primaryID), cachedAuthID, provider, model)
				}
			}
			// Return the upstream-shape 429 so Codex CLI recognises the
			// outcome as a quota event and renders the right message to
			// the user. Earlier we shipped an internal
			// "auth_bound_unavailable" 500 here, but Codex CLI does not
			// have a branch for that code — it falls through to a
			// generic "high demand" toast, which hides the actual cause
			// (the bound credential ran out of quota) and leaves the
			// user with no idea why their conversation stopped working.
			// 429 + usage_limit_reached matches the body shape OpenAI
			// itself returns when a Plus account hits the 5h/weekly
			// cap, so the Codex CLI's existing UI handles it natively.
			// Message is emitted as already-valid JSON so the handler's
			// BuildErrorResponseBody passes it through untouched
			// instead of wrapping it in the generic rate_limit_error
			// shape.
			return nil, &Error{
				Code:        "usage_limit_reached",
				Message:     `{"error":{"type":"usage_limit_reached","message":"The bound credential for this conversation reached its usage limit. Start a new conversation to route to a different account."}}`,
				HTTPStatus:  http.StatusTooManyRequests,
				BoundAuthID: cachedAuthID,
			}
		}
		if mirrorKey != "" {
			s.cache.SetWithModel(mirrorKey, bound.ID, model)
		}
		// Distinguish a normal cache hit (auth fully available) from a
		// real bypass (auth is currently in cooldown / unavailable). The
		// bypass case is the interesting one for operators investigating
		// upstream blips; the normal case should look like the
		// non-strict cache-hit log to avoid alert noise.
		if blocked, _, _ := isAuthBlockedForModel(bound, model, now); blocked {
			entry.Infof("session-affinity: cache hit (strict, bypassing cooldown) | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), bound.ID, provider, model)
			// Signal to the conductor that this auth came back through
			// strict-bypass so filterExecutionModels skips per-model
			// cooldown filtering on it (the binding's whole point is
			// to keep using this credential through transient blips).
			markStrictBypass(ctx)
		} else {
			entry.Infof("session-affinity: cache hit | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), bound.ID, provider, model)
		}
		return bound, nil
	}

	availabilityCandidates := auths
	if _, weighted := s.fallback.(*WeightedRoundRobinSelector); weighted {
		availabilityCandidates = positiveWeightAuths(auths)
	}
	available, err := getAvailableAuths(ctx, availabilityCandidates, provider, model, now)
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
					s.cache.SetWithModel(mirrorKey, auth.ID, model)
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

	// Cache-miss path: hold the cache write lock across "count → fallback
	// pick → bind" so concurrent first-turn requests for different sessions
	// observe each other's claims. Without this, N simultaneous misses
	// would all see the same "watanabe has 0 bindings" snapshot and all
	// pick her, collapsing distribution. The lock-correctness primitive
	// lives on the cache (WithSelectionLock); we surface the snapshot to
	// the inner LeastBoundSelector via context so it ranks against the
	// freshly-captured counts.
	var (
		picked    *Auth
		pickErr   error
		raced     bool
		racedAuth string
	)
	s.cache.WithSelectionLock(func(bindings map[string]int, setLocked func(sessionID, authID string)) {
		// Re-check under lock: another goroutine may have just bound this
		// session between the GetAndRefresh above and now. If so, honour
		// the existing binding without churning a fresh fallback pick.
		if existing, ok := s.cache.peekLocked(cacheKey); ok {
			for _, auth := range auths {
				if auth == nil {
					continue
				}
				if auth.ID == existing {
					if blocked, _, _ := isAuthBlockedForModel(auth, model, now); !blocked {
						picked = auth
						raced = true
						racedAuth = auth.ID
						if mirrorKey != "" {
							setLocked(mirrorKey, auth.ID)
						}
						return
					}
				}
			}
		}

		childCtx := WithBindingSnapshot(ctx, bindings)
		auth, err := s.fallback.Pick(childCtx, provider, model, opts, auths)
		if err != nil {
			pickErr = err
			return
		}
		picked = auth
		setLocked(cacheKey, auth.ID)
		if mirrorKey != "" && mirrorKey != cacheKey {
			setLocked(mirrorKey, auth.ID)
		}
	})
	if pickErr != nil {
		return nil, pickErr
	}
	if raced {
		entry.Infof("session-affinity: cache miss raced (adopted concurrent bind) | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), racedAuth, provider, model)
		return picked, nil
	}
	entry.Infof("session-affinity: cache miss, new binding | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), picked.ID, provider, model)
	return picked, nil
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

// InvalidateAuthBindings removes all session bindings for a specific auth
// and returns how many cache entries were dropped. Used by the management
// "release" action: after an account hits its quota, releasing its
// bindings lets each stranded conversation re-pick a fresh account on its
// next turn (the quota selector excludes the exhausted account), without
// the client having to fork the conversation locally. Returns 0 when no
// cache is configured.
func (s *SessionAffinitySelector) InvalidateAuthBindings(authID string) int {
	if s == nil || s.cache == nil {
		return 0
	}
	return s.cache.InvalidateAuthCount(authID)
}

// InvalidateWindowBinding removes the cache rows for ONE conversation
// (uuid) but only while it is still bound to authID. This is the
// per-window counterpart of InvalidateAuthBindings: the management UI's
// bindings popup lets an operator drop a single stranded conversation
// instead of the account's whole binding set. The authID guard means
// stale popup data can never release a conversation that has since
// re-bound to a different account. Returns the number of rows removed
// (usually 1–2 per conversation — the thread key and its window
// mirror); 0 when the uuid isn't bound to that auth or no cache is
// configured.
func (s *SessionAffinitySelector) InvalidateWindowBinding(authID, uuid string) int {
	if s == nil || s.cache == nil {
		return 0
	}
	return s.cache.InvalidateWindowForAuth(authID, uuid)
}

// BindingsByAuthSnapshot returns the live session-cache contents
// grouped by auth_id. Used by the management endpoint that renders
// the bindings reverse-index panel. Nil-safe; returns nil when the
// selector has no cache configured.
func (s *SessionAffinitySelector) BindingsByAuthSnapshot() map[string][]BindingSnapshotEntry {
	if s == nil || s.cache == nil {
		return nil
	}
	return s.cache.SnapshotByAuth()
}

// extractCodexForkSignal returns (currentThreadID, forkedFromThreadID) from
// the X-Codex-Turn-Metadata header when both fields are present and
// non-empty. Real Codex VS Code emits `forked_from_thread_id` only on a
// turn that comes from `/new` (or from a sub-agent that branched off a
// parent thread); regular continuation turns leave the field unset.
//
// The pair is returned together because the selector needs both: the
// forked-from id identifies the OLD binding to close, and the current
// thread_id is recorded as the "forked_to" replacement on that closed
// entry — operators reading the bindings panel can then trace which
// new conversation supplanted each closed one.
//
// Defensive when self-referential or empty: returns ("", "") rather
// than risk closing a thread on its own fresh first turn.
func extractCodexForkSignal(headers http.Header) (string, string) {
	if headers == nil {
		return "", ""
	}
	meta := headers.Get("X-Codex-Turn-Metadata")
	if meta == "" {
		return "", ""
	}
	currentTid := strings.TrimSpace(gjson.Get(meta, "thread_id").String())
	forkedFrom := strings.TrimSpace(gjson.Get(meta, "forked_from_thread_id").String())
	if forkedFrom == "" {
		return currentTid, ""
	}
	if forkedFrom == currentTid {
		// A turn that claims to be forked from itself is malformed.
		// Ignore the signal rather than close a still-active thread.
		return currentTid, ""
	}
	return currentTid, forkedFrom
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

// StableSessionAnchor returns the most stable per-conversation key for a
// request — the one that does NOT drift once the first assistant reply appears.
// For explicit session signals (headers / conversation_id) it equals
// ExtractSessionID. For the message-content fallback it returns the
// system+first-user short hash (constant across EVERY turn) instead of the
// primary system+first-user+first-assistant hash, which only stabilizes from
// turn 2 onward. Callers that need a stable UPSTREAM cache key (e.g. Grok's
// x-grok-conv-id / prompt_cache_key) should use this rather than
// ExtractSessionID so the emitted key is identical on turn 1 and every turn
// after.
func StableSessionAnchor(headers http.Header, payload []byte, metadata map[string]any) string {
	primary, fallback, _ := extractSessionIDs(headers, payload, metadata)
	if fallback != "" {
		return fallback
	}
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

	// Scope the content hash by model. This is the fallback key for clients that
	// send no explicit session id (e.g. GitHub Copilot BYOK). Without the model
	// in the key, switching models mid-conversation keeps the previous binding,
	// so a conversation started on one model stays pinned to that model's
	// credential even after the client selects a different one — observed as
	// grok-4.5 requests being served by the grok2api openai-compat auth after
	// the client switched over from grok-4.5-g2a. Scope by BASE model so a
	// thinking-suffix change (grok-4.5(high) -> grok-4.5(low)) keeps one
	// binding, while a genuinely different model rebinds and re-picks.
	modelScope := strings.ToLower(strings.TrimSpace(thinking.ParseSuffix(gjson.GetBytes(payload, "model").String()).ModelName))

	shortHash := computeSessionHash(modelScope, systemPrompt, firstUserMsg, "")
	if firstAssistantMsg == "" {
		return shortHash, ""
	}

	fullHash := computeSessionHash(modelScope, systemPrompt, firstUserMsg, firstAssistantMsg)
	return fullHash, shortHash
}

func computeSessionHash(modelScope, systemPrompt, userMsg, assistantMsg string) string {
	h := fnv.New64a()
	if modelScope != "" {
		h.Write([]byte("mdl:" + modelScope + "\n"))
	}
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
