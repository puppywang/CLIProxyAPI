// Package monitor maintains an in-memory registry of in-flight HTTP requests
// so operators can observe current activity and cancel hung requests.
package monitor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Status enumerates the lifecycle states of a tracked request.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCanceling Status = "canceling"
	StatusFinished  Status = "finished"
	StatusCanceled  Status = "canceled"
)

// Transport enumerates how the client speaks to CPA. WebSocket upgrades on
// long-lived endpoints (e.g. /v1/responses) report "ws" so operators can
// distinguish them from one-shot HTTP+SSE calls.
const (
	TransportHTTP = "http"
	TransportWS   = "ws"
)

// Entry holds a snapshot-friendly view of a single in-flight request.
type Entry struct {
	ID            string    `json:"id"`
	Method        string    `json:"method"`
	Transport     string    `json:"transport,omitempty"`
	Path          string    `json:"path"`
	ClientIP      string    `json:"client_ip"`
	UserAgent     string    `json:"user_agent,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	Model         string    `json:"model,omitempty"`
	AuthID        string    `json:"auth_id,omitempty"`
	AuthLabel     string    `json:"auth_label,omitempty"`
	Provider      string    `json:"provider,omitempty"`
	AuthProxy     string    `json:"auth_proxy,omitempty"`
	Streaming     bool      `json:"streaming"`
	RequestBytes  int64     `json:"request_bytes"`
	ResponseBytes int64     `json:"response_bytes"`
	Status        Status    `json:"status"`
	StatusCode    int       `json:"status_code,omitempty"`
	LastActivity  time.Time `json:"last_activity"`
	DurationMs    int64     `json:"duration_ms"`
	CanceledBy    string    `json:"canceled_by,omitempty"`
	CanceledAt    time.Time `json:"canceled_at,omitempty"`
	FirstChunkAt  time.Time `json:"first_chunk_at,omitempty"`
	InputTokens   int64     `json:"input_tokens,omitempty"`
	OutputTokens  int64     `json:"output_tokens,omitempty"`
	TotalTokens   int64     `json:"total_tokens,omitempty"`

	// Window / conversation metadata extracted from request headers
	// (currently X-Codex-Turn-Metadata for Codex clients, with fallbacks
	// for Session-Id / Thread-Id / X-Client-Request-Id). All four are
	// optional — non-Codex traffic leaves them empty. Used by the
	// operator UI to correlate parallel requests within a single window
	// (main thread + sub-agents) so it's visible when sub-agents
	// accidentally split across credentials.
	SessionID    string `json:"session_id,omitempty"`
	ThreadID     string `json:"thread_id,omitempty"`
	TurnID       string `json:"turn_id,omitempty"`
	ThreadSource string `json:"thread_source,omitempty"`

	// Workspace is the client's reported current working directory,
	// extracted from the Codex CLI environment_context block in the
	// request body (<cwd>…</cwd>). Optional — empty for non-Codex
	// clients or for requests without an environment_context payload.
	// The UI ellipsis-truncates the path to its trailing segment(s)
	// and shows the full value on hover.
	Workspace string `json:"workspace,omitempty"`
}

// trackedRequest is the mutable runtime representation behind a registry entry.
type trackedRequest struct {
	id            string
	method        string
	transport     string
	path          string
	clientIP      string
	userAgent     string
	startedAt     time.Time
	requestBytes  atomic.Int64
	streaming     atomic.Bool
	responseBytes atomic.Int64
	statusCode    atomic.Int32
	lastActivity  atomic.Int64
	lastBroadcast atomic.Int64
	firstChunkAt  atomic.Int64
	inputTokens   atomic.Int64
	outputTokens  atomic.Int64
	totalTokens   atomic.Int64

	mu           sync.RWMutex
	model        string
	authID       string
	authLabel    string
	provider     string
	authProxy    string
	status       Status
	cancel       context.CancelFunc
	canceledBy   string
	canceledAt   time.Time
	sessionID    string
	threadID     string
	turnID       string
	threadSource string
	workspace    string
}

func (t *trackedRequest) snapshot() Entry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	last := time.Unix(0, t.lastActivity.Load())
	if last.IsZero() {
		last = t.startedAt
	}
	var firstChunk time.Time
	if fc := t.firstChunkAt.Load(); fc > 0 {
		firstChunk = time.Unix(0, fc)
	}
	return Entry{
		ID:            t.id,
		Method:        t.method,
		Transport:     t.transport,
		Path:          t.path,
		ClientIP:      t.clientIP,
		UserAgent:     t.userAgent,
		StartedAt:     t.startedAt,
		Model:         t.model,
		AuthID:        t.authID,
		AuthLabel:     t.authLabel,
		Provider:      t.provider,
		AuthProxy:     t.authProxy,
		Streaming:     t.streaming.Load(),
		RequestBytes:  t.requestBytes.Load(),
		ResponseBytes: t.responseBytes.Load(),
		Status:        t.status,
		StatusCode:    int(t.statusCode.Load()),
		LastActivity:  last,
		DurationMs:    time.Since(t.startedAt).Milliseconds(),
		CanceledBy:    t.canceledBy,
		CanceledAt:    t.canceledAt,
		FirstChunkAt:  firstChunk,
		InputTokens:   t.inputTokens.Load(),
		OutputTokens:  t.outputTokens.Load(),
		TotalTokens:   t.totalTokens.Load(),
		SessionID:     t.sessionID,
		ThreadID:      t.threadID,
		TurnID:        t.turnID,
		ThreadSource:  t.threadSource,
		Workspace:     t.workspace,
	}
}

// AuthLookup is an optional callback that enriches an auth ID with a
// human-friendly label, the upstream provider name, and the outbound proxy
// URL (display form — must already be sanitised of credentials). The
// Registry tolerates a nil lookup.
type AuthLookup func(authID string) (label string, provider string, proxy string, ok bool)

// AuthBytesRecorder reports the request body size against the named auth.
// The cliproxy Service wires this to LeastRemainingQuotaSelector's
// RecordRequestBytes so the next CombinedQuotaScore reflects in-flight
// volume that wham/usage has not yet absorbed. Optional — pools without
// the codex quota subsystem skip the hookup. Invoked exactly once per
// request (at SetAuth time), so callers must NOT call it again for the
// same request on byte-count updates.
type AuthBytesRecorder func(authID string, bytes int64)

// Registry is the central in-memory tracker of all in-flight requests.
type Registry struct {
	mu            sync.RWMutex
	entries       map[string]*trackedRequest
	subscribers   map[chan Event]struct{}
	authLookup    AuthLookup
	bytesRecorder AuthBytesRecorder

	settings  *SettingsStore
	history   *historyRing
	histLog   *historyLog
	errors    *errorsRing
	errorsLog *errorsLog

	// sessionWorkspaces remembers the last observed `<cwd>` value per
	// session_id, independent of any tracked request lifetime. In-flight
	// entries are removed 5 seconds after Finish, so a panel that wants
	// to display "binding X belongs to workspace Y" would otherwise lose
	// the link as soon as the conversation goes idle. Capping prevents
	// unbounded growth — the session cache enforces a TTL too, so any
	// entry past `sessionWorkspaceMax` is FIFO-evicted at insertion
	// time.
	sessionWorkspacesMu sync.RWMutex
	sessionWorkspaces   map[string]string
	sessionWorkspaceOrd []string
}

// sessionWorkspaceMax caps the in-memory session-id → workspace map.
// Sized comfortably above any plausible session-affinity cache TTL
// throughput (a few thousand bindings per 6h is the upper bound for
// the current production pool).
const sessionWorkspaceMax = 4096

// Event is the message broadcast to SSE subscribers.
type Event struct {
	Type  string `json:"type"` // "added" | "updated" | "removed" | "snapshot"
	Entry Entry  `json:"entry,omitempty"`
	// Critical events MUST reach subscribers even when their channels are
	// momentarily full (state transitions, removals). Byte/token counter
	// updates remain best-effort and may be dropped under load.
	Critical bool `json:"-"`
}

// subscriberChannelBuffer sizes the per-subscriber event buffer. A large
// buffer keeps high-frequency byte/token updates from displacing state
// transitions; critical events have additional protection via blocking
// delivery (see broadcast).
const subscriberChannelBuffer = 256

// criticalBroadcastTimeout is the per-subscriber grace period for delivering
// a Critical event when its channel is full. Beyond this, the event is
// dropped to prevent the watcher / handler goroutines from blocking on a
// disconnected client.
const criticalBroadcastTimeout = 250 * time.Millisecond

// NewRegistry constructs an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		entries:           make(map[string]*trackedRequest),
		subscribers:       make(map[chan Event]struct{}),
		sessionWorkspaces: make(map[string]string),
		history:           newHistoryRing(200),
		errors:            newErrorsRing(200),
	}
}

// AttachSettings wires a settings store so the watcher can read live values.
func (r *Registry) AttachSettings(store *SettingsStore) {
	r.mu.Lock()
	r.settings = store
	r.mu.Unlock()
}

// AttachHistoryLog wires a JSONL writer that records every cancellation.
func (r *Registry) AttachHistoryLog(path string) {
	r.mu.Lock()
	r.histLog = newHistoryLog(path)
	r.mu.Unlock()
}

// AttachErrorsLog wires a JSONL writer that persists every non-2xx
// outcome captured by maybeRecordError. On attach, the most recent
// `errors.capacity` lines are streamed back into the ring buffer so
// the "Errors" panel survives CPA restarts. Writes are best-effort —
// a failed append never blocks the request lifecycle.
func (r *Registry) AttachErrorsLog(path string) {
	r.mu.Lock()
	r.errorsLog = newErrorsLog(path)
	ring := r.errors
	r.mu.Unlock()
	if ring == nil {
		return
	}
	// Replay the on-disk tail into the in-memory ring so the panel is
	// populated before the first request lands.
	replay := r.errorsLog.loadRecent(ring.capacity)
	for _, rec := range replay {
		ring.add(rec)
	}
}

// Settings returns the live settings snapshot or zero values when no store is attached.
func (r *Registry) Settings() Settings {
	r.mu.RLock()
	store := r.settings
	r.mu.RUnlock()
	if store == nil {
		return Settings{}
	}
	return store.Get()
}

// UpdateSettings replaces the persisted settings and returns the resulting values.
func (r *Registry) UpdateSettings(s Settings) (Settings, error) {
	r.mu.RLock()
	store := r.settings
	r.mu.RUnlock()
	if store == nil {
		return Settings{}, fmt.Errorf("settings store not attached")
	}
	if err := store.Set(s); err != nil {
		return store.Get(), err
	}
	return store.Get(), nil
}

// History returns the most recent cancellation records (newest first).
func (r *Registry) History(limit int) []CancelRecord {
	r.mu.RLock()
	hist := r.history
	r.mu.RUnlock()
	if hist == nil {
		return nil
	}
	return hist.recent(limit)
}

// RecentErrors returns the most recent non-2xx outcomes (newest first).
// Records are captured at Finish time and survive after the entry's
// terminal-linger window expires, so operators can investigate failures
// that happened minutes earlier even if the live in-flight list has
// since been cleared.
func (r *Registry) RecentErrors(limit int) []ErrorRecord {
	r.mu.RLock()
	er := r.errors
	r.mu.RUnlock()
	if er == nil {
		return nil
	}
	return er.recent(limit)
}

// SetAuthLookup installs (or replaces) the auth enrichment callback.
func (r *Registry) SetAuthLookup(lookup AuthLookup) {
	r.mu.Lock()
	r.authLookup = lookup
	r.mu.Unlock()
}

// SetBytesRecorder installs (or replaces) the per-auth request bytes
// recorder. Invoked exactly once when SetAuth fires for a request,
// with the request body size captured at Register time. The cliproxy
// Service wires this to the LeastRemainingQuotaSelector so the next
// pick reflects volume not yet absorbed by wham/usage.
func (r *Registry) SetBytesRecorder(rec AuthBytesRecorder) {
	r.mu.Lock()
	r.bytesRecorder = rec
	r.mu.Unlock()
}

// Register inserts a new in-flight entry and returns its tracker handle.
// transport identifies the client-side wire (TransportHTTP / TransportWS);
// pass an empty string to default to HTTP.
func (r *Registry) Register(id, method, transport, path, clientIP, userAgent string, requestBytes int64, cancel context.CancelFunc) *trackedRequest {
	if transport == "" {
		transport = TransportHTTP
	}
	now := time.Now()
	t := &trackedRequest{
		id:        id,
		method:    method,
		transport: transport,
		path:      path,
		clientIP:  clientIP,
		userAgent: userAgent,
		startedAt: now,
		status:    StatusRunning,
		cancel:    cancel,
	}
	t.requestBytes.Store(requestBytes)
	t.lastActivity.Store(now.UnixNano())

	r.mu.Lock()
	r.entries[id] = t
	r.mu.Unlock()

	r.broadcast(Event{Type: "added", Entry: t.snapshot()})
	return t
}

// RegisterHandle creates a new tracked entry and returns its externally usable
// Handle. This is the public entry point for callers outside the monitor
// package (e.g. a WebSocket handler that wants to map each logical frame to
// its own entry).
func (r *Registry) RegisterHandle(id, method, transport, path, clientIP, userAgent string, requestBytes int64, cancel context.CancelFunc) *Handle {
	t := r.Register(id, method, transport, path, clientIP, userAgent, requestBytes, cancel)
	return &Handle{r: r, t: t}
}

// Remove deletes an entry from the registry and notifies subscribers.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	t, ok := r.entries[id]
	if ok {
		delete(r.entries, id)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	r.broadcast(Event{Type: "removed", Entry: t.snapshot(), Critical: true})
}

// removeIfSame deletes the entry only when the slot still points at the
// provided tracker. This guards against a vanishingly small ID-collision
// window where a new Register has replaced the entry between Finish's
// schedule call and the AfterFunc firing.
func (r *Registry) removeIfSame(id string, want *trackedRequest) {
	r.mu.Lock()
	cur, ok := r.entries[id]
	if !ok || cur != want {
		r.mu.Unlock()
		return
	}
	delete(r.entries, id)
	r.mu.Unlock()
	r.broadcast(Event{Type: "removed", Entry: want.snapshot(), Critical: true})
}

// Snapshot returns a copy of all current entries ordered by start time descending.
func (r *Registry) Snapshot() []Entry {
	r.mu.RLock()
	entries := make([]Entry, 0, len(r.entries))
	for _, t := range r.entries {
		entries = append(entries, t.snapshot())
	}
	r.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].StartedAt.After(entries[j].StartedAt)
	})
	return entries
}

// Cancel triggers cancellation of the tracked request. The reason is recorded
// in the cancellation history. The bool result reports whether a matching
// entry was found and was actually transitioned (already-finished entries
// return false).
func (r *Registry) Cancel(id, by, reason string) bool {
	r.mu.RLock()
	t, ok := r.entries[id]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	t.mu.Lock()
	if t.status == StatusFinished || t.status == StatusCanceled || t.status == StatusCanceling {
		t.mu.Unlock()
		return false
	}
	t.status = StatusCanceling
	t.canceledBy = by
	t.canceledAt = time.Now()
	cancel := t.cancel
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	snap := t.snapshot()
	r.recordCancel(snap, reason, by)
	r.broadcast(Event{Type: "updated", Entry: snap, Critical: true})
	return true
}

// maybeRecordError pushes the snapshot into the recent-errors ring if
// the terminal outcome qualifies as a failure. We treat status codes
// in [400, 600) as errors, plus the canceled/canceling states
// (regardless of status), plus the "never wrote a status" case which
// usually means the connection dropped or the executor returned
// before any response could be written. Genuinely successful 2xx
// outcomes — and the "no error and no status, but status set" edge
// case via 304 — are ignored.
func (r *Registry) maybeRecordError(snap Entry) {
	reason := classifyErrorReason(snap)
	if reason == "" {
		return
	}
	r.mu.RLock()
	er := r.errors
	logger := r.errorsLog
	r.mu.RUnlock()
	if er == nil {
		return
	}
	rec := ErrorRecord{
		Entry:      snap,
		StatusCode: snap.StatusCode,
		Reason:     reason,
		RecordedAt: time.Now(),
	}
	er.add(rec)
	// Persist after the ring update so an append failure cannot keep
	// the record out of the live panel — operator visibility wins
	// over durability when the two diverge.
	logger.append(rec)
}

// classifyErrorReason returns a short tag describing why an entry is
// considered an error, or "" if the outcome is normal.
func classifyErrorReason(snap Entry) string {
	switch snap.Status {
	case StatusCanceled, StatusCanceling:
		return "canceled"
	}
	code := snap.StatusCode
	if code >= 400 && code < 600 {
		switch {
		case code == 401, code == 403:
			return "auth"
		case code == 429:
			return "quota"
		case code >= 500:
			return "upstream_5xx"
		default:
			return "client_4xx"
		}
	}
	if code == 0 && snap.Status == StatusFinished {
		// Finished without ever writing a status line — typically a
		// connection drop or an internal short-circuit before any
		// response went out. Worth surfacing.
		return "no_status"
	}
	return ""
}

func (r *Registry) recordCancel(snap Entry, reason, by string) {
	if reason == "" {
		reason = ReasonManual
	}
	rec := CancelRecord{
		Entry:      snap,
		Reason:     reason,
		CanceledBy: by,
		CanceledAt: time.Now(),
	}
	r.mu.RLock()
	hist := r.history
	log := r.histLog
	r.mu.RUnlock()
	if hist != nil {
		hist.add(rec)
	}
	if log != nil {
		log.append(rec)
	}
}

// SetTurnMetadata records the per-conversation identifiers extracted
// from request headers. session_id is window-stable; thread_id changes
// per /new and per sub-agent invocation; turn_id changes per message.
// All inputs are optional — empty values do not overwrite existing
// non-empty fields, so a malformed second header cannot erase context
// that was successfully captured at registration. The same call also
// touches the entry's last-activity timestamp and broadcasts an
// update so live UI listeners see the metadata appear.
func (r *Registry) SetTurnMetadata(t *trackedRequest, sessionID, threadID, turnID, threadSource string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	changed := false
	if sessionID != "" && t.sessionID != sessionID {
		t.sessionID = sessionID
		changed = true
	}
	if threadID != "" && t.threadID != threadID {
		t.threadID = threadID
		changed = true
	}
	if turnID != "" && t.turnID != turnID {
		t.turnID = turnID
		changed = true
	}
	if threadSource != "" && t.threadSource != threadSource {
		t.threadSource = threadSource
		changed = true
	}
	t.mu.Unlock()
	if !changed {
		return
	}
	r.touch(t)
	r.broadcast(Event{Type: "updated", Entry: t.snapshot()})
}

// SetModel updates the requested model identifier for an entry.
func (r *Registry) SetModel(t *trackedRequest, model string) {
	if t == nil || model == "" {
		return
	}
	t.mu.Lock()
	if t.model == model {
		t.mu.Unlock()
		return
	}
	t.model = model
	t.mu.Unlock()
	r.touch(t)
	r.broadcast(Event{Type: "updated", Entry: t.snapshot()})
}

// SetWorkspace records the client's reported current working directory
// (typically extracted from a Codex CLI <cwd>…</cwd> tag). Empty input
// does NOT overwrite an existing non-empty value, mirroring the
// SetTurnMetadata pattern: a malformed follow-up request cannot erase
// context that was already captured.
func (r *Registry) SetWorkspace(t *trackedRequest, workspace string) {
	if t == nil || workspace == "" {
		return
	}
	t.mu.Lock()
	if t.workspace == workspace {
		t.mu.Unlock()
		return
	}
	t.workspace = workspace
	t.mu.Unlock()
	r.touch(t)
	r.broadcast(Event{Type: "updated", Entry: t.snapshot()})
}

// RecordSessionWorkspace remembers the workspace path observed for a
// given session_id, outside the per-entry tracking lifetime. The
// Bindings reverse-index endpoint uses this to render the workspace
// next to each cached session binding (which long-outlives any single
// in-flight Entry). FIFO-evicts the oldest entry when sessionWorkspaceMax
// is exceeded.
func (r *Registry) RecordSessionWorkspace(sessionID, workspace string) {
	if r == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	workspace = strings.TrimSpace(workspace)
	if sessionID == "" || workspace == "" {
		return
	}
	r.sessionWorkspacesMu.Lock()
	defer r.sessionWorkspacesMu.Unlock()
	if existing, ok := r.sessionWorkspaces[sessionID]; ok {
		if existing == workspace {
			return
		}
		// Same key, value changed (e.g., user reopened a different
		// workspace in the same chat panel) — overwrite, keep its
		// position in the ord slice unchanged so eviction stays FIFO
		// over the original insertion order.
		r.sessionWorkspaces[sessionID] = workspace
		return
	}
	if len(r.sessionWorkspaceOrd) >= sessionWorkspaceMax {
		oldest := r.sessionWorkspaceOrd[0]
		r.sessionWorkspaceOrd = r.sessionWorkspaceOrd[1:]
		delete(r.sessionWorkspaces, oldest)
	}
	r.sessionWorkspaces[sessionID] = workspace
	r.sessionWorkspaceOrd = append(r.sessionWorkspaceOrd, sessionID)
}

// SessionWorkspaceSnapshot returns a copy of the entire session-id →
// workspace map. Safe for the caller to retain and mutate.
func (r *Registry) SessionWorkspaceSnapshot() map[string]string {
	if r == nil {
		return nil
	}
	r.sessionWorkspacesMu.RLock()
	defer r.sessionWorkspacesMu.RUnlock()
	out := make(map[string]string, len(r.sessionWorkspaces))
	for k, v := range r.sessionWorkspaces {
		out[k] = v
	}
	return out
}

// SetAuth updates the selected auth identifier and enriches label, provider,
// and outbound proxy from the configured AuthLookup.
func (r *Registry) SetAuth(t *trackedRequest, authID string) {
	if t == nil || authID == "" {
		return
	}
	r.mu.RLock()
	lookup := r.authLookup
	recorder := r.bytesRecorder
	r.mu.RUnlock()

	label, provider, proxy := "", "", ""
	if lookup != nil {
		if l, p, prox, ok := lookup(authID); ok {
			label = l
			provider = p
			proxy = prox
		}
	}

	t.mu.Lock()
	alreadySet := t.authID == authID
	if alreadySet && t.authLabel == label && t.provider == provider && t.authProxy == proxy {
		t.mu.Unlock()
		return
	}
	t.authID = authID
	if label != "" {
		t.authLabel = label
	}
	if provider != "" {
		t.provider = provider
	}
	// proxy is always assigned (may be empty if the auth has no proxy_url),
	// otherwise removing a proxy at runtime wouldn't show up here.
	t.authProxy = proxy
	t.mu.Unlock()

	// Record the request body size against this auth's local quota
	// counter — once per request, gated on alreadySet so a stream/retry
	// that lands on the same credential doesn't double-charge. We pull
	// requestBytes from the atomic counter (filled at Register time from
	// Content-Length).
	if !alreadySet && recorder != nil {
		if n := t.requestBytes.Load(); n > 0 {
			recorder(authID, n)
		}
	}
	r.touch(t)
	r.broadcast(Event{Type: "updated", Entry: t.snapshot()})
}

// byteBroadcastInterval throttles how often byte-count updates are pushed to
// SSE subscribers per entry. The internal counter remains accurate; this only
// controls the broadcast cadence.
const byteBroadcastInterval = 500 * time.Millisecond

// AddResponseBytes increments the response byte counter for an entry. To keep
// SSE traffic reasonable while still surfacing real-time growth, an "updated"
// event is broadcast at most once per byteBroadcastInterval per entry.
func (r *Registry) AddResponseBytes(t *trackedRequest, n int) {
	if t == nil || n <= 0 {
		return
	}
	t.responseBytes.Add(int64(n))
	r.touch(t)

	now := time.Now().UnixNano()
	last := t.lastBroadcast.Load()
	if now-last >= int64(byteBroadcastInterval) {
		if t.lastBroadcast.CompareAndSwap(last, now) {
			r.broadcast(Event{Type: "updated", Entry: t.snapshot()})
		}
	}
}

// SetStreaming records whether the response is detected as streaming.
func (r *Registry) SetStreaming(t *trackedRequest, streaming bool) {
	if t == nil {
		return
	}
	prev := t.streaming.Swap(streaming)
	if prev != streaming {
		r.broadcast(Event{Type: "updated", Entry: t.snapshot()})
	}
}

// SetStatusCode records the HTTP status code observed for the response.
func (r *Registry) SetStatusCode(t *trackedRequest, code int) {
	if t == nil || code <= 0 {
		return
	}
	t.statusCode.Store(int32(code))
}

// terminalLingerDuration keeps finished/canceled entries visible briefly so
// operators can see the outcome before they disappear from the list.
const terminalLingerDuration = 5 * time.Second

// Finish marks an entry as completed. The entry briefly lingers in the
// registry (in finished/canceled state) before being removed, so the UI can
// surface the terminal outcome.
func (r *Registry) Finish(t *trackedRequest) {
	if t == nil {
		return
	}
	t.mu.Lock()
	switch t.status {
	case StatusCanceling, StatusCanceled:
		t.status = StatusCanceled
	default:
		t.status = StatusFinished
	}
	id := t.id
	t.mu.Unlock()

	// Capture any non-2xx outcome in the recent-errors ring before
	// broadcasting the terminal state. Done here (rather than at the
	// remove timer) so the record exists as soon as the failure is
	// visible to the UI, and so the operator can correlate the live
	// entry with the persisted record. Status 0 means the response
	// never produced a status line — typically a client cancel or a
	// connection drop before any reply.
	snap := t.snapshot()
	r.maybeRecordError(snap)

	// Push the terminal status so SSE subscribers see the final state. This
	// transition must not be dropped under load — operators rely on it to
	// know the request actually ended.
	r.broadcast(Event{Type: "updated", Entry: snap, Critical: true})

	// Linger before removing so operators can see the outcome. removeIfSame
	// guards against the unlikely case where a new Register has overwritten
	// this slot before the timer fires.
	time.AfterFunc(terminalLingerDuration, func() {
		r.removeIfSame(id, t)
	})
}

func (r *Registry) touch(t *trackedRequest) {
	if t == nil {
		return
	}
	t.lastActivity.Store(time.Now().UnixNano())
}

// Subscribe registers a new SSE listener. The returned channel receives a
// "snapshot" event for each currently tracked entry, followed by live updates.
// The caller must invoke the returned cancel function to release resources.
func (r *Registry) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subscriberChannelBuffer)
	r.mu.Lock()
	r.subscribers[ch] = struct{}{}
	snapshot := make([]*trackedRequest, 0, len(r.entries))
	for _, t := range r.entries {
		snapshot = append(snapshot, t)
	}
	r.mu.Unlock()

	go func() {
		for _, t := range snapshot {
			ch <- Event{Type: "snapshot", Entry: t.snapshot()}
		}
	}()

	cancel := func() {
		r.mu.Lock()
		if _, ok := r.subscribers[ch]; ok {
			delete(r.subscribers, ch)
			close(ch)
		}
		r.mu.Unlock()
	}
	return ch, cancel
}

func (r *Registry) broadcast(ev Event) {
	r.mu.RLock()
	subs := make([]chan Event, 0, len(r.subscribers))
	for ch := range r.subscribers {
		subs = append(subs, ch)
	}
	r.mu.RUnlock()
	if ev.Critical {
		// Deliver critical events from a goroutine so a slow subscriber cannot
		// block the watcher / handler goroutine that triggered the state
		// transition. Each subscriber still has a bounded grace period.
		go func(subs []chan Event, ev Event) {
			for _, ch := range subs {
				select {
				case ch <- ev:
				case <-time.After(criticalBroadcastTimeout):
					// Subscriber is gone or too slow; the periodic UI refresh
					// will reconcile state when it catches up.
				}
			}
		}(subs, ev)
		return
	}
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			// Drop if the subscriber is too slow; the next snapshot fixes drift.
		}
	}
}
