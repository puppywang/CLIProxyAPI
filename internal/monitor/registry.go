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

	log "github.com/sirupsen/logrus"
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
	// BodyReceiveMs is how long the request body took to arrive off the wire
	// (from request arrival to the body's EOF). It exposes the previously
	// invisible upload phase — for slow client connections this can be tens
	// of seconds. ReceivingBody is true while the body is still arriving.
	BodyReceiveMs int64 `json:"body_receive_ms,omitempty"`
	ReceivingBody bool  `json:"receiving_body,omitempty"`
	// BodyReceivedBytes is how many request-body bytes have arrived so far.
	// With BodyReceiveMs it yields the (live) upload speed; a partial count
	// while ReceivingBody, otherwise the full body size.
	BodyReceivedBytes int64     `json:"body_received_bytes,omitempty"`
	CanceledBy        string    `json:"canceled_by,omitempty"`
	CanceledAt        time.Time `json:"canceled_at,omitempty"`
	FirstChunkAt      time.Time `json:"first_chunk_at,omitempty"`
	// SlowWindowBytes is the response-byte delta observed in the rolling
	// window that tripped the slow-stream watchdog. Only meaningful on a
	// ReasonSlow cancellation; zero/omitted otherwise.
	SlowWindowBytes int64 `json:"slow_window_bytes,omitempty"`
	InputTokens     int64 `json:"input_tokens,omitempty"`
	OutputTokens    int64 `json:"output_tokens,omitempty"`
	TotalTokens     int64 `json:"total_tokens,omitempty"`

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
	// ErrorSnippet is a bounded prefix of the error response body, captured
	// only for >=400 outcomes. It lets the operator see WHY a request failed
	// (e.g. "unknown provider for model X", context_too_large, engine
	// overloaded) directly in the monitor instead of digging through logs.
	ErrorSnippet string `json:"error_snippet,omitempty"`
	// StreamFailure describes a failure that happened AFTER the response
	// status line was already written — an SSE/WebSocket stream that errored
	// or ended before its terminal event. The HTTP status is stuck at 200 in
	// that case, so without this the outcome is indistinguishable from a
	// clean success (observed: codex reporting "stream disconnected before
	// completion" for requests the monitor showed as 200 OK).
	StreamFailure string `json:"stream_failure,omitempty"`
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
	// slowAnchorAt / slowAnchorBytes are the rolling-window baseline for the
	// slow-stream throughput watchdog. They are read and written exclusively
	// by the single watcher goroutine (scanStalled), so their pairing needs
	// no cross-field locking; atomics keep them race-free against any future
	// reader. Zero slowAnchorAt means "not yet anchored".
	slowAnchorAt    atomic.Int64
	slowAnchorBytes atomic.Int64
	// slowWindowBytes records the window delta that tripped the slow-stream
	// watchdog, captured just before Cancel so it lands in the snapshot.
	slowWindowBytes atomic.Int64
	inputTokens     atomic.Int64
	outputTokens    atomic.Int64
	totalTokens     atomic.Int64

	mu            sync.RWMutex
	model         string
	authID        string
	authLabel     string
	provider      string
	authProxy     string
	status        Status
	cancel        context.CancelFunc
	canceledBy    string
	canceledAt    time.Time
	sessionID     string
	threadID      string
	turnID        string
	threadSource  string
	workspace     string
	errorSnippet  string
	streamFailure string
	// bodyTiming measures how long the request body took to arrive. Set once
	// by the monitor middleware right after Register; read in snapshot().
	bodyTiming *bodyTimer
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
	var bodyReceiveMs, bodyReceivedBytes int64
	var receivingBody bool
	if t.bodyTiming != nil {
		ms, done := t.bodyTiming.receiveMillis(time.Now())
		bodyReceiveMs = ms
		receivingBody = !done
		bodyReceivedBytes = t.bodyTiming.received()
	}
	// Chunked request bodies (Content-Length: -1 — e.g. GitHub Copilot Chat)
	// never populate requestBytes at registration time. Fall back to the
	// body timer's measured byte count so the UI doesn't show "0 B" for a
	// 1.4 MB upload. Content-Length-known requests keep their declared size.
	reqBytes := t.requestBytes.Load()
	if reqBytes <= 0 && bodyReceivedBytes > 0 {
		reqBytes = bodyReceivedBytes
	}
	return Entry{
		ID:                t.id,
		Method:            t.method,
		Transport:         t.transport,
		Path:              t.path,
		ClientIP:          t.clientIP,
		UserAgent:         t.userAgent,
		StartedAt:         t.startedAt,
		Model:             t.model,
		AuthID:            t.authID,
		AuthLabel:         t.authLabel,
		Provider:          t.provider,
		AuthProxy:         t.authProxy,
		Streaming:         t.streaming.Load(),
		RequestBytes:      reqBytes,
		ResponseBytes:     t.responseBytes.Load(),
		Status:            t.status,
		StatusCode:        int(t.statusCode.Load()),
		LastActivity:      last,
		DurationMs:        time.Since(t.startedAt).Milliseconds(),
		BodyReceiveMs:     bodyReceiveMs,
		ReceivingBody:     receivingBody,
		BodyReceivedBytes: bodyReceivedBytes,
		CanceledBy:        t.canceledBy,
		CanceledAt:        t.canceledAt,
		FirstChunkAt:      firstChunk,
		SlowWindowBytes:   t.slowWindowBytes.Load(),
		InputTokens:       t.inputTokens.Load(),
		OutputTokens:      t.outputTokens.Load(),
		TotalTokens:       t.totalTokens.Load(),
		SessionID:         t.sessionID,
		ThreadID:          t.threadID,
		TurnID:            t.turnID,
		ThreadSource:      t.threadSource,
		Workspace:         t.workspace,
		ErrorSnippet:      t.errorSnippet,
		StreamFailure:     t.streamFailure,
	}
}

// isReceivingBody reports whether the request body is still arriving (timer
// attached, no EOF yet). Used by the watcher to push live upload progress.
func (t *trackedRequest) isReceivingBody() bool {
	t.mu.RLock()
	bt := t.bodyTiming
	t.mu.RUnlock()
	return bt != nil && !bt.done()
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

	// zenReasoningRejections counts 400 "reasoning_content must be passed
	// back" rejections (classified reason zen_reasoning_400). Surface as a
	// live alert counter on the monitor panel; reset by ZenReasoningAlertReset.
	zenReasoningRejections atomic.Int64

	// quotaHistory retains per-auth quota samples so the quota panel can draw
	// a usage curve (and show what an account peaked at before a reset).
	quotaHistory *quotaHistoryStore

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

// AttachHistoryLog wires a JSONL writer that records every cancellation. On
// attach, the most recent `history.capacity` lines are streamed back into the
// ring buffer so the "Recent cancellations" panel survives CPA restarts,
// matching AttachErrorsLog's behaviour (previously only the errors panel
// replayed, so cancellations appeared to vanish on every restart).
func (r *Registry) AttachHistoryLog(path string) {
	r.mu.Lock()
	r.histLog = newHistoryLog(path)
	ring := r.history
	r.mu.Unlock()
	if ring == nil {
		return
	}
	replay := r.histLog.loadRecent(ring.capacity)
	for _, rec := range replay {
		ring.add(rec)
	}
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

// ZenReasoningRejections returns the live counter of DeepSeek thinking-mode
// "reasoning_content must be passed back" 400 rejections (reason tag
// zen_reasoning_400) since the last reset. A non-zero value on a healthy
// session means client histories are still dropping reasoning_content.
func (r *Registry) ZenReasoningRejections() int64 {
	if r == nil {
		return 0
	}
	return r.zenReasoningRejections.Load()
}

// ZenReasoningAlertReset zeroes the zen reasoning rejection counter, e.g.
// after the root cause is addressed or a fix is deployed.
func (r *Registry) ZenReasoningAlertReset() {
	if r == nil {
		return
	}
	r.zenReasoningRejections.Store(0)
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
	if reason == "zen_reasoning_400" {
		total := r.zenReasoningRejections.Add(1)
		log.WithFields(log.Fields{
			"request_id": snap.ID,
			"model":      snap.Model,
			"auth_id":    snap.AuthID,
			"provider":   snap.Provider,
		}).Warnf("zen reasoning_content rejection #%d: DeepSeek thinking-mode gate refuses assistant tool_calls resent without reasoning_content (see monitor reason zen_reasoning_400)", total)
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
		case code == 400 && isZenReasoningRejection(snap.ErrorSnippet):
			// DeepSeek thinking-mode gate: a tool-calling assistant turn was
			// resent without its reasoning_content. Surface it as its own
			// reason so the operator can correlate these with Copilot
			// sessions that fail repeatedly on the same history shape.
			return "zen_reasoning_400"
		case code >= 500:
			return "upstream_5xx"
		default:
			return "client_4xx"
		}
	}
	if snap.StreamFailure != "" {
		// Status line already sent (typically 200) but the stream never
		// completed — the failure is invisible to the status code alone.
		return "stream_incomplete"
	}
	if code == 0 && snap.Status == StatusFinished {
		// Finished without ever writing a status line — typically a
		// connection drop or an internal short-circuit before any
		// response went out. Worth surfacing.
		return "no_status"
	}
	return ""
}

// isZenReasoningRejection reports whether the error snippet is the
// DeepSeek thinking-mode "reasoning_content must be passed back" 400.
func isZenReasoningRejection(snippet string) bool {
	if snippet == "" {
		return false
	}
	lower := strings.ToLower(snippet)
	return strings.Contains(lower, "reasoning_content") && strings.Contains(lower, "must be passed back")
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
	switch reason {
	case ReasonStall:
		rec.Detail = stallDetail(snap, rec.CanceledAt)
	case ReasonSlow:
		s := r.Settings()
		rec.Detail = slowDetail(snap, rec.CanceledAt, s.SlowWindowSeconds, s.SlowMinBytes)
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

// stallDetail builds the human-readable "specific situation" recorded on a
// stall cancellation. It distinguishes the two cases the watchdog covers:
//
//   - initial wait: the upstream produced no response bytes at all before
//     the stall threshold elapsed (TTFB never happened); and
//   - mid-stream gap: bytes were flowing, then the stream went silent for
//     longer than the threshold.
//
// The gap is measured from the last observed activity (last byte written to
// the client, or the start time when nothing was ever sent) to the moment of
// cancellation, matching exactly what scanStalled tested.
func stallDetail(snap Entry, canceledAt time.Time) string {
	ref := snap.LastActivity
	if ref.IsZero() {
		ref = snap.StartedAt
	}
	gap := canceledAt.Sub(ref)
	if gap < 0 {
		gap = 0
	}
	gapStr := gap.Round(time.Second).String()
	if snap.ResponseBytes <= 0 {
		return fmt.Sprintf("initial wait: no response bytes for %s after connect", gapStr)
	}
	return fmt.Sprintf("mid-stream gap: silent for %s after %s received", gapStr, formatStallBytes(snap.ResponseBytes))
}

// slowDetail builds the "specific situation" recorded on a slow-stream
// cancellation. It reports the number that actually tripped the rule — the
// bytes delivered in the last window — alongside the whole-request total, so
// an operator can tell a genuinely-slow stream apart from an initial burst
// followed by near-silence (whose whole-request average would look fast and
// contradict the "slow" verdict). SlowWindowBytes is captured by scanSlow at
// cancel time; it falls back to a total-throughput description if unset.
func slowDetail(snap Entry, canceledAt time.Time, windowSeconds, minBytes int) string {
	start := snap.FirstChunkAt
	if start.IsZero() {
		start = snap.StartedAt
	}
	total := canceledAt.Sub(start)
	if total <= 0 {
		total = time.Second
	}
	return fmt.Sprintf("slow stream: only %s in last %ds window (floor %s); %s total over %s",
		formatStallBytes(snap.SlowWindowBytes), windowSeconds, formatStallBytes(int64(minBytes)),
		formatStallBytes(snap.ResponseBytes), total.Round(time.Second).String())
}

// formatStallBytes renders a byte count in the same B/KB/MB style the operator
// UI uses, so stall records read consistently with the live in-flight view.
func formatStallBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
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

// SetErrorSnippet records a bounded prefix of an error response body so the
// operator UI can show why a request failed. Intended to be called once at
// finish for a >=400 outcome, just before Finish snapshots the entry. No-op
// for an empty snippet.
func (r *Registry) SetErrorSnippet(t *trackedRequest, snippet string) {
	if t == nil {
		return
	}
	snippet = strings.TrimSpace(snippet)
	if snippet == "" {
		return
	}
	const maxLen = 2048
	if len(snippet) > maxLen {
		snippet = snippet[:maxLen]
	}
	t.mu.Lock()
	t.errorSnippet = snippet
	t.mu.Unlock()
}

// SetStreamFailure records that a streaming response failed after its status
// line was already sent. classifyErrorReason promotes such an entry to an
// error even though the HTTP status stays 200.
func (r *Registry) SetStreamFailure(t *trackedRequest, reason string) {
	if t == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return
	}
	const maxLen = 2048
	if len(reason) > maxLen {
		reason = reason[:maxLen]
	}
	t.mu.Lock()
	t.streamFailure = reason
	t.mu.Unlock()
	r.touch(t)
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
