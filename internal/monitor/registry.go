// Package monitor maintains an in-memory registry of in-flight HTTP requests
// so operators can observe current activity and cancel hung requests.
package monitor

import (
	"context"
	"fmt"
	"sort"
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

	mu         sync.RWMutex
	model      string
	authID     string
	authLabel  string
	provider   string
	status     Status
	cancel     context.CancelFunc
	canceledBy string
	canceledAt time.Time
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
	}
}

// AuthLookup is an optional callback that enriches an auth ID with a human-friendly
// label and the upstream provider name. The Registry will tolerate a nil lookup.
type AuthLookup func(authID string) (label string, provider string, ok bool)

// Registry is the central in-memory tracker of all in-flight requests.
type Registry struct {
	mu          sync.RWMutex
	entries     map[string]*trackedRequest
	subscribers map[chan Event]struct{}
	authLookup  AuthLookup

	settings *SettingsStore
	history  *historyRing
	histLog  *historyLog
}

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
		entries:     make(map[string]*trackedRequest),
		subscribers: make(map[chan Event]struct{}),
		history:     newHistoryRing(200),
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

// SetAuthLookup installs (or replaces) the auth enrichment callback.
func (r *Registry) SetAuthLookup(lookup AuthLookup) {
	r.mu.Lock()
	r.authLookup = lookup
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

// SetAuth updates the selected auth identifier and enriches label/provider.
func (r *Registry) SetAuth(t *trackedRequest, authID string) {
	if t == nil || authID == "" {
		return
	}
	r.mu.RLock()
	lookup := r.authLookup
	r.mu.RUnlock()

	label, provider := "", ""
	if lookup != nil {
		if l, p, ok := lookup(authID); ok {
			label = l
			provider = p
		}
	}

	t.mu.Lock()
	if t.authID == authID && t.authLabel == label && t.provider == provider {
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
	t.mu.Unlock()
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

	// Push the terminal status so SSE subscribers see the final state. This
	// transition must not be dropped under load — operators rely on it to
	// know the request actually ended.
	r.broadcast(Event{Type: "updated", Entry: t.snapshot(), Critical: true})

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
