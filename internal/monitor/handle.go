package monitor

import (
	"context"
	"time"
)

// Handle is the externally visible accessor for an in-flight tracker. Other
// packages obtain one via HandleFromContext and feed in updates that the HTTP
// middleware cannot observe directly — for example, bodies and tokens
// flowing over a hijacked WebSocket connection.
//
// All methods are safe to call on a nil receiver and become no-ops, so call
// sites do not need defensive nil checks.
type Handle struct {
	r *Registry
	t *trackedRequest
}

// Active reports whether the handle still references a live tracker.
func (h *Handle) Active() bool {
	return h != nil && h.t != nil && h.r != nil
}

// SetModel records the requested model name. Empty strings and duplicate
// values are ignored so callers can invoke this on every inbound frame
// without worrying about churn.
func (h *Handle) SetModel(model string) {
	if !h.Active() {
		return
	}
	h.r.SetModel(h.t, model)
}

// SetAuth records the selected credential identifier and enriches it with
// the configured AuthLookup.
func (h *Handle) SetAuth(authID string) {
	if !h.Active() {
		return
	}
	h.r.SetAuth(h.t, authID)
}

// MarkStreaming flags the entry as a streaming response. Useful for hijacked
// WebSocket handlers since the response writer wrapper cannot see the
// Content-Type after upgrade.
func (h *Handle) MarkStreaming() {
	if !h.Active() {
		return
	}
	h.r.SetStreaming(h.t, true)
}

// AddRequestBytes accumulates inbound bytes that did not flow through the
// initial HTTP body (e.g. subsequent WebSocket frames from the client).
func (h *Handle) AddRequestBytes(n int) {
	if !h.Active() || n <= 0 {
		return
	}
	h.t.requestBytes.Add(int64(n))
	h.r.touch(h.t)
}

// AddResponseBytes accumulates outbound bytes that did not flow through the
// gin response writer (e.g. WebSocket frames written to the hijacked conn).
// Triggers throttled SSE broadcasts identical to the HTTP path.
func (h *Handle) AddResponseBytes(n int) {
	if !h.Active() {
		return
	}
	h.r.AddResponseBytes(h.t, n)
}

// ExtractUsage scans a chunk for provider token usage metadata and updates
// the entry monotonically.
func (h *Handle) ExtractUsage(chunk []byte) {
	if !h.Active() {
		return
	}
	h.r.ExtractUsage(h.t, chunk)
}

// MarkFirstByte records the wall-clock moment the upstream produced its
// first byte for this request. Subsequent calls are no-ops, mirroring the
// behaviour of the HTTP response writer wrapper.
func (h *Handle) MarkFirstByte() {
	if !h.Active() {
		return
	}
	h.t.firstChunkAt.CompareAndSwap(0, time.Now().UnixNano())
}

// MarkStreamFailure records that the response stream failed after its status
// line was already written (SSE/WebSocket error event, or the stream ending
// before its terminal event). The HTTP middleware cannot see this — the status
// code stays 200 — so without it the request looks like a clean success.
func (h *Handle) MarkStreamFailure(reason string) {
	if !h.Active() {
		return
	}
	h.r.SetStreamFailure(h.t, reason)
}

// SetStatusCode records the terminal HTTP status. Used by hijacked
// transports (WebSocket) that have no real status line: callers set 200 for
// a completed turn so the entry is not misclassified as a status-less error.
func (h *Handle) SetStatusCode(code int) {
	if !h.Active() {
		return
	}
	h.t.statusCode.Store(int32(code))
}

// Finish completes the underlying entry, broadcasting the terminal status
// and scheduling removal after the linger window. Safe to call on a nil
// handle.
func (h *Handle) Finish() {
	if !h.Active() {
		return
	}
	h.r.Finish(h.t)
}

type handleContextKey struct{}
type registryContextKey struct{}

// WithHandle returns a child context that carries the given handle. Safe to
// call with a nil handle.
func WithHandle(ctx context.Context, h *Handle) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if h == nil {
		return ctx
	}
	return context.WithValue(ctx, handleContextKey{}, h)
}

// HandleFromContext returns the handle attached by the monitor middleware,
// or nil if none is present.
func HandleFromContext(ctx context.Context) *Handle {
	if ctx == nil {
		return nil
	}
	if h, ok := ctx.Value(handleContextKey{}).(*Handle); ok {
		return h
	}
	return nil
}

// WithRegistry exposes the active Registry to downstream code. Used by the
// WebSocket handler so it can create per-frame sub-entries even though the
// middleware does not register the upgrade itself.
func WithRegistry(ctx context.Context, r *Registry) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, registryContextKey{}, r)
}

// RegistryFromContext returns the Registry attached to the context, if any.
func RegistryFromContext(ctx context.Context) *Registry {
	if ctx == nil {
		return nil
	}
	if r, ok := ctx.Value(registryContextKey{}).(*Registry); ok {
		return r
	}
	return nil
}
