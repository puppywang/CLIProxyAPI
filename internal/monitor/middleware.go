package monitor

import (
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/tidwall/gjson"
)

// trackedPathPrefixes restricts monitor tracking to the AI proxy routes.
// The management and health endpoints are intentionally excluded.
var trackedPathPrefixes = []string{
	"/v1/chat/completions",
	"/v1/completions",
	"/v1/messages",
	"/v1/responses",
	"/v1/images",
	"/v1/videos",
	"/v1beta/models/",
	"/backend-api/codex/",
}

func shouldTrack(path string) bool {
	for _, prefix := range trackedPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// Middleware returns a Gin handler that registers every AI request with the
// registry, counts response bytes, exposes a cancel function, and threads a
// selected-auth callback through the request context so the executor can
// publish the chosen credential.
func Middleware(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		if reg == nil || c == nil || c.Request == nil {
			c.Next()
			return
		}
		path := c.Request.URL.Path
		if !shouldTrack(path) {
			c.Next()
			return
		}

		id := logging.GetGinRequestID(c)
		if id == "" {
			// AI API paths are normally assigned an id by GinLogrusLogger.
			// Skip tracking if not available — avoids collisions.
			c.Next()
			return
		}

		ctx, cancel := context.WithCancel(c.Request.Context())
		// Expose the Registry on the context so handlers can create per-frame
		// sub-entries when they need finer granularity than one entry per
		// HTTP request (e.g. a WebSocket session that multiplexes many
		// logical user requests over a single connection).
		ctx = WithRegistry(ctx, reg)
		c.Request = c.Request.WithContext(ctx)

		isWSUpgrade := strings.EqualFold(strings.TrimSpace(c.Request.Header.Get("Upgrade")), "websocket")
		if isWSUpgrade {
			// Skip registering the upgrade itself. The downstream WS handler
			// is responsible for creating one entry per logical frame, which
			// is far more useful than a single long-lived "session" entry.
			defer cancel()
			c.Next()
			return
		}

		var reqBytes int64
		if c.Request.ContentLength > 0 {
			reqBytes = c.Request.ContentLength
		}

		transport := TransportHTTP

		entry := reg.Register(
			id,
			c.Request.Method,
			transport,
			path,
			c.ClientIP(),
			c.Request.Header.Get("User-Agent"),
			reqBytes,
			cancel,
		)

		// Try to extract model from the JSON body without consuming it. The
		// RequestLoggingMiddleware (if installed earlier) has already restored
		// the body, so we can safely read and restore again.
		if model := peekModelFromRequest(c); model != "" {
			reg.SetModel(entry, model)
		}

		// Extract Codex window/turn metadata from the request headers so
		// the live in-flight view shows which conversation each request
		// belongs to. This is the same source the session-affinity
		// selector uses, so the two views agree on what "the same
		// window" means.
		if sid, tid, turn, source := peekTurnMetadata(c); sid != "" || tid != "" || turn != "" {
			reg.SetTurnMetadata(entry, sid, tid, turn, source)
		}

		handle := &Handle{r: reg, t: entry}

		// Install the selected-auth callback. The handler code reads this from
		// the request context via handlers.requestExecutionMetadata, and the
		// auth conductor invokes it once an upstream credential is chosen.
		// Carry the handle alongside so downstream code (e.g. hijacked
		// WebSocket handlers) can push updates the HTTP wrapper cannot see.
		ctx2 := handlers.WithSelectedAuthIDCallback(c.Request.Context(), func(authID string) {
			reg.SetAuth(entry, authID)
		})
		ctx2 = WithHandle(ctx2, handle)
		c.Request = c.Request.WithContext(ctx2)

		// Replace the response writer so we can count bytes and detect streaming.
		wrapper := &countingWriter{ResponseWriter: c.Writer, reg: reg, entry: entry}
		c.Writer = wrapper

		defer func() {
			reg.SetStatusCode(entry, wrapper.Status())
			reg.Finish(entry)
			cancel()
		}()

		c.Next()
	}
}

// peekTurnMetadata reads conversation-level identifiers from the
// incoming request without consuming the body. It checks the headers
// every Codex client populates today, in order of specificity:
//
//  1. X-Codex-Turn-Metadata (a JSON blob carrying session/thread/turn
//     IDs and thread_source). Codex VSCode always sets this on every
//     /v1/responses call.
//  2. Plain Session-Id / Thread-Id / X-Codex-Window-Id / X-Client-
//     Request-Id headers, used by older CLI versions and fallbacks.
//
// Empty values are returned when the headers are missing or malformed
// — the caller treats this as "no metadata" and leaves the entry's
// fields untouched. We deliberately do not touch the request body
// here; peekModelFromRequest already restored it, and the turn
// metadata lives in headers anyway.
func peekTurnMetadata(c *gin.Context) (sessionID, threadID, turnID, threadSource string) {
	if c == nil || c.Request == nil {
		return "", "", "", ""
	}
	h := c.Request.Header
	if meta := h.Get("X-Codex-Turn-Metadata"); meta != "" {
		sessionID = strings.TrimSpace(gjson.Get(meta, "session_id").String())
		threadID = strings.TrimSpace(gjson.Get(meta, "thread_id").String())
		turnID = strings.TrimSpace(gjson.Get(meta, "turn_id").String())
		threadSource = strings.ToLower(strings.TrimSpace(gjson.Get(meta, "thread_source").String()))
	}
	if sessionID == "" {
		if v := strings.TrimSpace(h.Get("Session-Id")); v != "" {
			sessionID = v
		} else if v := strings.TrimSpace(h.Get("X-Codex-Window-Id")); v != "" {
			// X-Codex-Window-Id sometimes carries "<session-id>:<n>"
			// — split off the suffix.
			if idx := strings.IndexByte(v, ':'); idx > 0 {
				sessionID = v[:idx]
			} else {
				sessionID = v
			}
		}
	}
	if threadID == "" {
		if v := strings.TrimSpace(h.Get("Thread-Id")); v != "" {
			threadID = v
		} else if v := strings.TrimSpace(h.Get("X-Client-Request-Id")); v != "" {
			threadID = v
		}
	}
	return sessionID, threadID, turnID, threadSource
}

func peekModelFromRequest(c *gin.Context) string {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return ""
	}
	const maxPeek = 1 << 20 // 1 MiB
	if c.Request.ContentLength > 0 && c.Request.ContentLength > maxPeek {
		// Skip peek on very large bodies; model will be filled by the executor
		// callback path instead.
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxPeek+1))
	if err != nil {
		return ""
	}
	// Restore body so downstream handlers can still read it.
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		return ""
	}
	model := strings.TrimSpace(gjson.GetBytes(body, "model").String())
	return model
}

// countingWriter wraps gin.ResponseWriter to count outbound bytes and to
// detect streaming responses based on Content-Type.
type countingWriter struct {
	gin.ResponseWriter
	reg            *Registry
	entry          *trackedRequest
	headerCaptured bool
}

func (w *countingWriter) captureStreaming() {
	if w.headerCaptured {
		return
	}
	w.headerCaptured = true
	contentType := w.ResponseWriter.Header().Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") ||
		strings.Contains(contentType, "stream+json") {
		w.reg.SetStreaming(w.entry, true)
	}
}

func (w *countingWriter) Write(data []byte) (int, error) {
	w.captureStreaming()
	n, err := w.ResponseWriter.Write(data)
	if n > 0 {
		w.entry.firstChunkAt.CompareAndSwap(0, time.Now().UnixNano())
		w.reg.AddResponseBytes(w.entry, n)
		w.reg.ExtractUsage(w.entry, data[:n])
	}
	return n, err
}

func (w *countingWriter) WriteString(data string) (int, error) {
	w.captureStreaming()
	n, err := w.ResponseWriter.WriteString(data)
	if n > 0 {
		w.entry.firstChunkAt.CompareAndSwap(0, time.Now().UnixNano())
		w.reg.AddResponseBytes(w.entry, n)
		if n == len(data) {
			w.reg.ExtractUsage(w.entry, []byte(data))
		} else {
			w.reg.ExtractUsage(w.entry, []byte(data[:n]))
		}
	}
	return n, err
}

func (w *countingWriter) WriteHeader(code int) {
	w.reg.SetStatusCode(w.entry, code)
	w.ResponseWriter.WriteHeader(code)
	w.captureStreaming()
}
