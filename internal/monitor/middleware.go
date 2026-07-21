package monitor

import (
	"bytes"
	"context"
	"io"
	"regexp"
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

		// Attach the request-body timer (installed by RequestBodyTimingMiddleware
		// earlier in the chain) so the entry can report how long the upload took.
		if bt := bodyTimingFromContext(c.Request.Context()); bt != nil {
			entry.mu.Lock()
			entry.bodyTiming = bt
			entry.mu.Unlock()
		}

		// Try to extract model and workspace cwd from the JSON body without
		// consuming it. The RequestLoggingMiddleware (if installed earlier)
		// has already restored the body, so we can safely read and restore
		// again. Both values are pulled in the same read pass so we don't
		// double-read the body — cwd is embedded inside the request's
		// input_text content as a literal <cwd>…</cwd> tag and is therefore
		// invisible to gjson at the top level.
		model, workspace := peekModelAndWorkspaceFromRequest(c)
		if model != "" {
			reg.SetModel(entry, model)
		}
		if workspace != "" {
			reg.SetWorkspace(entry, workspace)
		}

		// Extract Codex window/turn metadata from the request headers so
		// the live in-flight view shows which conversation each request
		// belongs to. This is the same source the session-affinity
		// selector uses, so the two views agree on what "the same
		// window" means.
		var inflightSessionID, inflightThreadID string
		if sid, tid, turn, source := peekTurnMetadata(c); sid != "" || tid != "" || turn != "" {
			reg.SetTurnMetadata(entry, sid, tid, turn, source)
			inflightSessionID = sid
			inflightThreadID = tid
		}

		// Remember session_id → workspace outside the per-request entry
		// lifetime so the bindings reverse-index endpoint can render the
		// workspace path against each cached binding even after the
		// request has long finished. We record under BOTH session_id and
		// thread_id when both are known, because the session-affinity
		// cache uses thread_id as its primary key and session_id only as
		// a mirror — operators looking at a `codex-thread:<tid>` row
		// expect to see the workspace by tid lookup.
		if workspace != "" {
			if inflightSessionID != "" {
				reg.RecordSessionWorkspace(inflightSessionID, workspace)
			}
			if inflightThreadID != "" && inflightThreadID != inflightSessionID {
				reg.RecordSessionWorkspace(inflightThreadID, workspace)
			}
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
			// Record the error body (if any) before Finish snapshots the entry,
			// so the recent-errors ring carries the reason.
			if snip := wrapper.ErrorSnippet(); snip != "" {
				reg.SetErrorSnippet(entry, snip)
			}
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

// cwdPattern matches the <cwd>…</cwd> tag Codex CLI clients embed inside
// their environment_context input_text block. The tag value contains a path
// whose backslashes (Windows) appear in the JSON body as either literal
// backslashes (when the body itself was already decoded) or as escaped
// "\\" pairs (raw JSON on the wire). The pattern accepts any character that
// is not the opening "<" of the closing tag, which covers both shapes.
var cwdPattern = regexp.MustCompile(`<cwd>([^<]+)</cwd>`)

// modelFieldPattern matches a top-level-style "model":"…" field so the model
// can be recovered from a truncated JSON prefix (large bodies) without full
// parsing. The model field sits near the top of request bodies in practice.
var modelFieldPattern = regexp.MustCompile(`"model"\s*:\s*"([^"]+)"`)

// modelFromPrefix extracts the first "model":"…" value from a (possibly
// truncated) JSON prefix. Display-only best effort for oversized bodies.
func modelFromPrefix(prefix []byte) string {
	m := modelFieldPattern.FindSubmatch(prefix)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// peekModelAndWorkspaceFromRequest reads the request body once, extracts the
// model name and (when present) the workspace cwd embedded in a Codex
// environment_context block, and restores the body for downstream handlers.
// Returns empty strings on any failure or when the body is too large to peek.
func peekModelAndWorkspaceFromRequest(c *gin.Context) (model, workspace string) {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return "", ""
	}
	const maxPeek = 1 << 20 // 1 MiB
	if c.Request.ContentLength > 0 && c.Request.ContentLength > maxPeek {
		// Large body (e.g. big Codex /v1/responses payloads). Don't buffer it
		// all, but still recover the model from a bounded prefix so error rows
		// aren't left blank when the request fails before the executor fills
		// the model (e.g. an early "unknown provider" 502). The model field
		// sits near the top of the request JSON.
		const modelPeek = 64 << 10
		prefix, errPeek := io.ReadAll(io.LimitReader(c.Request.Body, modelPeek))
		if errPeek != nil {
			return "", ""
		}
		// Restore body as prefix + the still-unread remainder (no full buffering).
		c.Request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), c.Request.Body))
		return modelFromPrefix(prefix), ""
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxPeek+1))
	if err != nil {
		return "", ""
	}
	// Restore body so downstream handlers can still read it.
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		return "", ""
	}
	model = strings.TrimSpace(gjson.GetBytes(body, "model").String())
	workspace = extractWorkspaceFromBody(body)
	return model, workspace
}

// extractWorkspaceFromBody pulls the first <cwd>…</cwd> tag value out of the
// request body. JSON-escaped backslashes (e.g. "d:\\AISports") are normalised
// to plain backslashes so the value can be displayed verbatim.
func extractWorkspaceFromBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	m := cwdPattern.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	raw := strings.TrimSpace(string(m[1]))
	if raw == "" {
		return ""
	}
	// Normalise JSON-escaped backslashes to single backslashes. The body is
	// JSON on the wire so "d:\\AISports\\…" appears here as four bytes
	// "d:\\A" — collapsing the pair to a single backslash gives the value
	// the user actually typed.
	if strings.Contains(raw, `\\`) {
		raw = strings.ReplaceAll(raw, `\\`, `\`)
	}
	return raw
}

// countingWriter wraps gin.ResponseWriter to count outbound bytes and to
// detect streaming responses based on Content-Type.
type countingWriter struct {
	gin.ResponseWriter
	reg            *Registry
	entry          *trackedRequest
	headerCaptured bool
	// errBuf accumulates a bounded prefix of the response body, but only for
	// error outcomes (status >= 400). For a 4xx/5xx the body IS the error
	// payload, so this captures exactly why the request failed.
	errBuf []byte
}

const maxErrSnippet = 2048

// captureErr appends response bytes to the bounded error buffer when the
// outcome is an error. A 2xx (incl. streaming) never accumulates because the
// status gate is false, so the hot success path pays only one comparison.
func (w *countingWriter) captureErr(data []byte) {
	if len(w.errBuf) >= maxErrSnippet || w.ResponseWriter.Status() < 400 {
		return
	}
	room := maxErrSnippet - len(w.errBuf)
	if room > len(data) {
		room = len(data)
	}
	w.errBuf = append(w.errBuf, data[:room]...)
}

// ErrorSnippet returns the captured error body prefix (empty on success).
func (w *countingWriter) ErrorSnippet() string {
	return string(w.errBuf)
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
		w.captureErr(data[:n])
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
			w.captureErr([]byte(data))
		} else {
			w.reg.ExtractUsage(w.entry, []byte(data[:n]))
			w.captureErr([]byte(data[:n]))
		}
	}
	return n, err
}

func (w *countingWriter) WriteHeader(code int) {
	w.reg.SetStatusCode(w.entry, code)
	w.ResponseWriter.WriteHeader(code)
	w.captureStreaming()
}
