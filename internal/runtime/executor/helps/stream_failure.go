package helps

import (
	"context"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/monitor"
)

// MarkStreamFailure reports a streaming failure that happened after the
// response status line was already written, so the operator monitor can flag
// the request even though its HTTP status is stuck at 200.
//
// Streaming responses commit their status when the first byte goes out. An SSE
// error event, or a stream that simply stops before its terminal event, is
// therefore invisible to status-code-based error classification: the request
// is recorded as a clean 200 while the client reports a broken turn (codex
// surfaces exactly this as "stream disconnected before completion"). Executors
// call this at the point they detect the failure.
//
// No-op when the context carries no monitor handle (non-HTTP callers, tests).
func MarkStreamFailure(ctx context.Context, reason string) {
	reason = strings.TrimSpace(reason)
	if ctx == nil || reason == "" {
		return
	}
	monitor.HandleFromContext(ctx).MarkStreamFailure(reason)
}
