package monitor

import (
        "net/http/httptest"
        "testing"

        "github.com/gin-gonic/gin"
)

// TestCountingWriterExtractUsageFromSSE simulates the full write path: the
// handler writes "data: {json}\n\n" through the countingWriter, and the
// registry must extract usage from it. This mirrors what happens for
// qwen38 (llama.cpp) chat-completions streams.
func TestCountingWriterExtractUsageFromSSE(t *testing.T) {
        reg := NewRegistry()
        entry := reg.Register("cw-qwen", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, func() {})
        defer reg.Remove(entry.id)

        rec := httptest.NewRecorder()
        ginCtx, _ := gin.CreateTestContext(rec)
        w := &countingWriter{ResponseWriter: ginCtx.Writer, reg: reg, entry: entry}
        // Simulate handler WriteChunk: "data: {json}\n\n"
        chunk := []byte(`data: {"choices":[],"usage":{"completion_tokens":10,"prompt_tokens":53,"total_tokens":63}}\n\n`)
        n, err := w.Write(chunk)
        if err != nil {
                t.Fatalf("Write: %v", err)
        }
        if n != len(chunk) {
                t.Fatalf("wrote %d, want %d", n, len(chunk))
        }
        snap := entry.snapshot()
        if snap.InputTokens != 53 {
                t.Errorf("expected InputTokens=53, got %d", snap.InputTokens)
        }
        if snap.OutputTokens != 10 {
                t.Errorf("expected OutputTokens=10, got %d", snap.OutputTokens)
        }
}