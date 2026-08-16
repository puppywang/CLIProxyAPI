package monitor

import (
        "testing"
)

// TestExtractUsageLlamaCppChatCompletions verifies that a llama.cpp-style
// chat-completions stream (the qwen38 upstream shape) yields token counts.
// The final chunk carries usage + timings; the usage fields are standard
// OpenAI prompt_tokens/completion_tokens so they must be picked up.
func TestExtractUsageLlamaCppChatCompletions(t *testing.T) {
        reg := NewRegistry()
        entry := reg.Register("llama-qwen", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, func() {})
        defer reg.Remove(entry.id)

        // Content chunks without usage marker are skipped.
        if reg.ExtractUsage(entry, []byte(`data: {"choices":[{"delta":{"content":"hi"}}]}`)) {
                t.Fatal("did not expect extraction without marker")
        }
        // Final chunk with usage (llama.cpp emits usage + timings).
        final := []byte(`data: {"choices":[],"created":1786892725,"id":"chatcmpl-x","model":"qwen3.8-27b","object":"chat.completion.chunk","usage":{"completion_tokens":10,"prompt_tokens":53,"total_tokens":63,"prompt_tokens_details":{"cached_tokens":0}},"timings":{"prompt_n":53,"predicted_n":10}}`)
        if !reg.ExtractUsage(entry, final) {
                t.Fatal("expected extraction from llama.cpp usage chunk")
        }
        snap := entry.snapshot()
        if snap.InputTokens != 53 {
                t.Errorf("expected InputTokens=53, got %d", snap.InputTokens)
        }
        if snap.OutputTokens != 10 {
                t.Errorf("expected OutputTokens=10, got %d", snap.OutputTokens)
        }
        if snap.TotalTokens != 63 {
                t.Errorf("expected TotalTokens=63, got %d", snap.TotalTokens)
        }
}

// TestExtractUsageSSEDataPrefix verifies the SSE "data: " prefix does not
// break extraction — countingWriter feeds raw wire bytes, which include the
// prefix for SSE streams.
func TestExtractUsageSSEDataPrefix(t *testing.T) {
        reg := NewRegistry()
        entry := reg.Register("sse-qwen", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, func() {})
        defer reg.Remove(entry.id)

        chunk := []byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\n\n")
        if !reg.ExtractUsage(entry, chunk) {
                t.Fatal("expected extraction from SSE data line")
        }
        snap := entry.snapshot()
        if snap.InputTokens != 7 || snap.OutputTokens != 3 {
                t.Fatalf("got in=%d out=%d, want 7/3", snap.InputTokens, snap.OutputTokens)
        }
}