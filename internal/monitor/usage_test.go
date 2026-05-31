package monitor

import (
	"context"
	"testing"
)

func TestExtractUsageOpenAIChatCompletions(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("usage-oai", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, cancel)
	defer reg.Remove(entry.id)

	chunk := []byte(`data: {"id":"x","choices":[],"usage":{"prompt_tokens":42,"completion_tokens":128,"total_tokens":170}}`)
	if !reg.ExtractUsage(entry, chunk) {
		t.Fatal("expected usage extraction to succeed")
	}
	snap := entry.snapshot()
	if snap.InputTokens != 42 || snap.OutputTokens != 128 || snap.TotalTokens != 170 {
		t.Errorf("got in=%d out=%d total=%d", snap.InputTokens, snap.OutputTokens, snap.TotalTokens)
	}
}

func TestExtractUsageOpenAIResponses(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("usage-resp", "POST", "", "/v1/responses", "127.0.0.1", "", 0, cancel)
	defer reg.Remove(entry.id)

	chunk := []byte(`event: response.completed
data: {"type":"response.completed","response":{"id":"r1","usage":{"input_tokens":100,"output_tokens":250,"total_tokens":350}}}`)
	if !reg.ExtractUsage(entry, chunk) {
		t.Fatal("expected usage extraction to succeed")
	}
	snap := entry.snapshot()
	if snap.InputTokens != 100 || snap.OutputTokens != 250 || snap.TotalTokens != 350 {
		t.Errorf("got in=%d out=%d total=%d", snap.InputTokens, snap.OutputTokens, snap.TotalTokens)
	}
}

func TestExtractUsageAnthropic(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("usage-claude", "POST", "", "/v1/messages", "127.0.0.1", "", 0, cancel)
	defer reg.Remove(entry.id)

	chunkStart := []byte(`event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":50,"output_tokens":1}}}`)
	chunkDelta := []byte(`event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":200}}`)

	reg.ExtractUsage(entry, chunkStart)
	reg.ExtractUsage(entry, chunkDelta)

	snap := entry.snapshot()
	if snap.InputTokens != 50 {
		t.Errorf("expected input=50, got %d", snap.InputTokens)
	}
	if snap.OutputTokens != 200 {
		t.Errorf("expected monotonic output=200, got %d", snap.OutputTokens)
	}
}

func TestExtractUsageGemini(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("usage-gemini", "POST", "", "/v1beta/models/gemini", "127.0.0.1", "", 0, cancel)
	defer reg.Remove(entry.id)

	chunk := []byte(`{"candidates":[],"usageMetadata":{"promptTokenCount":80,"candidatesTokenCount":160,"totalTokenCount":240}}`)
	reg.ExtractUsage(entry, chunk)

	snap := entry.snapshot()
	if snap.InputTokens != 80 || snap.OutputTokens != 160 || snap.TotalTokens != 240 {
		t.Errorf("got in=%d out=%d total=%d", snap.InputTokens, snap.OutputTokens, snap.TotalTokens)
	}
}

func TestExtractUsageMonotonicAndSkipsNoMarker(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("usage-mono", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, cancel)
	defer reg.Remove(entry.id)

	// No usage marker -> no work performed.
	if reg.ExtractUsage(entry, []byte(`data: {"choices":[{"delta":{"content":"hello"}}]}`)) {
		t.Fatal("did not expect extraction without marker")
	}
	// First extraction.
	reg.ExtractUsage(entry, []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	// Second chunk with lower output_tokens should be ignored (monotonic).
	reg.ExtractUsage(entry, []byte(`{"usage":{"output_tokens":3}}`))
	snap := entry.snapshot()
	if snap.OutputTokens != 5 {
		t.Errorf("expected monotonic OutputTokens=5, got %d", snap.OutputTokens)
	}
}
