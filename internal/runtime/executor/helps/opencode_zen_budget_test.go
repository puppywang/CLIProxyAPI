package helps

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestOpencodeZenBudgetLeavesSmallPayloadUntouched(t *testing.T) {
	input := `{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	if len(out) > OpencodeZenMaxPayloadBytes {
		t.Fatal("small payload must not be trimmed")
	}
	if got := gjson.GetBytes(out, "messages.1.content").String(); got != "hi" {
		t.Fatalf("user content = %q, want hi", got)
	}
}

func TestOpencodeZenBudgetTrimsOversizedPayload(t *testing.T) {
	big := strings.Repeat("conversation history padding ", 60000) // ~1.84MB
	input := `{"model":"m","messages":[` +
		`{"role":"system","content":"client"},` +
		`{"role":"user","content":"old message"},` +
		`{"role":"user","content":"` + big + `"},` +
		`{"role":"user","content":"newest question"}` +
		`],"stream":true}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	if !gjson.ValidBytes(out) {
		t.Fatal("trimmed payload must be valid JSON")
	}
	if len(out) > OpencodeZenMaxPayloadBytes {
		t.Fatalf("trimmed payload %d exceeds budget %d", len(out), OpencodeZenMaxPayloadBytes)
	}
	messages := gjson.GetBytes(out, "messages").Array()
	if len(messages) < 2 {
		t.Fatalf("messages count = %d, want >= 2", len(messages))
	}
	if messages[0].Get("role").String() != "system" || messages[0].Get("content").String() != OpencodeZenSystemPrompt() {
		t.Fatal("messages[0] must be the canonical system prompt")
	}
	last := messages[len(messages)-1]
	if last.Get("content").String() != "newest question" {
		t.Fatalf("newest user message must be preserved, got %q", last.Get("content").String())
	}
}

func TestOpencodeZenBudgetTruncatesSingleOversizedMessage(t *testing.T) {
	big := strings.Repeat("x", 1_600_000)
	input := `{"model":"m","messages":[{"role":"user","content":"` + big + `tail-marker-123"}],"stream":false}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	if len(out) > OpencodeZenMaxPayloadBytes {
		t.Fatalf("trimmed payload %d exceeds budget %d", len(out), OpencodeZenMaxPayloadBytes)
	}
	content := gjson.GetBytes(out, "messages.1.content").String()
	if !strings.HasSuffix(content, "tail-marker-123") {
		t.Fatalf("truncated content must keep its tail, got suffix %q", content[max(0, len(content)-40):])
	}
	if !strings.Contains(content, "[context truncated by proxy]") {
		t.Fatal("truncated content must carry the truncation marker")
	}
}

func TestOpencodeZenBudgetDropsOrphanedToolMessages(t *testing.T) {
	// The oversized message is an assistant reply; trimming must drop it and
	// then also drop the tool message it orphaned.
	big := strings.Repeat("long-assistant-reply ", 60_000) // ~1.2MB
	input := `{"model":"m","messages":[` +
		`{"role":"system","content":"client"},` +
		`{"role":"user","content":"small"},` +
		`{"role":"assistant","content":"` + big + `"},` +
		`{"role":"tool","tool_call_id":"c1","content":"file content"},` +
		`{"role":"user","content":"newest"}` +
		`],"stream":true}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	if len(out) > OpencodeZenMaxPayloadBytes {
		t.Fatalf("trimmed payload %d exceeds budget %d", len(out), OpencodeZenMaxPayloadBytes)
	}
	messages := gjson.GetBytes(out, "messages").Array()
	if len(messages) < 1 {
		t.Fatal("messages lost entirely")
	}
	for _, m := range messages[1:] {
		role := m.Get("role").String()
		if role == "tool" || role == "function" {
			t.Fatal("orphaned tool/function message survived trimming at the old edge")
		}
	}
	last := messages[len(messages)-1]
	if last.Get("content").String() != "newest" {
		t.Fatalf("newest message must be preserved, got %q", last.Get("content").String())
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
