package helps

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

type zenTestToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type zenTestMsg struct {
	Role       string            `json:"role"`
	Content    *string           `json:"content,omitempty"`
	Reasoning  string            `json:"reasoning_content,omitempty"`
	ToolCalls  []zenTestToolCall `json:"tool_calls,omitempty"`
	ToolCallID string            `json:"tool_call_id,omitempty"`
}

// TestBudgetTrimPreservesReasoningContent models the exact failure shape:
// a Copilot-style payload >1MB whose history interleaves assistant
// (reasoning_content + tool_calls) with tool results, then asserts that
// budget trimming never leaves an assistant message with tool_calls but
// without reasoning_content (the DeepSeek "must be passed back" rejection).
func TestBudgetTrimPreservesReasoningContent(t *testing.T) {
	turn := func(i int) []zenTestMsg {
		c := fmt.Sprintf("context data for turn %d. %s", i, strings.Repeat("padding ", 300))
		uid := fmt.Sprintf("u%d", i)
		callID := fmt.Sprintf("call_%d", i)
		rc := fmt.Sprintf("reasoning for turn %d that must survive trimming and keep association with tool call %s", i, callID)
		return []zenTestMsg{
			{Role: "user", Content: &c},
			{
				Role:      "assistant",
				Content:   &uid,
				Reasoning: rc,
				ToolCalls: []zenTestToolCall{{
					ID:   callID,
					Type: "function",
					Function: struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					}{Name: "read_file", Arguments: fmt.Sprintf(`{"filePath":"C:\\repo\\f%d.txt"}`, i)},
				}},
			},
			{Role: "tool", ToolCallID: callID, Content: ptr("Found file contents " + fmt.Sprint(i))},
		}
	}

	var msgs []zenTestMsg
	for i := 0; i < 700; i++ {
		msgs = append(msgs, turn(i)...)
	}
	payload, err := json.Marshal(map[string]any{
		"model":    "deepseek-v4-flash-free",
		"messages": msgs,
		"stream":   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= OpencodeZenMaxPayloadBytes {
		t.Fatalf("test payload must exceed budget: got %d", len(payload))
	}
	t.Logf("payload size: %d", len(payload))

	out := ConvertOpenAIRequestToOpencodeZen(payload)
	if len(out) > OpencodeZenMaxPayloadBytes {
		t.Fatalf("converted payload %d still over budget %d", len(out), OpencodeZenMaxPayloadBytes)
	}
	bad := 0
	withRC := 0
	assistantWithTools := 0
	for _, m := range gjson.GetBytes(out, "messages").Array() {
		if m.Get("role").String() != "assistant" {
			continue
		}
		tc := len(m.Get("tool_calls").Array())
		if tc == 0 {
			continue
		}
		assistantWithTools++
		if !m.Get("reasoning_content").Exists() {
			bad++
			if bad <= 3 {
				t.Logf("BAD assistant with %d tool_calls, no reasoning_content: %s", tc, m.Raw[:min(200, len(m.Raw))])
			}
		} else {
			withRC++
		}
	}
	if bad > 0 {
		t.Fatalf("budget trimming left %d assistant(tool_calls) messages without reasoning_content (of %d with tools)", bad, assistantWithTools)
	}
	t.Logf("assistant messages with tool_calls: %d, with reasoning preserved: %d", assistantWithTools, withRC)
}

func ptr(s string) *string { return &s }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
