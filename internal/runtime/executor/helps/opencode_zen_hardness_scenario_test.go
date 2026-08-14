package helps

import (
	"testing"

	"github.com/tidwall/gjson"
)

// TestMergeOpencodeZenToolsHardnessScenario simulates a DeepSeek Harness
// request that ships its own tool set (read/write/edit/pwsh with snake_case
// file_path params).
//
// Invariants (verified against the zen gateway):
//  1. The canonical six tools must be FULLY present verbatim — altering one
//     triggers 429.
//  2. Tool names MUST be unique — the upstream rejects duplicate tool names
//     with "Tool names must be unique".
//  3. Colliding client tools (read/write) are injected under meaningful
//     model-facing aliases (read_file/write_file) with the client's own
//     snake_case schema, so the model can actually call them.
func TestMergeOpencodeZenToolsHardnessScenario(t *testing.T) {
	input := `{
		"model": "deepseek-v4-flash-free",
		"messages": [{"role": "user", "content": "q"}],
		"tools": [
			{"type": "function", "function": {"name": "read", "parameters": {"properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "write", "parameters": {"properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "edit", "parameters": {"properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "pwsh", "parameters": {"properties": {"command": {"type": "string"}}}}}
		]
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	tools := gjson.GetBytes(out, "tools").Array()

	// 3) Client tools first, colliding ones under model-facing aliases with
	//    the client's own schema.
	expect := []struct {
		name  string
		hasFp bool // expects file_path param
	}{
		{"read_file", true},
		{"write_file", true},
		{"edit", true},
		{"pwsh", false},
	}
	for i, e := range expect {
		got := tools[i].Get("function.name").String()
		if got != e.name {
			t.Fatalf("tools[%d] = %q, want %q", i, got, e.name)
		}
		props := tools[i].Get("function.parameters.properties").Raw
		if e.hasFp && !gjson.GetBytes([]byte(props), "file_path").Exists() {
			t.Errorf("%s must keep client's file_path schema, got: %s", e.name, props)
		}
	}

	// 2) No duplicate tool names.
	names := make(map[string]int)
	for _, tool := range tools {
		names[tool.Get("function.name").String()]++
	}
	for name, count := range names {
		if count > 1 {
			t.Errorf("tool %q appears %d times; names must be unique", name, count)
		}
	}

	// 1) All six canonical names present exactly once (canonical read/write
	//    kept verbatim alongside the aliased client tools).
	for _, name := range []string{"read", "task", "todowrite", "webfetch", "websearch", "write"} {
		if names[name] != 1 {
			t.Errorf("canonical tool name %q must be present exactly once (got %d)", name, names[name])
		}
	}
}

// TestRewriteOpencodeZenResponseToolNames verifies the response rewrite
// restores client-facing names for both non-streaming bodies and streaming
// data lines, while leaving arguments untouched.
func TestRewriteOpencodeZenResponseToolNames(t *testing.T) {
	// Non-streaming body.
	body := []byte(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"read_file","arguments":"{\"file_path\":\"/x\"}"}}]}}]}`)
	out := RewriteOpencodeZenResponseToolNames(body)
	if got := gjson.GetBytes(out, "choices.0.message.tool_calls.0.function.name").String(); got != "read" {
		t.Errorf("non-stream rename = %q, want read", got)
	}
	if got := gjson.GetBytes(out, "choices.0.message.tool_calls.0.function.arguments").String(); got != `{"file_path":"/x"}` {
		t.Errorf("arguments must stay untouched, got %q", got)
	}

	// Streaming data line (arguments are incremental fragments — untouched).
	line := []byte(`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"write_file","arguments":"{\"fi"}}]}}]}`)
	out = RewriteOpencodeZenResponseToolNames(line)
	if got := gjson.GetBytes(out, "choices.0.delta.tool_calls.0.function.name").String(); got != "write" {
		t.Errorf("stream rename = %q, want write", got)
	}
	if got := gjson.GetBytes(out, "choices.0.delta.tool_calls.0.function.arguments").String(); got != `{"fi` {
		t.Errorf("stream arguments must stay untouched, got %q", got)
	}

	// Unrelated line unchanged.
	plain := []byte(`data: {"choices":[{"delta":{"content":"hi"}}]}`)
	if got := string(RewriteOpencodeZenResponseToolNames(plain)); got != string(plain) {
		t.Errorf("unrelated line must pass through, got %q", got)
	}
}

// TestOpencodeZenRequestHistoryRename verifies assistant tool_calls names in
// the message history are rewritten to model-facing aliases so upstream
// history matches the renamed tool definitions.
func TestOpencodeZenRequestHistoryRename(t *testing.T) {
	input := `{
		"model": "deepseek-v4-flash-free",
		"messages": [
			{"role": "user", "content": "q"},
			{"role": "assistant", "content": "", "tool_calls": [{"id": "a1", "type": "function", "function": {"name": "read", "arguments": "{\"file_path\":\"/x\"}"}}]},
			{"role": "tool", "tool_call_id": "a1", "content": "ok"}
		],
		"tools": [
			{"type": "function", "function": {"name": "read", "parameters": {"properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}}
		]
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	got := gjson.GetBytes(out, "messages").Array()
	found := false
	for _, m := range got {
		calls := m.Get("tool_calls").Array()
		if len(calls) == 0 {
			continue
		}
		found = true
		name := calls[0].Get("function.name").String()
		if name != "read_file" {
			t.Errorf("history tool_calls name = %q, want read_file", name)
		}
		args := calls[0].Get("function.arguments").String()
		if args != `{"file_path":"/x"}` {
			t.Errorf("history arguments must stay untouched, got %q", args)
		}
	}
	if !found {
		t.Fatal("assistant tool_calls message missing from converted payload")
	}
}
