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
//  3. ALL colliding client tools are injected under meaningful model-facing
//     aliases (read_file/write_file/delegate_task/update_todos/fetch_url/
//     web_search) with the client's own schema, so the model can actually
//     call them.
func TestMergeOpencodeZenToolsHardnessScenario(t *testing.T) {
	input := `{
		"model": "deepseek-v4-flash-free",
		"messages": [{"role": "user", "content": "q"}],
		"tools": [
			{"type": "function", "function": {"name": "read", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "write", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "edit", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "pwsh", "parameters": {"type": "object", "properties": {"command": {"type": "string"}}}}},
			{"type": "function", "function": {"name": "task", "parameters": {"type": "object", "properties": {"prompt": {"type": "string"}}, "required": ["prompt"]}}},
			{"type": "function", "function": {"name": "todowrite", "parameters": {"type": "object", "properties": {"todos": {"type": "array"}}, "required": ["todos"]}}},
			{"type": "function", "function": {"name": "webfetch", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
			{"type": "function", "function": {"name": "websearch", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}}
		]
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	tools := gjson.GetBytes(out, "tools").Array()

	// 3) Client tools first, colliding ones under model-facing aliases with
	//    the client's own schema. Non-colliding (edit/pwsh) keep their names.
	expect := []struct {
		name  string
		hasFp bool // expects file_path param
	}{
		{"read_file", true},
		{"write_file", true},
		{"edit", true},
		{"pwsh", false},
		{"delegate_task", false},
		{"update_todos", false},
		{"fetch_url", false},
		{"web_search", false},
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

// TestOpencodeZenNormalizeToolSchema verifies a colliding client tool whose
// parameters lack the outer type gets type:"object" injected, so the gateway
// schema check ("schema must be a JSON Schema of 'type: object'") passes.
func TestOpencodeZenNormalizeToolSchema(t *testing.T) {
	input := `{
		"model": "deepseek-v4-flash-free",
		"messages": [{"role": "user", "content": "q"}],
		"tools": [
			{"type": "function", "function": {"name": "read", "parameters": {"properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}}
		]
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	got := gjson.GetBytes(out, "tools.0.function.parameters.type").String()
	if got != "object" {
		t.Errorf("renamed tool parameters.type = %q, want object", got)
	}
	if got := gjson.GetBytes(out, "tools.0.function.name").String(); got != "read_file" {
		t.Errorf("renamed tool name = %q, want read_file", got)
	}
	if got := gjson.GetBytes(out, "tools.0.function.parameters.properties.file_path").Exists(); !got {
		t.Error("client file_path property must survive normalization")
	}
}

// TestRewriteOpencodeZenResponseToolNames verifies the response rewrite
// restores client-facing names for both non-streaming bodies and streaming
// data lines, while leaving arguments untouched.
func TestRewriteOpencodeZenResponseToolNames(t *testing.T) {
	// Client declared a tool named "read" (collides with canonical), so the
	// alias read_file -> read must be reversed.
	renamed := map[string]bool{"read": true, "write": true}

	// Non-streaming body.
	body := []byte(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"read_file","arguments":"{\"file_path\":\"/x\"}"}}]}}]}`)
	out := RewriteOpencodeZenResponseToolNames(body, renamed)
	if got := gjson.GetBytes(out, "choices.0.message.tool_calls.0.function.name").String(); got != "read" {
		t.Errorf("non-stream rename = %q, want read", got)
	}
	if got := gjson.GetBytes(out, "choices.0.message.tool_calls.0.function.arguments").String(); got != `{"file_path":"/x"}` {
		t.Errorf("arguments must stay untouched, got %q", got)
	}

	// Streaming data line (arguments are incremental fragments — untouched).
	line := []byte(`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"write_file","arguments":"{\"fi"}}]}}]}`)
	out = RewriteOpencodeZenResponseToolNames(line, renamed)
	if got := gjson.GetBytes(out, "choices.0.delta.tool_calls.0.function.name").String(); got != "write" {
		t.Errorf("stream rename = %q, want write", got)
	}
	if got := gjson.GetBytes(out, "choices.0.delta.tool_calls.0.function.arguments").String(); got != `{"fi` {
		t.Errorf("stream arguments must stay untouched, got %q", got)
	}

	// Unrelated line unchanged.
	plain := []byte(`data: {"choices":[{"delta":{"content":"hi"}}]}`)
	if got := string(RewriteOpencodeZenResponseToolNames(plain, renamed)); got != string(plain) {
		t.Errorf("unrelated line must pass through, got %q", got)
	}
}

// TestRewriteOpencodeZenResponseToolNamesSkipsClientNamedAliases verifies the
// fix for the Copilot regression: a client whose own tool is ALREADY named
// read_file (no collision with the canonical read) must keep read_file in the
// response. Only aliases for tools the client actually declared under a
// colliding name are reversed.
func TestRewriteOpencodeZenResponseToolNamesSkipsClientNamedAliases(t *testing.T) {
	// Client declared read_file/write_file directly — no collision, no rename.
	renamed := map[string]bool{}

	body := []byte(`{"choices":[{"message":{"tool_calls":[
		{"function":{"name":"read_file","arguments":"{\"filePath\":\"/x\"}"}},
		{"function":{"name":"write_file","arguments":"{\"filePath\":\"/y\"}"}}
	]}}]}`)
	out := RewriteOpencodeZenResponseToolNames(body, renamed)
	calls := gjson.GetBytes(out, "choices.0.message.tool_calls").Array()
	if len(calls) != 2 {
		t.Fatalf("tool_calls = %d, want 2", len(calls))
	}
	if got := calls[0].Get("function.name").String(); got != "read_file" {
		t.Errorf("tool_calls[0] = %q, want read_file (client's real tool name)", got)
	}
	if got := calls[1].Get("function.name").String(); got != "write_file" {
		t.Errorf("tool_calls[1] = %q, want write_file (client's real tool name)", got)
	}
	if got := calls[0].Get("function.arguments").String(); got != `{"filePath":"/x"}` {
		t.Errorf("arguments must stay untouched, got %q", got)
	}
}

// TestRewriteOpencodeZenResponseToolNamesPartialAliases verifies that only
// the aliases whose client-side original was declared are reversed: a client
// declaring read but NOT write keeps read_file -> read while write_file stays
// untouched.
func TestRewriteOpencodeZenResponseToolNamesPartialAliases(t *testing.T) {
	renamed := map[string]bool{"read": true}

	body := []byte(`{"choices":[{"message":{"tool_calls":[
		{"function":{"name":"read_file"}},
		{"function":{"name":"write_file"}}
	]}}]}`)
	out := RewriteOpencodeZenResponseToolNames(body, renamed)
	calls := gjson.GetBytes(out, "choices.0.message.tool_calls").Array()
	if got := calls[0].Get("function.name").String(); got != "read" {
		t.Errorf("tool_calls[0] = %q, want read (client declared read)", got)
	}
	if got := calls[1].Get("function.name").String(); got != "write_file" {
		t.Errorf("tool_calls[1] = %q, want write_file (client did not declare write)", got)
	}
}

// TestRewriteOpencodeZenResponseAllAliases verifies every canonical-collision
// alias is rewritten back to its client name in one pass.
func TestRewriteOpencodeZenResponseAllAliases(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"tool_calls":[
		{"function":{"name":"read_file"}},
		{"function":{"name":"write_file"}},
		{"function":{"name":"delegate_task"}},
		{"function":{"name":"update_todos"}},
		{"function":{"name":"fetch_url"}},
		{"function":{"name":"web_search"}}
	]}}]}`)
	renamed := map[string]bool{"read": true, "write": true, "task": true, "todowrite": true, "webfetch": true, "websearch": true}
	out := RewriteOpencodeZenResponseToolNames(body, renamed)
	want := []string{"read", "write", "task", "todowrite", "webfetch", "websearch"}
	calls := gjson.GetBytes(out, "choices.0.message.tool_calls").Array()
	if len(calls) != len(want) {
		t.Fatalf("tool_calls = %d, want %d", len(calls), len(want))
	}
	for i, w := range want {
		if got := calls[i].Get("function.name").String(); got != w {
			t.Errorf("tool_calls[%d] = %q, want %q", i, got, w)
		}
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
