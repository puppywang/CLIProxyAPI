package helps

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// TestConvertOpenAIRequestToOpencodeZenInjectionDisabled verifies the
// context-injection toggle: with injection off, the canonical opencode
// system prompt and the canonical six tools are NOT injected, the client's
// own prompt/tools/tool_choice pass through verbatim, and only the
// gateway-required legal-shape fixes remain (reasoning_content backfill,
// developer->system, include_usage, prompt_cache_key dropped).
func TestConvertOpenAIRequestToOpencodeZenInjectionDisabled(t *testing.T) {
	// Save and restore the global toggle around the test.
	prev := OpencodeZenInjectContextEnabled()
	SetOpencodeZenInjectContext(false)
	t.Cleanup(func() { SetOpencodeZenInjectContext(prev) })

	input := `{
		"model": "deepseek-v4-flash-free",
		"messages": [
			{"role": "system", "content": "client system instruction"},
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "bash", "arguments": "{}"}}]},
			{"role": "tool", "tool_call_id": "call_1", "content": "ok"}
		],
		"tools": [{"type": "function", "function": {"name": "bash", "parameters": {}}}],
		"tool_choice": "required",
		"stream": true,
		"prompt_cache_key": "sk-keep-away"
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	if !gjson.ValidBytes(out) {
		t.Fatal("converted payload is not valid JSON")
	}
	messages := gjson.GetBytes(out, "messages").Array()
	if len(messages) != 4 {
		t.Fatalf("messages count = %d, want 4 (no canonical prompt injected)", len(messages))
	}
	// Client system message preserved verbatim (no canonical prompt in front).
	if messages[0].Get("role").String() != "system" || messages[0].Get("content").String() != "client system instruction" {
		t.Fatalf("messages[0] must be the client system message verbatim, got %q", messages[0].Get("content").String())
	}
	// reasoning_content backfill must still happen on the tool-call turn.
	assistant := messages[2]
	if assistant.Get("role").String() != "assistant" {
		t.Fatalf("messages[2] role = %q, want assistant", assistant.Get("role").String())
	}
	if !assistant.Get("reasoning_content").Exists() {
		t.Fatal("reasoning_content backfill must remain active with injection off")
	}
	// Client tools / tool_choice untouched.
	tools := gjson.GetBytes(out, "tools").Array()
	if len(tools) != 1 {
		t.Fatalf("tools count = %d, want 1 (client tools only)", len(tools))
	}
	if tools[0].Get("function.name").String() != "bash" {
		t.Fatalf("tools[0] = %q, want client bash tool", tools[0].Get("function.name").String())
	}
	if got := gjson.GetBytes(out, "tool_choice").String(); got != "required" {
		t.Fatalf("tool_choice = %q, want client's required preserved", got)
	}
	// Legal-shape fixes still active.
	if gjson.GetBytes(out, "stream_options.include_usage").Bool() != true {
		t.Fatal("stream_options.include_usage must still be forced for streaming")
	}
	if gjson.GetBytes(out, "prompt_cache_key").Exists() {
		t.Fatal("prompt_cache_key must still be dropped")
	}
	// Model passthrough.
	if gjson.GetBytes(out, "model").String() != "deepseek-v4-flash-free" {
		t.Fatalf("model = %q, want deepseek-v4-flash-free", gjson.GetBytes(out, "model").String())
	}
}

// TestConvertOpenAIRequestToOpencodeZenInjectionDisabledDeveloperRole
// verifies that with injection off a "developer" message is still
// normalized to "system" (opencode-go rejects the developer role with 400).
func TestConvertOpenAIRequestToOpencodeZenInjectionDisabledDeveloperRole(t *testing.T) {
	prev := OpencodeZenInjectContextEnabled()
	SetOpencodeZenInjectContext(false)
	t.Cleanup(func() { SetOpencodeZenInjectContext(prev) })

	input := `{
		"model": "m",
		"messages": [
			{"role": "developer", "content": "client dev instruction"},
			{"role": "user", "content": "hello"}
		]
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	if !gjson.ValidBytes(out) {
		t.Fatal("converted payload is not valid JSON")
	}
	messages := gjson.GetBytes(out, "messages").Array()
	if len(messages) != 2 {
		t.Fatalf("messages count = %d, want 2", len(messages))
	}
	if messages[0].Get("role").String() != "system" {
		t.Fatalf("messages[0] role = %q, want system (developer normalized)", messages[0].Get("role").String())
	}
	if messages[0].Get("content").String() != "client dev instruction" {
		t.Fatalf("messages[0] content = %q, want client dev instruction preserved", messages[0].Get("content").String())
	}
	if strings.Contains(string(out), "You are opencode") {
		t.Fatalf("payload must NOT contain the canonical opencode prompt with injection off; out=%s", out)
	}
}
