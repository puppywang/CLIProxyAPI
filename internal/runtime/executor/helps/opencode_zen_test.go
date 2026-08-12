package helps

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestOpencodeZenAssets(t *testing.T) {
	if !gjson.ValidBytes([]byte(opencodeZenTools)) {
		t.Fatal("opencode zen tools asset is not valid JSON")
	}
	tools := gjson.Parse(opencodeZenTools).Array()
	if len(tools) != 6 {
		t.Fatalf("opencode zen tools count = %d, want 6", len(tools))
	}
	expected := []string{"read", "task", "todowrite", "webfetch", "websearch", "write"}
	for i, name := range expected {
		if tools[i].Get("function.name").String() != name {
			t.Fatalf("opencode zen tool[%d] name = %q, want %q", i, tools[i].Get("function.name").String(), name)
		}
	}
	if !strings.HasPrefix(opencodeZenSystemPrompt, "You are opencode, an interactive CLI tool") {
		t.Fatal("opencode zen system prompt asset does not start with the canonical prompt")
	}
	if len(opencodeZenSystemPrompt) < 9000 {
		t.Fatalf("opencode zen system prompt length = %d, want >= 9000", len(opencodeZenSystemPrompt))
	}
}

func TestConvertOpenAIRequestToOpencodeZen(t *testing.T) {
	input := `{
		"model": "some-model",
		"max_tokens": 32000,
		"reasoning_effort": "max",
		"messages": [
			{"role": "system", "content": "client system instruction"},
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "hi"},
			{"role": "user", "content": "world"}
		],
		"tools": [{"type": "function", "function": {"name": "bash", "parameters": {}}}],
		"tool_choice": "required",
		"stream": true
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	if !gjson.ValidBytes(out) {
		t.Fatal("converted payload is not valid JSON")
	}
	messages := gjson.GetBytes(out, "messages").Array()
	if len(messages) != 4 {
		t.Fatalf("messages count = %d, want 4", len(messages))
	}
	if messages[0].Get("role").String() != "system" {
		t.Fatalf("messages[0] role = %q, want system", messages[0].Get("role").String())
	}
	if got := messages[0].Get("content").String(); got != OpencodeZenSystemPrompt() {
		t.Fatalf("messages[0].content does not match the canonical opencode prompt (len %d)", len(got))
	}
	if messages[1].Get("content").String() != "hello" || messages[2].Get("content").String() != "hi" || messages[3].Get("content").String() != "world" {
		t.Fatal("non-system messages were not preserved in order")
	}

	tools := gjson.GetBytes(out, "tools").Array()
	if len(tools) != 6 {
		t.Fatalf("tools count = %d, want 6", len(tools))
	}
	if tools[0].Get("function.name").String() != "read" {
		t.Fatalf("tools[0] = %q, want read", tools[0].Get("function.name").String())
	}
	if got := gjson.GetBytes(out, "tool_choice").String(); got != "auto" {
		t.Fatalf("tool_choice = %q, want auto", got)
	}
	if gjson.GetBytes(out, "stream").Bool() != true {
		t.Fatal("stream must be preserved as true")
	}
	if gjson.GetBytes(out, "stream_options.include_usage").Bool() != true {
		t.Fatal("stream_options.include_usage must be forced to true for streaming")
	}
	if gjson.GetBytes(out, "model").String() != "some-model" {
		t.Fatalf("model = %q, want some-model", gjson.GetBytes(out, "model").String())
	}
	if gjson.GetBytes(out, "max_tokens").Int() != 32000 || gjson.GetBytes(out, "reasoning_effort").String() != "max" {
		t.Fatal("max_tokens/reasoning_effort must pass through")
	}
}

func TestConvertOpenAIRequestToOpencodeZenNonStream(t *testing.T) {
	input := `{
		"model": "m",
		"messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "q"}],
		"stream": false
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	if gjson.GetBytes(out, "stream").Bool() != false {
		t.Fatal("non-streaming request must keep stream=false")
	}
	if gjson.GetBytes(out, "stream_options").Exists() {
		t.Fatal("non-streaming request must not gain stream_options")
	}
	if gjson.GetBytes(out, "messages.1.content").String() != "q" {
		t.Fatal("user message must be preserved")
	}
}

func TestConvertOpenAIRequestToOpencodeZenEscapingRoundTrip(t *testing.T) {
	input := `{"model": "m", "messages": [{"role": "user", "content": "D:\\HomeProject\\cli-request-monitor and <env> & quotes \"x\""}], "stream": true}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("converted payload must be decodable JSON: %v", err)
	}
	prompt, ok := doc["messages"].([]any)[0].(map[string]any)["content"].(string)
	if !ok {
		t.Fatal("system prompt must decode back to a plain string")
	}
	if prompt != OpencodeZenSystemPrompt() {
		t.Fatal("decoded system prompt differs from the canonical opencode prompt")
	}
	userContent := doc["messages"].([]any)[1].(map[string]any)["content"].(string)
	if userContent != `D:\HomeProject\cli-request-monitor and <env> & quotes "x"` {
		t.Fatalf("user content mangled by escaping: %q", userContent)
	}
}

func TestConvertOpenAIRequestToOpencodeZenNoOps(t *testing.T) {
	if out := ConvertOpenAIRequestToOpencodeZen(nil); out != nil {
		t.Fatal("nil payload must pass through")
	}
	invalid := []byte(`not json`)
	if out := ConvertOpenAIRequestToOpencodeZen(invalid); string(out) != "not json" {
		t.Fatal("invalid payload must pass through unchanged")
	}
}
