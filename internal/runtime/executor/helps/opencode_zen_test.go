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
	if len(messages) != 6 {
		t.Fatalf("messages count = %d, want 6", len(messages))
	}
	if messages[0].Get("role").String() != "system" {
		t.Fatalf("messages[0] role = %q, want system", messages[0].Get("role").String())
	}
	// A client shipping its own tools gets the trimmed canonical prompt so
	// the opencode env/skills tail cannot steer it; the gateway-verified
	// prefix must still be present.
	if got := messages[0].Get("content").String(); got != OpencodeZenSystemPromptTrimmed() {
		t.Fatalf("messages[0].content does not match the trimmed opencode prompt (len %d, want %d)", len(got), len(OpencodeZenSystemPromptTrimmed()))
	}
	if !strings.Contains(messages[0].Get("content").String(), "<system-reminder>") {
		t.Fatal("trimmed prompt must keep the full <system-reminder> marker")
	}
	if strings.Contains(messages[0].Get("content").String(), "<available_skills>") {
		t.Fatal("trimmed prompt must not contain the skills tail")
	}
	if messages[1].Get("content").String() != "client system instruction" {
		t.Fatalf("client system message must be preserved, got %q", messages[1].Get("content").String())
	}
	if messages[2].Get("content").String() != OpencodeZenClientToolNote() {
		t.Fatalf("messages[2] = %q, want the client tool guard note", messages[2].Get("content").String())
	}
	if messages[3].Get("content").String() != "hello" || messages[4].Get("content").String() != "hi" || messages[5].Get("content").String() != "world" {
		t.Fatal("non-system messages were not preserved in order")
	}

	tools := gjson.GetBytes(out, "tools").Array()
	if len(tools) != 7 {
		t.Fatalf("tools count = %d, want 7", len(tools))
	}
	if tools[0].Get("function.name").String() != "bash" {
		t.Fatalf("tools[0] = %q, want client bash tool first", tools[0].Get("function.name").String())
	}
	if tools[1].Get("function.name").String() != "read" {
		t.Fatalf("tools[1] = %q, want canonical read tool second", tools[1].Get("function.name").String())
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

func TestConvertOpenAIRequestToOpencodeZenDeduplicatesCanonicalTools(t *testing.T) {
	input := `{
		"model": "m",
		"messages": [{"role": "user", "content": "q"}],
		"tools": [
			{"type": "function", "function": {"name": "read", "parameters": {}}},
			{"type": "function", "function": {"name": "special_tool", "parameters": {}}}
		],
		"stream": true
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	tools := gjson.GetBytes(out, "tools").Array()
	// client read + special_tool + canonical six (read duplicated for gateway)
	if len(tools) != 8 {
		t.Fatalf("tools count = %d, want 8 (client read + special_tool + canonical 6)", len(tools))
	}
	// Client-declared tools are listed first and keep their own definition.
	if tools[0].Get("function.name").String() != "read" {
		t.Fatalf("tools[0] = %q, want client read first", tools[0].Get("function.name").String())
	}
	if tools[1].Get("function.name").String() != "special_tool" {
		t.Fatalf("tools[1] = %q, want special_tool", tools[1].Get("function.name").String())
	}
	// Canonical six must all be present (gateway 429 guard), read/write may
	// appear twice (client + canonical).
	for _, name := range []string{"task", "todowrite", "webfetch", "websearch"} {
		count := 0
		for _, tool := range tools {
			if tool.Get("function.name").String() == name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("tool %q must appear exactly once, got %d", name, count)
		}
	}
	for _, name := range []string{"read", "write"} {
		count := 0
		for _, tool := range tools {
			if tool.Get("function.name").String() == name {
				count++
			}
		}
		if count < 1 {
			t.Fatalf("canonical tool %q must be present, got %d", name, count)
		}
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
	if gjson.GetBytes(out, "messages.2.content").String() != "q" {
		t.Fatal("user message must be preserved")
	}
	if gjson.GetBytes(out, "messages.1.content").String() != "x" {
		t.Fatal("client system message must be preserved")
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

func TestOpencodeZenClientToolNoteOnlyForOwnTools(t *testing.T) {
	withOwn := `{"model":"m","messages":[{"role":"user","content":"q"}],"tools":[{"type":"function","function":{"name":"bash","parameters":{}}}],"stream":true}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(withOwn))
	messages := gjson.GetBytes(out, "messages").Array()
	found := false
	for _, m := range messages {
		if m.Get("content").String() == OpencodeZenClientToolNote() {
			found = true
		}
	}
	if !found {
		t.Fatal("client tool note must be injected when client ships its own tools")
	}

	canonicalOnly := `{"model":"m","messages":[{"role":"user","content":"q"}],"tools":[{"type":"function","function":{"name":"read","parameters":{}}}],"stream":true}`
	out = ConvertOpenAIRequestToOpencodeZen([]byte(canonicalOnly))
	messages = gjson.GetBytes(out, "messages").Array()
	for _, m := range messages {
		if m.Get("content").String() == OpencodeZenClientToolNote() {
			t.Fatal("client tool note must NOT be injected when only canonical tools are present")
		}
	}
}

func TestOpencodeZenEnsureReasoningContent(t *testing.T) {
	// assistant with tool_calls but no reasoning_content -> field added empty
	raw := `{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"read","arguments":"{}"}}]}`
	out := OpencodeZenEnsureReasoningContent(raw)
	if !gjson.Get(out, "reasoning_content").Exists() {
		t.Fatal("reasoning_content must be added")
	}
	if got := gjson.Get(out, "reasoning_content").String(); got != "" {
		t.Fatalf("reasoning_content = %q, want empty", got)
	}
	// existing reasoning_content untouched
	withRC := `{"role":"assistant","content":"","reasoning_content":"think","tool_calls":[{"id":"c1","type":"function","function":{"name":"read","arguments":"{}"}}]}`
	if out2 := OpencodeZenEnsureReasoningContent(withRC); out2 != withRC {
		t.Fatal("existing reasoning_content must be preserved verbatim")
	}
	// plain assistant without tool_calls -> untouched
	plain := `{"role":"assistant","content":"hello"}`
	if out3 := OpencodeZenEnsureReasoningContent(plain); out3 != plain {
		t.Fatal("plain assistant must be untouched")
	}
	// user message untouched
	user := `{"role":"user","content":"hi"}`
	if out4 := OpencodeZenEnsureReasoningContent(user); out4 != user {
		t.Fatal("user message must be untouched")
	}
}

func TestOpencodeZenRepeatNoteDetection(t *testing.T) {
	// 3 identical grep calls -> note must be produced.
	three := `[
		{"role":"user","content":"check it"},
		{"role":"assistant","content":"","tool_calls":[{"id":"a1","type":"function","function":{"name":"grep_search","arguments":"{\"query\":\"Flush|Hijack\"}"}}]},
		{"role":"tool","tool_call_id":"a1","content":"Found 1 match"},
		{"role":"assistant","content":"","tool_calls":[{"id":"a2","type":"function","function":{"name":"grep_search","arguments":"{\"query\":\"Flush|Hijack\"}"}}]},
		{"role":"tool","tool_call_id":"a2","content":"Found 1 match"},
		{"role":"assistant","content":"","tool_calls":[{"id":"a3","type":"function","function":{"name":"grep_search","arguments":"{\"query\":\"Flush|Hijack\"}"}}]},
		{"role":"tool","tool_call_id":"a3","content":"Found 1 match"}
	]`
	if note := OpencodeZenRepeatNote(three); note == "" {
		t.Fatal("repeat note expected for 3 identical tool calls, got empty")
	} else if !strings.Contains(note, "grep_search") {
		t.Fatalf("note should name the repeated tool, got %q", note)
	}

	// Different arguments must NOT trigger.
	diff := `[
		{"role":"user","content":"check it"},
		{"role":"assistant","content":"","tool_calls":[{"id":"a1","type":"function","function":{"name":"grep_search","arguments":"{\"query\":\"A\"}"}}]},
		{"role":"tool","tool_call_id":"a1","content":"Found 1 match"},
		{"role":"assistant","content":"","tool_calls":[{"id":"a2","type":"function","function":{"name":"grep_search","arguments":"{\"query\":\"B\"}"}}]},
		{"role":"tool","tool_call_id":"a2","content":"Found 1 match"},
		{"role":"assistant","content":"","tool_calls":[{"id":"a3","type":"function","function":{"name":"grep_search","arguments":"{\"query\":\"C\"}"}}]},
		{"role":"tool","tool_call_id":"a3","content":"Found 1 match"}
	]`
	if note := OpencodeZenRepeatNote(diff); note != "" {
		t.Fatalf("no note expected for different calls, got %q", note)
	}

	// 2 occurrences (below threshold) must NOT trigger.
	twice := `[
		{"role":"assistant","content":"","tool_calls":[{"id":"a1","type":"function","function":{"name":"read","arguments":"{\"filePath\":\"x\"}"}}]},
		{"role":"tool","tool_call_id":"a1","content":"content"},
		{"role":"assistant","content":"","tool_calls":[{"id":"a2","type":"function","function":{"name":"read","arguments":"{\"filePath\":\"x\"}"}}]},
		{"role":"tool","tool_call_id":"a2","content":"content"}
	]`
	if note := OpencodeZenRepeatNote(twice); note != "" {
		t.Fatalf("no note expected below threshold, got %q", note)
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
