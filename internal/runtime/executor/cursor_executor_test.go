package executor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCursorVariantParams(t *testing.T) {
	cases := []struct {
		model, effort string
		want          string // json of params, or "nil"
	}{
		{"cursor-kimi-k3", "", `[{"id":"reasoning","value":"max"}]`},
		{"cursor-grok-4.6-fast", "", `[{"id":"effort","value":"medium"},{"id":"fast","value":"true"}]`},
		{"cursor-claude-opus-5", "", `[{"id":"cyber","value":"false"},{"id":"thinking","value":"false"},{"id":"context","value":"300k"},{"id":"effort","value":"medium"},{"id":"fast","value":"false"}]`},
		{"cursor-gpt-5.6-sol-fast", "xhigh", `[{"id":"context","value":"272k"},{"id":"reasoning","value":"xhigh"},{"id":"fast","value":"true"}]`},
		{"cursor-gpt-5.4-mini", "", `[{"id":"reasoning","value":"medium"}]`},
		{"cursor-gpt-5.4", "", `[{"id":"context","value":"272k"},{"id":"reasoning","value":"medium"},{"id":"fast","value":"false"}]`},
		{"cursor-gemini-3.1-pro", "", `nil`},
		// clamp cases: reasoning_effort=max on families without max
		{"cursor-grok-4.6-fast", "max", `[{"id":"effort","value":"xhigh"},{"id":"fast","value":"true"}]`},
		{"cursor-grok-4.6", "max", `[{"id":"effort","value":"xhigh"},{"id":"fast","value":"false"}]`},
		{"cursor-grok-4.5", "xhigh", `[{"id":"effort","value":"high"},{"id":"fast","value":"false"}]`},
		{"cursor-grok-4.5-fast", "max", `[{"id":"effort","value":"high"},{"id":"fast","value":"true"}]`},
		{"cursor-gpt-5.5", "xhigh", `[{"id":"context","value":"272k"},{"id":"reasoning","value":"extra-high"},{"id":"fast","value":"false"}]`},
		{"cursor-gpt-5.4", "max", `[{"id":"context","value":"272k"},{"id":"reasoning","value":"extra-high"},{"id":"fast","value":"false"}]`},
		{"cursor-gpt-5.4-mini", "max", `[{"id":"reasoning","value":"xhigh"}]`},
		{"cursor-gpt-5.4-nano", "xhigh", `[{"id":"reasoning","value":"xhigh"}]`},
		{"cursor-gpt-5.1", "max", `[{"id":"reasoning","value":"high"}]`},
		{"cursor-gpt-5.2", "max", `[{"id":"reasoning","value":"extra-high"},{"id":"fast","value":"false"}]`},
		{"cursor-kimi-k3", "medium", `[{"id":"reasoning","value":"max"}]`},
		{"cursor-kimi-k3", "xhigh", `[{"id":"reasoning","value":"max"}]`},
		{"cursor-glm-5.2", "medium", `[{"id":"reasoning","value":"max"}]`},
		{"cursor-glm-5.2", "low", `[{"id":"reasoning","value":"high"}]`},
		{"cursor-gemini-3.6-flash", "max", `[{"id":"effort","value":"high"}]`},
		{"cursor-gemini-3.6-flash", "xhigh", `[{"id":"effort","value":"high"}]`},
	}
	for _, c := range cases {
		got := cursorVariantParams(c.model, c.effort)
		var gotJSON string
		if got == nil {
			gotJSON = "nil"
		} else {
			b, _ := json.Marshal(got)
			gotJSON = string(b)
		}
		if gotJSON != c.want {
			t.Errorf("%s effort=%q: got %s want %s", c.model, c.effort, gotJSON, c.want)
		}
	}
}

func TestCursorPromptFromPayloadResourceParts(t *testing.T) {
	// Simulates a Copilot request: user text + workspace resource part.
	payload := []byte(`{
		"messages": [
			{"role":"system","content":"You are a coding assistant."},
			{"role":"user","content":[
				{"type":"text","text":"帮我改这个文件"},
				{"type":"resource","resource":{"uri":"file:///d:/proj/main.go","text":"package main\nfunc main(){}"}},
				{"type":"image_url","image_url":{"url":"data:image/png;base64,xxx"}}
			]}
		]
	}`)
	out := cursorPromptFromPayload(payload)
	for _, want := range []string{
		"[System]",
		"帮我改这个文件",
		"[File: file:///d:/proj/main.go]",
		"package main",
		"[Image omitted: direct prompt encoder does not yet carry inline images]",
		"简体中文",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt missing %q — got:\n%s", want, out)
		}
	}
}

func TestCursorAppendLangHint(t *testing.T) {
	// CJK prompt -> hint appended
	cn := cursorAppendLangHint("帮我看看这个代码")
	if !strings.Contains(cn, "简体中文") {
		t.Errorf("CJK prompt should get lang hint, got:\n%s", cn)
	}
	// English prompt -> no hint
	en := cursorAppendLangHint("explain this code")
	if strings.Contains(en, "简体中文") {
		t.Errorf("English prompt should NOT get lang hint, got:\n%s", en)
	}
	// Empty -> empty
	if got := cursorAppendLangHint(""); got != "" {
		t.Errorf("empty prompt should stay empty, got %q", got)
	}
}
