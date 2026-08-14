package helps

import (
	"testing"

	"github.com/tidwall/gjson"
)

// TestNormalizeOpenAIChatRoles verifies the developer->system normalization
// for chat.completions payloads (the opengo / opencode-go upstream case that
// 400s on role "developer").
func TestNormalizeOpenAIChatRoles(t *testing.T) {
	input := []byte(`{
		"model": "deepseek-v4-flash",
		"messages": [
			{"role": "developer", "content": "system instructions here"},
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "hi"},
			{"role": "developer", "content": "another dev message"}
		]
	}`)
	out := NormalizeOpenAIChatRoles(input)
	messages := gjson.GetBytes(out, "messages").Array()
	if len(messages) != 4 {
		t.Fatalf("messages count = %d, want 4", len(messages))
	}
	if messages[0].Get("role").String() != "system" {
		t.Fatalf("messages[0].role = %q, want system", messages[0].Get("role").String())
	}
	if messages[0].Get("content").String() != "system instructions here" {
		t.Fatalf("messages[0].content lost: %q", messages[0].Get("content").String())
	}
	if messages[3].Get("role").String() != "system" {
		t.Fatalf("messages[3].role = %q, want system", messages[3].Get("role").String())
	}
	if messages[1].Get("role").String() != "user" || messages[2].Get("role").String() != "assistant" {
		t.Fatal("non-developer messages must pass through untouched")
	}
	// No developer role may survive.
	for i, m := range messages {
		if m.Get("role").String() == "developer" {
			t.Fatalf("messages[%d] still developer: %s", i, m.Raw)
		}
	}
}

// TestNormalizeOpenAIChatRolesNoOp verifies payloads without a messages array
// or without developer roles are returned byte-for-byte.
func TestNormalizeOpenAIChatRolesNoOp(t *testing.T) {
	cases := [][]byte{
		// No messages array (responses dialect uses input; must be untouched).
		[]byte(`{"model":"m","input":[{"type":"message","role":"developer","content":"x"}]}`),
		// Messages without developer.
		[]byte(`{"model":"m","messages":[{"role":"system","content":"s"},{"role":"user","content":"u"}]}`),
		// Invalid JSON.
		[]byte(`{not json`),
		// Empty.
		{},
	}
	for _, c := range cases {
		out := NormalizeOpenAIChatRoles(c)
		if string(out) != string(c) {
			t.Fatalf("expected no-op for %s, got %s", string(c), string(out))
		}
	}
}

// TestNormalizeOpenAIChatRolesNonChatKeepsDeveloper verifies the responses
// dialect ("input" array) keeps developer untouched — it is a legal role there.
func TestNormalizeOpenAIChatRolesNonChatKeepsDeveloper(t *testing.T) {
	input := []byte(`{"model":"m","input":[{"type":"message","role":"developer","content":"x"}]}`)
	out := NormalizeOpenAIChatRoles(input)
	if string(out) != string(input) {
		t.Fatalf("responses-dialect payload must be untouched, got %s", string(out))
	}
}
