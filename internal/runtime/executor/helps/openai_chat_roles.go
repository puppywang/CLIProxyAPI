package helps

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// NormalizeOpenAIChatRoles rewrites role "developer" messages to "system"
// inside the chat.completions "messages" array. Newer OpenAI SDKs (and
// Cursor's client) emit system prompts with role "developer", which is the
// Responses-dialect alias for system; several OpenAI-compatible upstreams —
// notably the opencode-go / Console Go gateway — reject it with
// 400 "unknown variant `developer`" because their Rust deserializer only
// accepts system/user/assistant/tool/latest_reminder.
//
// Only the chat.completions "messages" array is touched. The responses
// dialect keeps "developer" as a first-class legal role in its "input"
// array, so that shape is left untouched. Messages that do not carry
// "developer" are passed through byte-for-byte; when nothing changes the
// original payload is returned as-is.
func NormalizeOpenAIChatRoles(payload []byte) []byte {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return payload
	}
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}
	arr := messages.Array()
	changed := false
	kept := make([]string, 0, len(arr))
	for _, m := range arr {
		if m.Get("role").String() == "developer" {
			raw, err := sjson.SetRawBytes([]byte(m.Raw), "role", []byte(`"system"`))
			if err == nil {
				kept = append(kept, string(raw))
				changed = true
				continue
			}
		}
		kept = append(kept, m.Raw)
	}
	if !changed {
		return payload
	}
	rebuilt := "[" + strings.Join(kept, ",") + "]"
	updated, err := sjson.SetRawBytes(payload, "messages", []byte(rebuilt))
	if err != nil {
		return payload
	}
	return updated
}
