package helps

import (
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// opencodeZenSystemPrompt is the exact system prompt captured from a real
// opencode CLI request. The zen gateway performs a content-based check on the
// system message, so this text must match byte-for-byte.
//
//go:embed opencode_zen_system_prompt.txt
var opencodeZenSystemPrompt string

// opencodeZenTools is the exact tools array captured from the same request.
//
//go:embed opencode_zen_tools.json
var opencodeZenTools string

// OpencodeZenSystemPrompt exposes the canonical opencode system prompt.
func OpencodeZenSystemPrompt() string {
	return opencodeZenSystemPrompt
}

// OpencodeZenToolsJSON exposes the canonical opencode tools array as JSON text.
func OpencodeZenToolsJSON() string {
	return opencodeZenTools
}

// OpencodeZenUserAgent is the User-Agent the real opencode CLI sends.
const OpencodeZenUserAgent = "opencode/1.18.16 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14"

// OpencodeZenAPIKey is the anonymous bearer key accepted by the zen gateway.
const OpencodeZenAPIKey = "public"

// opencodeZenJSONString escapes text as a JSON string literal using the same
// escaping the opencode CLI produces (json.Marshal plus un-escaped <, >, &).
func opencodeZenJSONString(text string) string {
	encoded, err := json.Marshal(text)
	if err != nil {
		return `""`
	}
	replacer := strings.NewReplacer(
		`\u003c`, `<`,
		`\u003e`, `>`,
		`\u0026`, `&`,
	)
	return replacer.Replace(string(encoded))
}

// ConvertOpenAIRequestToOpencodeZen rewrites an OpenAI chat completions payload
// into the exact shape the opencode zen gateway recognizes as a genuine
// opencode CLI request:
//
//  1. messages[0] becomes a single system message carrying the real opencode
//     system prompt; client-provided system messages are dropped and other
//     messages are preserved in order.
//  2. tools is replaced by the canonical opencode tool set
//     (read/task/todowrite/webfetch/websearch/write) and tool_choice is "auto".
//  3. stream_options.include_usage is forced to true for streaming requests so
//     usage accounting survives the gateway.
//
// All other fields (model, max_tokens, reasoning_effort, stream, ...) pass
// through unchanged.
func ConvertOpenAIRequestToOpencodeZen(payload []byte) []byte {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return payload
	}

	rawMessages := gjson.GetBytes(payload, "messages").Raw
	rebuilt := `[{"role":"system","content":` + opencodeZenJSONString(opencodeZenSystemPrompt) + `}`
	gjson.Parse(rawMessages).ForEach(func(_, value gjson.Result) bool {
		role := value.Get("role").String()
		if role == "system" {
			return true
		}
		rebuilt += "," + value.Raw
		return true
	})
	rebuilt += "]"

	out, err := sjson.SetRawBytes(payload, "messages", []byte(rebuilt))
	if err != nil {
		return payload
	}
	out, err = sjson.SetRawBytes(out, "tools", []byte(opencodeZenTools))
	if err != nil {
		return payload
	}
	out, err = sjson.SetRawBytes(out, "tool_choice", []byte(`"auto"`))
	if err != nil {
		return payload
	}
	if gjson.GetBytes(out, "stream").Bool() {
		out, err = sjson.SetRawBytes(out, "stream_options.include_usage", []byte(`true`))
		if err != nil {
			return payload
		}
	}
	// The gateway validates against the canonical body; drop proxy-only fields.
	out, _ = sjson.DeleteBytes(out, "prompt_cache_key")
	return out
}
