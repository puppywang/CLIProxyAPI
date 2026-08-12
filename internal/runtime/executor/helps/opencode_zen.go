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

// OpencodeZenMaxPayloadBytes caps the size of payloads forwarded to the zen
// gateway. Payloads above roughly 1MB are rejected with a
// FreeUsageLimitError, so oversized histories are trimmed to this budget.
const OpencodeZenMaxPayloadBytes = 1_000_000

// opencodeZenContextMarker marks content truncated by the proxy.
const opencodeZenContextMarker = "\n...[context truncated by proxy]...\n"

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
	out = enforceOpencodeZenPayloadBudget(out)
	return out
}

// enforceOpencodeZenPayloadBudget shrinks an over-budget payload by dropping
// the oldest messages (keeping the newest ones) and, when a single message
// exceeds the budget, truncating its content tail. The canonical system
// message is always retained.
func enforceOpencodeZenPayloadBudget(payload []byte) []byte {
	budget := OpencodeZenMaxPayloadBytes
	if len(payload) <= budget {
		return payload
	}
	rawMessages := gjson.GetBytes(payload, "messages").Raw
	if rawMessages == "" {
		return payload
	}
	parsed := gjson.Parse(rawMessages).Array()
	if len(parsed) == 0 {
		return payload
	}
	sysRaw := `{"role":"system","content":` + opencodeZenJSONString(opencodeZenSystemPrompt) + `}`
	kept := make([]string, 0, len(parsed)+1)
	kept = append(kept, sysRaw)
	for i := range parsed {
		kept = append(kept, parsed[i].Raw)
	}
	// Drop orphaned tool/function messages at the old edge after trimming;
	// their matching assistant tool_calls message has been dropped too.
	for len(kept) > 1 {
		role := gjson.Parse(kept[len(kept)-1]).Get("role").String()
		if role != "tool" && role != "function" {
			break
		}
		kept = kept[:len(kept)-1]
	}

	rebuild := func() ([]byte, int) {
		var b strings.Builder
		b.WriteByte('[')
		for i, raw := range kept {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(raw)
		}
		b.WriteByte(']')
		arr := b.String()
		out, err := sjson.SetRawBytes(payload, "messages", []byte(arr))
		if err != nil {
			return payload, len(payload)
		}
		return out, len(arr)
	}

	// dropOrphanedRemoves tool/function messages that became the oldest kept
	// message after trimming (their matching assistant tool_calls message was
	// dropped). Runs before every rebuild because each trim can expose a new
	// orphan at the old edge.
	dropOrphans := func() {
		for len(kept) > 1 {
			role := gjson.Parse(kept[1]).Get("role").String()
			if role != "tool" && role != "function" {
				break
			}
			kept = append(kept[:1], kept[2:]...)
		}
	}

	dropOrphans()
	for {
		out, arrLen := rebuild()
		if len(out) <= budget {
			return out
		}
		overhead := len(out) - arrLen
		if len(kept) <= 1 {
			// The system message alone cannot exhaust the budget; give up.
			return out
		}
		if len(kept) == 2 {
			avail := budget - overhead - len(sysRaw) - 3
			fitted, ok := fitOpencodeZenMessageToBudget(kept[1], avail)
			if !ok {
				kept = kept[:1]
				continue
			}
			kept[1] = fitted
			continue
		}
		// Keep trimming the oldest non-system message.
		kept = append(kept[:1], kept[2:]...)
		dropOrphans()
	}
}

// fitOpencodeZenMessageToBudget truncates a single message's content keeping
// its tail so the whole message raw fits within budgetBytes. Returns false
// when the message cannot fit even with empty content.
func fitOpencodeZenMessageToBudget(raw string, budgetBytes int) (string, bool) {
	if budgetBytes <= 0 {
		return "", false
	}
	res := gjson.Parse(raw)
	contentRes := res.Get("content")
	if !contentRes.Exists() {
		if len(raw) <= budgetBytes {
			return raw, true
		}
		return "", false
	}
	content := contentRes.String()
	head := raw[:contentRes.Index]
	tail := raw[contentRes.Index+len(contentRes.Raw):]
	headTailLen := len(head) + len(tail)
	if headTailLen > budgetBytes {
		return "", false
	}
	target := budgetBytes - headTailLen - len(opencodeZenContextMarker)

	// Find the smallest suffix length whose encoded form fits the target.
	lo, hi := 0, len(content)
	best := len(content)
	for lo <= hi {
		mid := (lo + hi) / 2
		encoded := opencodeZenJSONString(opencodeZenContextMarker + content[mid:])
		if len(encoded) <= target {
			best = mid
			hi = mid - 1
		} else {
			lo = mid + 1
		}
	}
	return head + opencodeZenJSONString(opencodeZenContextMarker+content[best:]) + tail, true
}
