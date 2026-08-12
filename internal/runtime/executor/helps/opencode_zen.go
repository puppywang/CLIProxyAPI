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

// OpencodeZenClientToolNote exposes the guard note injected for clients that
// ship their own tool environment.
func OpencodeZenClientToolNote() string {
	return opencodeZenClientToolNote
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

// opencodeZenClientToolNote is appended as an extra system message when the
// client request carries its own tool set (e.g. GitHub Copilot's workspace
// tools). The canonical six tools must remain in the payload for the gateway
// check, but the model must not call tools its environment cannot execute.
const opencodeZenClientToolNote = "Note: your environment provides its own tool set; call only the tools that this environment exposes. Do not call read, task, todowrite, webfetch, websearch, or write unless they are listed among your environment's tools (they are placeholder definitions required by the gateway)."

// ConvertOpenAIRequestToOpencodeZen rewrites an OpenAI chat completions payload
// into a shape the opencode zen gateway recognizes as a genuine opencode CLI
// request while preserving the client's own instructions and tools:
//
//  1. messages[0] becomes a single system message carrying the real opencode
//     system prompt; client-provided system messages are preserved verbatim as
//     additional system messages and other messages keep their order.
//  2. tools is the canonical opencode tool set
//     (read/task/todowrite/webfetch/websearch/write) followed by any client
//     tools not already present; tool_choice is "auto".
//  3. stream_options.include_usage is forced to true for streaming requests so
//     usage accounting survives the gateway.
//
// The zen gateway requires the canonical system prompt and the canonical six
// tools to be fully present; everything else in the payload is mergeable.
// All other fields (model, max_tokens, reasoning_effort, stream, ...) pass
// through unchanged.
func ConvertOpenAIRequestToOpencodeZen(payload []byte) []byte {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return payload
	}

	rawMessages := gjson.GetBytes(payload, "messages").Raw
	sysRaw := `{"role":"system","content":` + opencodeZenJSONString(opencodeZenSystemPrompt) + `}`
	rebuilt := "[" + sysRaw

	// Client system messages come right after the canonical one, verbatim.
	gjson.Parse(rawMessages).ForEach(func(_, value gjson.Result) bool {
		if value.Get("role").String() == "system" {
			rebuilt += "," + value.Raw
		}
		return true
	})
	// Clients that ship their own tools (Copilot, ...) must not call the
	// canonical six; add a guard note so the model sticks to its own tools.
	if clientHasOwnTools(payload) {
		rebuilt += `,{"role":"system","content":` + opencodeZenJSONString(opencodeZenClientToolNote) + `}`
	}
	// All other messages keep their original order.
	gjson.Parse(rawMessages).ForEach(func(_, value gjson.Result) bool {
		if value.Get("role").String() != "system" {
			rebuilt += "," + value.Raw
		}
		return true
	})
	rebuilt += "]"

	out, err := sjson.SetRawBytes(payload, "messages", []byte(rebuilt))
	if err != nil {
		return payload
	}
	out, err = sjson.SetRawBytes(out, "tools", []byte(mergeOpencodeZenTools(payload)))
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

// clientHasOwnTools reports whether the client request declares tools other
// than the canonical opencode six, meaning it runs in its own tool
// environment (e.g. GitHub Copilot).
func clientHasOwnTools(payload []byte) bool {
	hasOwn := false
	gjson.GetBytes(payload, "tools").ForEach(func(_, tool gjson.Result) bool {
		name := tool.Get("function.name").String()
		switch name {
		case "read", "task", "todowrite", "webfetch", "websearch", "write":
			return true
		}
		if name != "" {
			hasOwn = true
		}
		return true
	})
	return hasOwn
}

// mergeOpencodeZenTools returns the client's own tools (deduplicated by
// function name, listed first so the model prefers its environment's tools)
// followed by the canonical opencode tool set. A tool whose name collides with
// one of the canonical six is always emitted in its canonical form so the
// gateway validation still passes.
func mergeOpencodeZenTools(payload []byte) string {
	canonicalNames := map[string]struct{}{
		"read": {}, "task": {}, "todowrite": {},
		"webfetch": {}, "websearch": {}, "write": {},
	}
	var clientTools []string
	seen := make(map[string]struct{}, 8)
	gjson.GetBytes(payload, "tools").ForEach(func(_, tool gjson.Result) bool {
		name := tool.Get("function.name").String()
		if name == "" {
			return true
		}
		if _, isCanonical := canonicalNames[name]; isCanonical {
			return true
		}
		if _, dup := seen[name]; dup {
			return true
		}
		seen[name] = struct{}{}
		clientTools = append(clientTools, tool.Raw)
		return true
	})

	var b strings.Builder
	b.WriteByte('[')
	first := true
	for _, raw := range clientTools {
		if !first {
			b.WriteByte(',')
		}
		b.WriteString(raw)
		first = false
	}
	for _, tool := range gjson.Parse(opencodeZenTools).Array() {
		if !first {
			b.WriteByte(',')
		}
		b.WriteString(tool.Raw)
		first = false
	}
	b.WriteByte(']')
	return b.String()
}

// enforceOpencodeZenPayloadBudget shrinks an over-budget payload by dropping
// the oldest non-system messages (keeping the newest ones) and, when a single
// message exceeds the budget, truncating its content tail. Canonical and
// client system messages are always retained.
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
	// Convert already injects the canonical system prompt as messages[0];
	// only prepend another one when it is missing (direct callers).
	if len(parsed) == 0 || gjson.Parse(parsed[0].Raw).Get("role").String() != "system" {
		kept = append(kept, sysRaw)
	}
	for i := range parsed {
		kept = append(kept, parsed[i].Raw)
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

	isSystem := func(raw string) bool {
		return gjson.Parse(raw).Get("role").String() == "system"
	}
	// firstMessage returns the index of the oldest non-system message, or -1.
	firstMessage := func() int {
		for i := 1; i < len(kept); i++ {
			if !isSystem(kept[i]) {
				return i
			}
		}
		return -1
	}

	// dropOrphans removes tool/function messages at the old edge (their
	// matching assistant tool_calls message was dropped by trimming).
	dropOrphans := func() {
		for {
			i := firstMessage()
			if i < 0 {
				return
			}
			role := gjson.Parse(kept[i]).Get("role").String()
			if role != "tool" && role != "function" {
				return
			}
			kept = append(kept[:i], kept[i+1:]...)
		}
	}

	dropOrphans()
	for {
		out, arrLen := rebuild()
		if len(out) <= budget {
			return out
		}
		overhead := len(out) - arrLen
		i := firstMessage()
		if i < 0 {
			// Only system messages remain; nothing else can be trimmed.
			return out
		}
		if i == len(kept)-1 {
			// The single remaining non-system message: truncate instead of
			// dropping so the newest turn is always preserved.
			avail := budget - overhead - (arrLen - len(kept[i]) - 1)
			fitted, ok := fitOpencodeZenMessageToBudget(kept[i], avail)
			if !ok {
				kept = append(kept[:i], kept[i+1:]...)
				continue
			}
			kept[i] = fitted
			continue
		}
		// Keep trimming the oldest non-system message.
		kept = append(kept[:i], kept[i+1:]...)
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
