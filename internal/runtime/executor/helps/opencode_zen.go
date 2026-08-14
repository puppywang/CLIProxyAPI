package helps

import (
	_ "embed"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
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

// DebugZenRequestShape logs a compact shape summary of the converted zen
// request so looping histories (repeated identical tool calls) can be
// diagnosed from the server logs: message roles with counts, how many tool
// results exist, and the last few message roles with their sizes.
func DebugZenRequestShape(payload []byte) {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return
	}
	msgs := gjson.GetBytes(payload, "messages")
	if !msgs.Exists() {
		return
	}
	var roleSeq []string
	roleCount := make(map[string]int)
	// Track tool_calls ↔ tool result pairing consistency:
	// pendingToolCallIDs remembers ids announced by assistant messages so we
	// can spot tool results that reference *unknown* call ids (orphan results)
	// or assistant messages whose calls never got a result.
	pending := make(map[string]bool)
	var toolCalls, toolResults, orphanResults, unmatchedCalls int
	msgs.ForEach(func(_, m gjson.Result) bool {
		role := m.Get("role").String()
		if role == "" {
			role = "?"
		}
		roleSeq = append(roleSeq, role)
		roleCount[role]++
		switch role {
		case "assistant":
			calls := m.Get("tool_calls").Array()
			if len(calls) > 0 {
				toolCalls += len(calls)
			}
			for _, c := range calls {
				id := c.Get("id").String()
				if id != "" {
					pending[id] = true
				}
			}
		case "tool", "function":
			if m.Get("content").String() != "" {
				toolResults++
			}
			id := m.Get("tool_call_id").String()
			if id != "" && pending[id] {
				pending[id] = false
			} else if id != "" {
				orphanResults++
			}
		}
		return true
	})
	for _, answered := range pending {
		if answered {
			unmatchedCalls++
		}
	}
	// Summarise long sequences so the log stays readable (e.g. "u,a,t ×5").
	compact := make([]string, 0, len(roleSeq))
	for start := 0; start < len(roleSeq); {
		end := start + 1
		for end < len(roleSeq) && roleSeq[end] == roleSeq[start] {
			end++
		}
		if end-start >= 3 {
			compact = append(compact, roleSeq[start]+"×"+fmt.Sprint(end-start))
		} else {
			for i := start; i < end; i++ {
				compact = append(compact, roleSeq[i])
			}
		}
		start = end
	}
	tail := roleSeq
	if len(tail) > 8 {
		tail = roleSeq[len(roleSeq)-8:]
	}
	log.Debugf("opencode zen: shape roles=%s counts=%v toolCalls=%d toolResults=%d orphanResults=%d unmatchedCalls=%d tail=%v",
		strings.Join(compact, ","), roleCount, toolCalls, toolResults, orphanResults, unmatchedCalls, tail)
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

// opencodeZenEnsureReasoningContent returns the message raw JSON, adding an
// empty reasoning_content field to assistant messages that carry tool_calls
// but no reasoning_content. The DeepSeek thinking-mode gateway rejects
// requests where a tool-calling assistant turn is resent without its
// reasoning_content ("reasoning_content in the thinking mode must be passed
// back to the API"); Copilot session histories are not guaranteed to retain
// the field (e.g. across compaction or model switches), so the empty field
// satisfies the gateway without inventing content the model never produced.
func opencodeZenEnsureReasoningContent(m gjson.Result) string {
	if m.Get("role").String() != "assistant" {
		return m.Raw
	}
	if len(m.Get("tool_calls").Array()) == 0 {
		return m.Raw
	}
	if m.Get("reasoning_content").Exists() {
		return m.Raw
	}
	out, err := sjson.SetRawBytes([]byte(m.Raw), "reasoning_content", []byte(`""`))
	if err != nil {
		return m.Raw
	}
	return string(out)
}

// OpencodeZenEnsureReasoningContent exposes the helper for tests.
func OpencodeZenEnsureReasoningContent(raw string) string {
	return opencodeZenEnsureReasoningContent(gjson.Parse(raw))
}

// opencodeZenClientToolNote is appended as an extra system message when the
// client request carries its own tool set (e.g. DeepSeek Harness, GitHub
// Copilot). The canonical six tools must remain in the payload for the gateway
// check, but the model must not call tools its environment cannot execute —
// and the opencode system prompt's tool policy does not apply either.
const opencodeZenClientToolNote = "Note: you are running inside your own tool environment. The opencode system prompt above and its six tools (read, task, todowrite, webfetch, websearch, write) are placeholder definitions required by the API gateway — ignore their descriptions and usage policy, and DO NOT call them. Use ONLY the tools that your environment exposes; they are listed first and carry your environment's real parameter schemas."

// opencodeZenToolRename maps client tool names that collide with the
// canonical opencode six onto meaningful model-facing names. The client's own
// schema (parameters/description) is preserved verbatim under the new name;
// responses are renamed back before returning to the client. The names are
// chosen to be self-describing and familiar to models (MCP/Claude-Code style)
// so the agent prefers them over the canonical placeholders.
//
// All six canonical names are covered, because any of them can collide with a
// client-declared tool (Copilot ships task; harness-style runtimes often
// declare their own todo/web tools). A collision that is NOT aliased would
// either duplicate the name upstream ("Tool names must be unique") or replace
// the canonical definition (gateway 429 risk).
var opencodeZenToolRename = map[string]string{
	"read":      "read_file",      // MCP-style
	"write":     "write_file",     // MCP-style
	"task":      "delegate_task",  // opencode task spawns a sub-agent
	"todowrite": "update_todos",   // semantic: update the task list
	"webfetch":  "fetch_url",      // semantic: fetch a URL
	"websearch": "web_search",     // Claude Code official name
}

// opencodeZenModelToolName returns the model-facing name for a client tool,
// or the original name when no rename applies.
func opencodeZenModelToolName(name string) string {
	if mapped, ok := opencodeZenToolRename[name]; ok {
		return mapped
	}
	return name
}

// opencodeZenClientToolName returns the client-facing name for a model tool,
// or the original name when no rename applies (inverse of
// opencodeZenModelToolName).
func opencodeZenClientToolName(name string) string {
	for clientName, modelName := range opencodeZenToolRename {
		if modelName == name {
			return clientName
		}
	}
	return name
}

// opencodeZenRewriteRequestToolNames rewrites assistant tool_calls function
// names in the message history from client names to model-facing names (e.g.
// read -> read_file) so upstream history is consistent with the renamed tool
// definitions injected by mergeOpencodeZenTools.
func opencodeZenRewriteRequestToolNames(rawMessages string) string {
	if !strings.Contains(rawMessages, "tool_calls") {
		return rawMessages
	}
	parsed := gjson.Parse(rawMessages)
	if !parsed.IsArray() {
		return rawMessages
	}
	out := make([]string, 0, len(parsed.Array()))
	for _, m := range parsed.Array() {
		if m.Get("role").String() != "assistant" || len(m.Get("tool_calls").Array()) == 0 {
			out = append(out, m.Raw)
			continue
		}
		raw := m.Raw
		for i, call := range m.Get("tool_calls").Array() {
			name := call.Get("function.name").String()
			modelName := opencodeZenModelToolName(name)
			if modelName == name {
				continue
			}
			var err error
			raw, err = sjson.Set(raw, fmt.Sprintf("tool_calls.%d.function.name", i), modelName)
			if err != nil {
				break
			}
		}
		out = append(out, raw)
	}
	return "[" + strings.Join(out, ",") + "]"
}

// RewriteOpencodeZenResponseToolNames rewrites tool_calls function names in an
// upstream OpenAI-format response (streaming data line or non-streaming body)
// from model-facing names back to client-facing names (e.g. read_file -> read)
// so the client runtime recognizes the tools it declared. Uses the full
// opencodeZenToolRename map so every aliased tool is covered.
func RewriteOpencodeZenResponseToolNames(line []byte) []byte {
	if len(opencodeZenToolRename) == 0 {
		return line
	}
	out := make([]byte, len(line))
	copy(out, line)
	// Fast path: nothing to do unless a known alias appears.
	changed := false
	for _, modelName := range opencodeZenToolRename {
		if bytes.Contains(out, []byte(`"name":"`+modelName+`"`)) {
			changed = true
			break
		}
	}
	if !changed {
		return line
	}
	for clientName, modelName := range opencodeZenToolRename {
		out = bytes.ReplaceAll(out, []byte(`"name":"`+modelName+`"`), []byte(`"name":"`+clientName+`"`))
	}
	return out
}

// opencodeZenSystemPromptTrimmed returns the canonical opencode system prompt
// trimmed at a verified-accepted boundary for clients that ship their own
// tool environment (e.g. GitHub Copilot): everything from the "# Tool usage
// policy" heading onward (the <env> block, skills list and the model-ID
// footer) is dropped so the client's own system message stays dominant,
// while the probe-verified prefix (including the full <system-reminder>
// marker, which must survive verbatim) is retained to pass the gateway.
//
// Probe results (fresh window, same request, no rate-limit noise):
//
//	cut after "# Tool usage policy" heading (7341): 200 x2
//	cut inside "<system-reminder>" marker (7190):   429
//	cut at starting "<system-reminder>" tag (7212):  200
//	full canonical prompt (control):                200
//
// The boundary is therefore anchored at the "# Tool usage policy" heading,
// which sits well after the mandatory <system-reminder> marker.
func OpencodeZenSystemPromptTrimmed() string {
	if idx := strings.Index(opencodeZenSystemPrompt, "# Tool usage policy"); idx >= 0 {
		return strings.TrimRight(opencodeZenSystemPrompt[:idx], " \t\n")
	}
	return OpencodeZenSystemPrompt()
}

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
	// Clients that ship their own tools (Copilot, ...) get a trimmed canonical
	// prompt: the probe-verified prefix up to "# Tool usage policy" satisfies
	// the gateway check while dropping the opencode <env>/skills/model-ID tail
	// that would otherwise steer the model away from its own environment.
	hasOwnTools := clientHasOwnTools(payload)
	canonicalText := opencodeZenSystemPrompt
	if hasOwnTools {
		canonicalText = OpencodeZenSystemPromptTrimmed()
	}
	sysRaw := `{"role":"system","content":` + opencodeZenJSONString(canonicalText) + `}`
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
	if hasOwnTools {
		rebuilt += `,{"role":"system","content":` + opencodeZenJSONString(opencodeZenClientToolNote) + `}`
	}
	// Break cognitive loops: when the history already contains the same tool
	// call (same name + same arguments) repeated several times, tell the model
	// the result never changes, so it stops re-running it hoping for new info.
	if note := opencodeZenRepeatNote(rawMessages); note != "" {
		rebuilt += `,{"role":"system","content":` + opencodeZenJSONString(note) + `}`
	}
	// All other messages keep their original order, with assistant tool_calls
	// names rewritten to the model-facing aliases (read -> read_file) so the
	// history is consistent with the renamed tool definitions above.
	gjson.Parse(opencodeZenRewriteRequestToolNames(rawMessages)).ForEach(func(_, value gjson.Result) bool {
		if value.Get("role").String() == "system" {
			return true
		}
		rebuilt += "," + opencodeZenEnsureReasoningContent(value)
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

// opencodeZenRepeatThreshold is the number of identical tool calls tolerated
// before the proxy injects a convergence hint.
const opencodeZenRepeatThreshold = 3

// opencodeZenRepeatNote scans the message history for assistant tool_calls
// that occur repeatedly with identical function name and arguments, and
// returns a system-level hint when any of them repeats at least
// opencodeZenRepeatThreshold times. The hint tells the model the call's
// result is already known and unchanged, suppressing the "re-run the same
// query hoping for new information" loop. Returns "" when nothing repeats.
func opencodeZenRepeatNote(rawMessages string) string {
	if rawMessages == "" || !gjson.Valid(rawMessages) {
		return ""
	}
	type callKey struct {
		name string
		args string
	}
	counts := make(map[callKey]int)
	firstIndex := make(map[callKey]int)
	index := 0
	gjson.Parse(rawMessages).ForEach(func(_, m gjson.Result) bool {
		call := m.Get("role").String() == "assistant"
		if !call {
			index++
			return true
		}
		for _, tc := range m.Get("tool_calls").Array() {
			name := tc.Get("function.name").String()
			args := tc.Get("function.arguments").String()
			if name == "" {
				continue
			}
			key := callKey{name: name, args: args}
			counts[key]++
			if _, ok := firstIndex[key]; !ok {
				firstIndex[key] = index
			}
		}
		index++
		return true
	})

	// Pick the most repeated call (first occurrence order breaks ties), skip
	// direct text-only responses.
	type cand struct {
		key   callKey
		count int
		order int
	}
	var best cand
	for key, count := range counts {
		if count < opencodeZenRepeatThreshold {
			continue
		}
		if count > best.count || (count == best.count && firstIndex[key] < best.order) {
			best = cand{key: key, count: count, order: firstIndex[key]}
		}
	}
	if best.count == 0 {
		return ""
	}
	args := best.key.args
	if len(args) > 400 {
		args = args[:400] + "..."
	}
	return fmt.Sprintf("Note: you have already called %s with the same arguments %d times in this conversation, and each result was identical. The result is not going to change on another call. If it did not answer your question, re-read the existing results above instead of calling %s again.", best.key.name, best.count, best.key.name)
}

// DebugZenReasoningShape dumps per-message reasoning/tool-call presence for
// the converted payload, to diagnose upstream "reasoning_content must be
// passed back" rejections. For each assistant message it logs whether
// reasoning_content exists and whether tool_calls exist; tool messages are
// counted. The last few messages are printed in full (truncated) so the
// failing boundary is visible.
func DebugZenReasoningShape(payload []byte, stage string) {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "opencode zen: reasoning shape (%s, len=%d): ", stage, len(payload))
	asstWithReasoning, asstNoReasoning, asstWithTools, toolMsgs, toolNoId := 0, 0, 0, 0, 0
	msgs := gjson.GetBytes(payload, "messages")
	msgs.ForEach(func(_, m gjson.Result) bool {
		role := m.Get("role").String()
		switch role {
		case "assistant":
			hasRc := m.Get("reasoning_content").Exists()
			hasTc := len(m.Get("tool_calls").Array()) > 0
			if hasRc {
				asstWithReasoning++
			} else {
				asstNoReasoning++
			}
			if hasTc {
				asstWithTools++
			}
		case "tool", "function":
			toolMsgs++
			if m.Get("tool_call_id").String() == "" {
				toolNoId++
			}
		}
		return true
	})
	fmt.Fprintf(&b, "assistant(reasoning)=%d assistant(no-reasoning)=%d assistant(tool_calls)=%d tool=%d toolNoId=%d",
		asstWithReasoning, asstNoReasoning, asstWithTools, toolMsgs, toolNoId)
	// Show the tail boundary verbatim: the newest messages decide whether a
	// pending tool call / reasoning field survives.
	tailStart := 0
	total := len(msgs.Array())
	if total > 6 {
		tailStart = total - 6
	}
	for i := tailStart; i < total; i++ {
		raw := msgs.Array()[i].Raw
		if len(raw) > 300 {
			raw = raw[:300] + "..."
		}
		fmt.Fprintf(&b, "\n  [%d] %s", i, raw)
	}
	log.Debugf("%s", b.String())
}

// OpencodeZenRepeatNote exposes the convergence hint for tests.
func OpencodeZenRepeatNote(rawMessages string) string {
	return opencodeZenRepeatNote(rawMessages)
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

// opencodeZenNormalizeToolSchema makes a renamed client tool's parameters a
// valid JSON Schema object. The zen gateway validates tool schemas and
// rejects a schema whose top-level type is missing ("schema must be a JSON
// Schema of 'type: object', got 'type: null'"). Clients occasionally declare
// parameters without the outer type (e.g. only properties/required), so
// ensure parameters.type = "object" exists and parameters is an object.
func opencodeZenNormalizeToolSchema(raw string) string {
	params := gjson.Get(raw, "function.parameters")
	if !params.Exists() || params.IsObject() && params.Get("type").String() == "" {
		var err error
		raw, err = sjson.Set(raw, "function.parameters.type", "object")
		if err != nil {
			return raw
		}
	}
	if !params.Exists() {
		var err error
		raw, err = sjson.SetRaw(raw, "function.parameters", `{"type":"object"}`)
		if err != nil {
			return raw
		}
	}
	return raw
}

// mergeOpencodeZenTools returns the client's own tools (deduplicated by
// function name, listed first so the model prefers its environment's tools)
// followed by the FULL canonical opencode tool set.
//
// The zen gateway enforces TWO invariants that must both hold:
//  1. The canonical six tool definitions must be FULLY present — removing or
//     altering one triggers 429.
//  2. Tool names must be UNIQUE — emitting the client's read/write AND the
//     canonical read/write duplicates the name and the upstream rejects the
//     payload with "Tool names must be unique".
//
// Therefore a client-declared tool that collides with a canonical name is
// injected under a meaningful model-facing alias (read -> read_file,
// write -> write_file) with the client's OWN schema (snake_case file_path),
// while the canonical tool keeps its original name and definition. Upstream
// sees unique names, the canonical six survive verbatim (invariant 1), and
// the model sees a self-describing tool it can actually call. Responses and
// request histories are renamed back (read_file -> read) so the client
// runtime always sees the tools it declared.
func mergeOpencodeZenTools(payload []byte) string {
	var clientTools []string
	seen := make(map[string]struct{}, 8)
	gjson.GetBytes(payload, "tools").ForEach(func(_, tool gjson.Result) bool {
		name := tool.Get("function.name").String()
		if name == "" {
			return true
		}
		if _, dup := seen[name]; dup {
			return true
		}
		seen[name] = struct{}{}
		// Colliding tools get a meaningful model-facing alias; the schema stays
		// the client's own (file_path etc), normalized to a valid JSON Schema
		// so the gateway schema check passes (it validates EVERY tool schema,
		// renamed or not).
		modelName := opencodeZenModelToolName(name)
		if modelName != name {
			if renamed, err := sjson.Set(tool.Raw, "function.name", modelName); err == nil {
				clientTools = append(clientTools, opencodeZenNormalizeToolSchema(renamed))
				return true
			}
		}
		clientTools = append(clientTools, opencodeZenNormalizeToolSchema(tool.Raw))
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
	// Canonical six are always appended in full and verbatim (unique names:
	// colliding client tools were renamed above) — the gateway check requires
	// them byte-for-byte.
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
