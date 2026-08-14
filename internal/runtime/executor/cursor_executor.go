package executor

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// CursorExecutor implements the Cursor CLI AgentService protocol. The bidi
// path is the only request execution path so native local execution stays
// available for every Cursor request.
type CursorExecutor struct {
	cfg           *config.Config
	authEndpoint  string
	agentEndpoint string
	dialAgent     cursorAgentDialer
	httpClient    *http.Client
}

// NewCursorExecutor creates a Cursor executor bound to the global config.
func NewCursorExecutor(cfg *config.Config) *CursorExecutor {
	return &CursorExecutor{cfg: cfg}
}

// Identifier implements cliproxyauth.ProviderExecutor.
func (e *CursorExecutor) Identifier() string { return "cursor" }

// cursorAuthInfo extracts cursor-specific attributes from the auth entry.
type cursorAuthInfo struct {
	apiKey string
}

func cursorInfoFromAuth(auth *cliproxyauth.Auth) cursorAuthInfo {
	info := cursorAuthInfo{}
	if auth == nil {
		return info
	}
	if auth.Attributes != nil {
		info.apiKey = strings.TrimSpace(auth.Attributes["api_key"])
	}
	return info
}

// PrepareRequest injects the Cursor API key into the outgoing HTTP request.
func (e *CursorExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	info := cursorInfoFromAuth(auth)
	if info.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+info.apiKey)
	}
	req.Header.Set("x-cursor-client-type", "sdk")
	req.Header.Set("x-cursor-client-version", "sdk-1.0.0")
	req.Header.Set("x-ghost-mode", "true")
	return nil
}

// HttpRequest injects Cursor credentials into the request and executes it.
func (e *CursorExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("cursor executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

// Refresh is a no-op for static API keys.
func (e *CursorExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	return auth, nil
}

// CountTokens returns a token estimate using a simple heuristic (4 chars/token for CJK-aware text).
func (e *CursorExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	// Estimate from the payload message text.
	var count int
	if len(req.Payload) > 0 {
		// Rough heuristic: JSON bytes / 4 (CJK chars often occupy 3 bytes in UTF-8,
		// English ~1 byte; 4 is a reasonable middle ground).
		count = len(req.Payload) / 4
		if count < 1 {
			count = 1
		}
	}
	usageJSON := fmt.Sprintf(`{"usage":{"prompt_tokens":%d,"completion_tokens":0,"total_tokens":%d}}`, count, count)
	translated := sdktranslator.TranslateTokenCount(ctx, "openai", responseFormat, int64(count), []byte(usageJSON))
	return cliproxyexecutor.Response{Payload: translated}, nil
}

type cursorModelParam struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// cursorVariantParams maps a model name to the full set of params the Cursor
// AgentService expects in RequestedModel. Params must match exactly one
// supported Cursor variant.
// The optional reasoningEffort (from the OpenAI request's reasoning_effort field,
// surfaced via Options.Metadata[ReasoningEffortMetadataKey]) is used when the
// model name does NOT explicitly carry an effort/reasoning suffix — this lets
// clients control thinking level dynamically without model-name suffixes.
// clampVariantLevel constrains a requested variant value to the family's
// allowed set. Unknown values degrade to the highest allowed level, except
// none/minimal/low which degrade to the lowest. This protects against clients
// sending reasoning_effort values the Cursor variant doesn't support
// (e.g. grok has no "max" effort, gpt-5.5 uses "extra-high" not "xhigh").
func clampVariantLevel(value string, allowed ...string) string {
	if len(allowed) == 0 {
		return value
	}
	for _, a := range allowed {
		if value == a {
			return value
		}
	}
	switch value {
	case "none", "minimal", "low":
		return allowed[0]
	}
	return allowed[len(allowed)-1]
}

func cursorVariantParams(model, reasoningEffort string) []cursorModelParam {
	low := strings.ToLower(strings.TrimSpace(model))
	// Strip common cursor prefixes.
	low = strings.TrimPrefix(low, "cursor-")
	hasFast := strings.Contains(low, "fast")
	// Explicit suffix wins over the client reasoning_effort override.
	nameEffort := cursorNameEffort(low)
	if nameEffort == "" {
		nameEffort = normalizeEffort(reasoningEffort)
	}
	nameReasoning := cursorNameReasoning(low)
	if nameReasoning == "" {
		nameReasoning = normalizeReasoning(reasoningEffort)
	}
	base := cursorBaseModel(low)

	// Parameter sets per model family, matching GET /v1/models exactly.
	// claude families with [thinking, context, effort, fast]:
	//   claude-opus-5, claude-opus-4-8, claude-opus-4-7
	if strings.HasPrefix(base, "claude-opus-5") ||
		strings.HasPrefix(base, "claude-opus-4-8") ||
		strings.HasPrefix(base, "claude-opus-4-7") {
		effort := nameEffort
		if effort == "" {
			effort = "medium"
		}
		thinkingV := "false"
		if strings.Contains(low, "thinking") || (effort != "low" && reasoningEffort != "") {
			thinkingV = "true"
		}
		cyberV := "false"
		if strings.Contains(low, "cyber") {
			cyberV = "true"
		}
		contextV := "300k"
		if strings.Contains(low, "1m") {
			contextV = "1m"
		}
		return []cursorModelParam{
			{ID: "cyber", Value: cyberV},
			{ID: "thinking", Value: thinkingV},
			{ID: "context", Value: contextV},
			{ID: "effort", Value: effort},
			{ID: "fast", Value: fmt.Sprintf("%t", hasFast)},
		}
	}
	// claude families with [thinking, context, effort] (no fast):
	//   claude-fable-5, claude-sonnet-5, claude-sonnet-4-6, claude-opus-4-6
	if strings.HasPrefix(base, "claude-fable-5") ||
		strings.HasPrefix(base, "claude-sonnet-5") ||
		strings.HasPrefix(base, "claude-sonnet-4-6") ||
		strings.HasPrefix(base, "claude-opus-4-6") {
		effort := nameEffort
		if effort == "" {
			effort = "medium"
		}
		thinkingV := "false"
		if strings.Contains(low, "thinking") || (effort != "low" && reasoningEffort != "") {
			thinkingV = "true"
		}
		contextV := "300k"
		if strings.Contains(low, "1m") {
			contextV = "1m"
		}
		return []cursorModelParam{
			{ID: "thinking", Value: thinkingV},
			{ID: "context", Value: contextV},
			{ID: "effort", Value: effort},
		}
	}
	// claude families with [thinking] only: claude-opus-4-5, claude-haiku-4-5
	if strings.HasPrefix(base, "claude-opus-4-5") || strings.HasPrefix(base, "claude-haiku-4-5") {
		thinkingV := "false"
		if strings.Contains(low, "thinking") || reasoningEffort != "" {
			thinkingV = "true"
		}
		return []cursorModelParam{
			{ID: "thinking", Value: thinkingV},
		}
	}
	// claude families with [thinking, context]: claude-sonnet-4-5, claude-sonnet-4
	if strings.HasPrefix(base, "claude-sonnet-4-5") || strings.HasPrefix(base, "claude-sonnet-4") {
		thinkingV := "false"
		if strings.Contains(low, "thinking") || reasoningEffort != "" {
			thinkingV = "true"
		}
		contextV := "300k"
		if strings.Contains(low, "1m") {
			contextV = "1m"
		}
		return []cursorModelParam{
			{ID: "thinking", Value: thinkingV},
			{ID: "context", Value: contextV},
		}
	}
	// gpt families with [reasoning] only: gpt-5.4-mini/nano (none..xhigh),
	// gpt-5.1 (low..high). NOTE: must be checked BEFORE the gpt-5.4 prefix match.
	if strings.HasPrefix(base, "gpt-5.4-mini") ||
		strings.HasPrefix(base, "gpt-5.4-nano") {
		reasoning := nameReasoning
		if reasoning == "" {
			reasoning = "medium"
		}
		reasoning = clampVariantLevel(reasoning, "none", "low", "medium", "high", "xhigh")
		return []cursorModelParam{
			{ID: "reasoning", Value: reasoning},
		}
	}
	if strings.HasPrefix(base, "gpt-5.1") {
		reasoning := nameReasoning
		if reasoning == "" {
			reasoning = "medium"
		}
		reasoning = clampVariantLevel(reasoning, "low", "medium", "high")
		return []cursorModelParam{
			{ID: "reasoning", Value: reasoning},
		}
	}
	// gpt families with [context, reasoning, fast]:
	//   gpt-5.6-sol/5.6-terra/5.6-luna accept none..max;
	//   gpt-5.5/5.4 accept none..extra-high (NOT "xhigh").
	if strings.HasPrefix(base, "gpt-5.6-sol") ||
		strings.HasPrefix(base, "gpt-5.6-terra") ||
		strings.HasPrefix(base, "gpt-5.6-luna") {
		reasoning := nameReasoning
		if reasoning == "" {
			reasoning = "medium"
		}
		reasoning = clampVariantLevel(reasoning, "none", "low", "medium", "high", "xhigh", "max")
		contextV := "272k"
		if strings.Contains(low, "1m") {
			contextV = "1m"
		}
		return []cursorModelParam{
			{ID: "context", Value: contextV},
			{ID: "reasoning", Value: reasoning},
			{ID: "fast", Value: fmt.Sprintf("%t", hasFast)},
		}
	}
	if strings.HasPrefix(base, "gpt-5.5") ||
		strings.HasPrefix(base, "gpt-5.4") {
		reasoning := nameReasoning
		if reasoning == "" {
			reasoning = "medium"
		}
		reasoning = clampVariantLevel(reasoning, "none", "low", "medium", "high", "extra-high")
		contextV := "272k"
		if strings.Contains(low, "1m") {
			contextV = "1m"
		}
		return []cursorModelParam{
			{ID: "context", Value: contextV},
			{ID: "reasoning", Value: reasoning},
			{ID: "fast", Value: fmt.Sprintf("%t", hasFast)},
		}
	}
	// gpt families with [reasoning, fast]: gpt-5.3-codex, gpt-5.2 (low..extra-high)
	if strings.HasPrefix(base, "gpt-5.3-codex") || strings.HasPrefix(base, "gpt-5.2") {
		reasoning := nameReasoning
		if reasoning == "" {
			reasoning = "medium"
		}
		reasoning = clampVariantLevel(reasoning, "low", "medium", "high", "extra-high")
		return []cursorModelParam{
			{ID: "reasoning", Value: reasoning},
			{ID: "fast", Value: fmt.Sprintf("%t", hasFast)},
		}
	}
	// grok: [effort, fast] — effort is low/medium/high/xhigh (grok-4.5 lacks xhigh);
	// clamp client "max" (common from reasoning_effort) onto the family maximum.
	if strings.HasPrefix(base, "grok-") {
		effort := nameEffort
		if effort == "" {
			effort = "medium"
		}
		if strings.HasPrefix(base, "grok-4.5") {
			effort = clampVariantLevel(effort, "low", "medium", "high")
		} else {
			effort = clampVariantLevel(effort, "low", "medium", "high", "xhigh")
		}
		return []cursorModelParam{
			{ID: "effort", Value: effort},
			{ID: "fast", Value: fmt.Sprintf("%t", hasFast)},
		}
	}
	// composer: [fast]
	if strings.HasPrefix(base, "composer-") {
		return []cursorModelParam{
			{ID: "fast", Value: fmt.Sprintf("%t", hasFast)},
		}
	}
	// kimi-k3: [reasoning] — variants are low/high/max; max is default and
	// high has been observed to fail variant matching, so clamp unknowns
	// (medium/xhigh from reasoning_effort) onto the family set.
	if strings.HasPrefix(base, "kimi-k3") {
		reasoning := nameReasoning
		if reasoning == "" || reasoning == "high" {
			reasoning = "max"
		}
		reasoning = clampVariantLevel(reasoning, "low", "high", "max")
		return []cursorModelParam{
			{ID: "reasoning", Value: reasoning},
		}
	}
	// glm-5.2: [reasoning] — variants are high/max, high is default.
	if strings.HasPrefix(base, "glm-") {
		reasoning := nameReasoning
		if reasoning == "" {
			reasoning = "high"
		}
		reasoning = clampVariantLevel(reasoning, "high", "max")
		return []cursorModelParam{
			{ID: "reasoning", Value: reasoning},
		}
	}
	// gemini-3.6-flash: [effort] — minimal/low/medium/high (no xhigh/max)
	if strings.HasPrefix(base, "gemini-3.6") {
		effort := nameEffort
		if effort == "" {
			effort = "medium"
		}
		effort = clampVariantLevel(effort, "minimal", "low", "medium", "high")
		return []cursorModelParam{
			{ID: "effort", Value: effort},
		}
	}
	// No-parameter models (gemini-3.1-pro, gemini-3-flash, gemini-3.5-flash,
	// gemini-2.5-flash, gpt-5-mini, kimi-k2.7-code) and unknown:
	// omit params = server default variant.
	return nil
}

// cursorNameEffort extracts the explicit effort level encoded in a model name
// (e.g. "grok-4.6-xhigh-fast" -> "xhigh"), or "" when none is present.
func cursorNameEffort(low string) string {
	switch {
	case strings.Contains(low, "max"):
		return "max"
	case strings.Contains(low, "xhigh"):
		return "xhigh"
	case strings.Contains(low, "high"):
		return "high"
	case strings.Contains(low, "medium"):
		return "medium"
	case strings.Contains(low, "low"):
		return "low"
	case strings.Contains(low, "minimal"):
		return "minimal"
	case strings.Contains(low, "none"):
		return "none"
	}
	return ""
}

// cursorNameReasoning extracts the explicit reasoning level encoded in a model
// name (gpt/kimi/glm families), or "" when none is present.
func cursorNameReasoning(low string) string {
	switch {
	case strings.Contains(low, "max"):
		return "max"
	case strings.Contains(low, "xhigh") || strings.Contains(low, "extra-high"):
		return "xhigh"
	case strings.Contains(low, "high"):
		return "high"
	case strings.Contains(low, "medium"):
		return "medium"
	case strings.Contains(low, "low"):
		return "low"
	case strings.Contains(low, "none"):
		return "none"
	}
	return ""
}

// normalizeEffort maps client reasoning_effort values onto Cursor effort levels.
// Returns "" for empty/unknown input so callers can fall back to family defaults.
func normalizeEffort(effort string) string {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "minimal":
		return "minimal"
	case "none":
		return "minimal"
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "xhigh":
		return "xhigh"
	case "max":
		return "max"
	}
	return ""
}

// normalizeReasoning maps client reasoning_effort values onto Cursor reasoning
// levels. Returns "" for empty/unknown input so callers can fall back to family
// defaults. Note: gpt families accept xhigh; kimi/glm accept max.
func normalizeReasoning(effort string) string {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "minimal", "none":
		return "none"
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "xhigh":
		return "xhigh"
	case "max":
		return "max"
	}
	return ""
}

// cursorBaseModel strips reasoning/effort/fast/thinking suffixes (and the
// optional "cursor-" prefix) to derive the base model id used by AgentService.
func cursorBaseModel(model string) string {
	low := strings.ToLower(strings.TrimSpace(model))
	low = strings.TrimPrefix(low, "cursor-")
	for _, suffix := range []string{
		"-thinking-high-fast", "-thinking-high", "-thinking-max-fast", "-thinking-max",
		"-thinking-xhigh-fast", "-thinking-xhigh", "-thinking-low-fast", "-thinking-low",
		"-thinking-medium-fast", "-thinking-medium",
		"-xhigh-fast", "-xhigh", "-high-fast", "-high", "-medium-fast", "-medium",
		"-low-fast", "-low", "-max-fast", "-max", "-none", "-fast", "-minimal",
	} {
		if strings.HasSuffix(low, suffix) {
			return low[:len(low)-len(suffix)]
		}
	}
	return low
}

// cursorPromptFromPayload converts an OpenAI chat/completions payload into a
// single prompt text. System + user messages are joined; assistant history is
// preserved as context.
func cursorPromptFromPayload(payload []byte) string {
	messages := gjson.GetBytes(payload, "messages").Array()
	if len(messages) == 0 {
		// Maybe responses-style input
		if input := gjson.GetBytes(payload, "input").Array(); len(input) > 0 {
			var b strings.Builder
			for _, m := range input {
				role := gjson.Get(m.Raw, "role").String()
				content := gjson.Get(m.Raw, "content").String()
				if role == "" {
					role = "user"
				}
				if content == "" {
					// content can be an array of parts
					content = gjson.Get(m.Raw, "content").Raw
				}
				b.WriteString(fmt.Sprintf("%s: %s\n", strings.ToUpper(role), content))
			}
			return cursorAppendLangHint(strings.TrimSpace(b.String()))
		}
		return ""
	}
	var b strings.Builder
	for _, m := range messages {
		role := gjson.Get(m.Raw, "role").String()
		if role == "" {
			role = "user"
		}
		content := cursorMessageText(m)
		if content == "" {
			continue
		}
		switch role {
		case "system":
			b.WriteString("[System]\n" + content + "\n\n")
		case "tool":
			b.WriteString("[Tool Result]\n" + content + "\n\n")
		default:
			b.WriteString(strings.ToUpper(role) + ": " + content + "\n\n")
		}
	}
	return cursorAppendLangHint(strings.TrimSpace(b.String()))
}

// cursorAppendLangHint appends a Simplified-Chinese instruction when the prompt
// contains CJK characters so the direct agent follows the client's language.
func cursorAppendLangHint(prompt string) string {
	if prompt == "" {
		return prompt
	}
	if !containsCJK(prompt) {
		return prompt
	}
	return prompt + "\n\n[语言要求] 请始终使用简体中文回复（Simplified Chinese），除非用户明确要求其他语言。"
}

// containsCJK reports whether s contains any CJK Unified Ideograph.
func containsCJK(s string) bool {
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
	}
	return false
}

// cursorMessageText extracts plain text from a message content (string or part array).
// Part types handled:
//   - text:     plain text part (kept as-is)
//   - resource: workspace/opened-file context (Copilot sends opened documents,
//     workspace files and MCP resource reads here) — carried as [File: <uri>] blocks
//   - file:     attachment references — carried as [Attachment: <name>]
//   - image_url: the current minimal direct prompt encoder has no inline-image
//     field, so it uses a placeholder rather than silently dropping the part
func cursorMessageText(m gjson.Result) string {
	content := gjson.Get(m.Raw, "content")
	if content.Type == gjson.String {
		return content.String()
	}
	if content.IsArray() {
		var parts []string
		for _, p := range content.Array() {
			switch p.Get("type").String() {
			case "text":
				parts = append(parts, p.Get("text").String())
			case "resource":
				res := p.Get("resource")
				uri := strings.TrimSpace(res.Get("uri").String())
				text := strings.TrimSpace(res.Get("text").String())
				if text == "" {
					text = strings.TrimSpace(res.Get("content").String())
				}
				switch {
				case uri != "" && text != "":
					parts = append(parts, fmt.Sprintf("[File: %s]\n%s", uri, text))
				case uri != "":
					parts = append(parts, fmt.Sprintf("[File: %s]", uri))
				case text != "":
					parts = append(parts, text)
				}
			case "file":
				f := p.Get("file")
				uri := strings.TrimSpace(f.Get("uri").String())
				text := strings.TrimSpace(f.Get("text").String())
				name := strings.TrimSpace(f.Get("name").String())
				switch {
				case uri != "" && text != "":
					parts = append(parts, fmt.Sprintf("[Attachment: %s]\n%s", uri, text))
				case uri != "":
					parts = append(parts, fmt.Sprintf("[Attachment: %s]", uri))
				case name != "":
					parts = append(parts, fmt.Sprintf("[Attachment: %s]", name))
				}
			case "image_url":
				parts = append(parts, "[Image omitted: direct prompt encoder does not yet carry inline images]")
			}
		}
		return strings.Join(parts, "\n")
	}
	return content.Raw
}

// cursorHTTPClient returns a proxy-aware HTTP client for Cursor requests.
func (e *CursorExecutor) cursorHTTPClient(ctx context.Context, auth *cliproxyauth.Auth) *http.Client {
	if e != nil && e.httpClient != nil {
		return e.httpClient
	}
	return helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-streaming execution
// ─────────────────────────────────────────────────────────────────────────────

// cursorReasoningEffort extracts the client-requested reasoning_effort from
// execution options metadata (populated by the request handler from the
// OpenAI payload's reasoning_effort field).
func cursorReasoningEffort(opts cliproxyexecutor.Options) string {
	if len(opts.Metadata) == 0 {
		return ""
	}
	raw, ok := opts.Metadata[cliproxyexecutor.ReasoningEffortMetadataKey]
	if !ok || raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	case []byte:
		return strings.TrimSpace(string(value))
	default:
		return ""
	}
}

// Execute runs a non-streaming turn through the direct Cursor AgentService
// bidi protocol. This is intentionally the default for every cursor request so
// native shell/file execution is available even when the client supplied no
// OpenAI-side tools.
func (e *CursorExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	resp, _, err = e.executeAgent(ctx, auth, req, opts, false)
	return resp, err
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming execution
// ─────────────────────────────────────────────────────────────────────────────

// ExecuteStream streams a chat completion through the direct Cursor
// AgentService bidi protocol.
func (e *CursorExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	_, stream, err := e.executeAgent(ctx, auth, req, opts, true)
	return stream, err
}
