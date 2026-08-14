package executor

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

const cursorToolCallMarker = "<<<CURSOR_CPA_TOOL_CALL>>>"

type cursorClientTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type cursorToolResult struct {
	CallID  string
	Name    string
	Content string
}

type cursorPendingCall struct {
	ID   string
	Name string
}

func cursorClientTools(payload []byte) []cursorClientTool {
	raw := gjson.GetBytes(payload, "tools")
	if !raw.Exists() || !raw.IsArray() {
		return nil
	}
	var out []cursorClientTool
	for _, t := range raw.Array() {
		name := strings.TrimSpace(t.Get("function.name").String())
		if name == "" {
			name = strings.TrimSpace(t.Get("name").String())
		}
		if name == "" {
			continue
		}
		desc := t.Get("function.description").String()
		if desc == "" {
			desc = t.Get("description").String()
		}
		params := t.Get("function.parameters")
		if !params.Exists() {
			params = t.Get("parameters")
		}
		item := cursorClientTool{Name: name, Description: desc}
		if params.Exists() {
			item.Parameters = json.RawMessage(params.Raw)
		}
		out = append(out, item)
	}
	return out
}

func cursorHasClientTools(payload []byte) bool {
	return len(cursorClientTools(payload)) > 0
}

func cursorToolResults(payload []byte) []cursorToolResult {
	messages := gjson.GetBytes(payload, "messages")
	callNames := map[string]string{}
	var out []cursorToolResult
	if messages.Exists() && messages.IsArray() {
		for _, m := range messages.Array() {
			role := m.Get("role").String()
			if role == "assistant" {
				for _, tc := range m.Get("tool_calls").Array() {
					id := strings.TrimSpace(tc.Get("id").String())
					name := strings.TrimSpace(tc.Get("function.name").String())
					if id != "" && name != "" {
						callNames[id] = name
					}
				}
				continue
			}
			if role != "tool" {
				continue
			}
			id := strings.TrimSpace(m.Get("tool_call_id").String())
			if id == "" {
				id = strings.TrimSpace(m.Get("call_id").String())
			}
			out = append(out, cursorToolResult{
				CallID:  id,
				Name:    callNames[id],
				Content: cursorMessageText(m),
			})
		}
		return out
	}

	// Responses API payloads are normally translated before reaching this
	// helper. Keep a direct fallback so session continuation also works when a
	// caller supplies the Responses shape unchanged.
	input := gjson.GetBytes(payload, "input")
	if !input.Exists() || !input.IsArray() {
		return nil
	}
	for _, item := range input.Array() {
		switch item.Get("type").String() {
		case "function_call":
			id := strings.TrimSpace(item.Get("call_id").String())
			name := strings.TrimSpace(item.Get("name").String())
			if id != "" && name != "" {
				callNames[id] = name
			}
		case "function_call_output":
			id := strings.TrimSpace(item.Get("call_id").String())
			output := item.Get("output")
			content := output.String()
			if output.IsObject() || output.IsArray() {
				content = output.Raw
			}
			out = append(out, cursorToolResult{CallID: id, Name: callNames[id], Content: content})
		}
	}
	return out
}

func cursorHasToolResults(payload []byte) bool {
	return len(cursorToolResults(payload)) > 0
}

func cursorShouldUseAgentLoop(payload []byte) bool {
	return cursorHasClientTools(payload) || cursorHasToolResults(payload)
}

func cursorToolSchemaPrompt(tools []cursorClientTool) string {
	if len(tools) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("You can request tools that run on the user's machine. When you need a tool, respond with ONLY this block (no extra text outside it):\n\n")
	b.WriteString(cursorToolCallMarker)
	b.WriteByte('\n')
	b.WriteString(`{"name":"<tool_name>","arguments":{...}}`)
	b.WriteByte('\n')
	b.WriteString(cursorToolCallMarker)
	b.WriteString("\n\nYou may emit multiple blocks to call several tools. If you do not need a tool, answer normally without the marker.\n\nAvailable tools:\n")
	for _, t := range tools {
		b.WriteString("- ")
		b.WriteString(t.Name)
		if t.Description != "" {
			b.WriteString(": ")
			b.WriteString(t.Description)
		}
		if len(t.Parameters) > 0 {
			b.WriteString("\n  parameters: ")
			b.Write(t.Parameters)
		}
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

func cursorParseToolCallBlocks(text string) (remaining string, calls []cursorPendingCall, argJSON []string) {
	remaining = text
	for {
		start := strings.Index(remaining, cursorToolCallMarker)
		if start < 0 {
			break
		}
		after := start + len(cursorToolCallMarker)
		end := strings.Index(remaining[after:], cursorToolCallMarker)
		if end < 0 {
			break
		}
		body := strings.TrimSpace(remaining[after : after+end])
		fullEnd := after + end + len(cursorToolCallMarker)
		name, args := cursorParseToolCallJSON(body)
		if name != "" {
			calls = append(calls, cursorPendingCall{ID: "call_" + uuid.NewString(), Name: name})
			argJSON = append(argJSON, args)
		}
		remaining = strings.TrimSpace(remaining[:start] + remaining[fullEnd:])
	}
	return remaining, calls, argJSON
}

func cursorParseToolCallJSON(body string) (name, args string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", "{}"
	}
	parsed := gjson.Parse(body)
	name = strings.TrimSpace(parsed.Get("name").String())
	if name == "" {
		return "", "{}"
	}
	arg := parsed.Get("arguments")
	if !arg.Exists() {
		return name, "{}"
	}
	if arg.Type == gjson.String {
		return name, arg.String()
	}
	return name, arg.Raw
}

func cursorMarshalOpenAIChunk(model, finish string, delta map[string]any) ([]byte, error) {
	chunk := map[string]any{
		"id":      "chatcmpl-" + uuid.NewString(),
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{
			{
				"index":         0,
				"delta":         delta,
				"finish_reason": nil,
			},
		},
	}
	if finish != "" {
		chunk["choices"].([]map[string]any)[0]["finish_reason"] = finish
	}
	return json.Marshal(chunk)
}

func cursorOpenAITextDelta(model, text string) ([]byte, error) {
	return cursorMarshalOpenAIChunk(model, "", map[string]any{"content": text})
}

func cursorOpenAIToolCallStart(model string, index int, call cursorPendingCall) ([]byte, error) {
	return cursorMarshalOpenAIChunk(model, "", map[string]any{
		"role":    "assistant",
		"content": nil,
		"tool_calls": []map[string]any{
			{
				"index": index,
				"id":    call.ID,
				"type":  "function",
				"function": map[string]any{
					"name":      call.Name,
					"arguments": "",
				},
			},
		},
	})
}

func cursorOpenAIToolCallArgs(model string, index int, args string) ([]byte, error) {
	return cursorMarshalOpenAIChunk(model, "", map[string]any{
		"tool_calls": []map[string]any{
			{
				"index": index,
				"function": map[string]any{
					"arguments": args,
				},
			},
		},
	})
}

func cursorOpenAIFinish(model, reason string) ([]byte, error) {
	return cursorMarshalOpenAIChunk(model, reason, map[string]any{})
}

func cursorOpenAINonStreamToolMessage(model, text string, calls []cursorPendingCall, argJSON []string) ([]byte, error) {
	toolCalls := make([]map[string]any, 0, len(calls))
	for i, c := range calls {
		args := "{}"
		if i < len(argJSON) && argJSON[i] != "" {
			args = argJSON[i]
		}
		toolCalls = append(toolCalls, map[string]any{
			"id":   c.ID,
			"type": "function",
			"function": map[string]any{
				"name":      c.Name,
				"arguments": args,
			},
		})
	}
	msg := map[string]any{"role": "assistant", "content": text}
	finish := "stop"
	if len(toolCalls) > 0 {
		msg["tool_calls"] = toolCalls
		if strings.TrimSpace(text) == "" {
			msg["content"] = nil
		}
		finish = "tool_calls"
	}
	resp := map[string]any{
		"id":      "chatcmpl-" + uuid.NewString(),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       msg,
				"finish_reason": finish,
			},
		},
	}
	return json.Marshal(resp)
}

func cursorOpenAINonStreamText(model, text string) ([]byte, error) {
	return cursorOpenAINonStreamToolMessage(model, text, nil, nil)
}

func cursorFormatToolResultLine(res cursorToolResult) string {
	label := res.CallID
	if res.Name != "" {
		label = fmt.Sprintf("%s (%s)", res.CallID, res.Name)
	}
	return fmt.Sprintf("[Tool Result for %s]\n%s", label, res.Content)
}
