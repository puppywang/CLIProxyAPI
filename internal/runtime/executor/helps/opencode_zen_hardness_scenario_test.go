package helps

import (
	"testing"

	"github.com/tidwall/gjson"
)

// TestMergeOpencodeZenToolsHardnessScenario simulates a DeepSeek Harness
// request that ships its own tool set (read/write/edit/pwsh with snake_case
// file_path params).
//
// Invariants:
//  1. The client's read/write definitions (file_path) MUST be preserved and
//     listed first — replacing them with the canonical camelCase filePath
//     placeholders breaks the harness runtime validation.
//  2. The canonical six tools MUST all still be present (including read/write
//     with filePath) — the zen gateway rejects the request with 429 if any
//     canonical tool is missing.
func TestMergeOpencodeZenToolsHardnessScenario(t *testing.T) {
	input := `{
		"model": "deepseek-v4-flash-free",
		"messages": [{"role": "user", "content": "q"}],
		"tools": [
			{"type": "function", "function": {"name": "read", "parameters": {"properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "write", "parameters": {"properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "edit", "parameters": {"properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
			{"type": "function", "function": {"name": "pwsh", "parameters": {"properties": {"command": {"type": "string"}}}}}
		]
	}`
	out := ConvertOpenAIRequestToOpencodeZen([]byte(input))
	tools := gjson.GetBytes(out, "tools").Array()

	// 1) Client tools keep their own schema and come first.
	clientNames := []string{"read", "write", "edit", "pwsh"}
	for i, name := range clientNames {
		got := tools[i].Get("function.name").String()
		if got != name {
			t.Fatalf("tools[%d] = %q, want client tool %q first", i, got, name)
		}
	}
	for _, name := range []string{"read", "write", "edit"} {
		found := false
		for _, tool := range tools {
			if tool.Get("function.name").String() != name {
				continue
			}
			props := tool.Get("function.parameters.properties").Raw
			if gjson.GetBytes([]byte(props), "file_path").Exists() {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("client %s tool with file_path must be preserved", name)
		}
	}

	// 2) Canonical six all present (duplicates allowed), with filePath for read/write.
	for _, name := range []string{"read", "task", "todowrite", "webfetch", "websearch", "write"} {
		found := false
		for _, tool := range tools {
			if tool.Get("function.name").String() != name {
				continue
			}
			props := tool.Get("function.parameters.properties").Raw
			if name == "read" || name == "write" {
				if gjson.GetBytes([]byte(props), "filePath").Exists() {
					found = true
					break
				}
			} else {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("canonical tool %s must remain present (gateway 429 guard)", name)
		}
	}
}
