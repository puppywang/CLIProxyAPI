package config

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAICompatibilityOpencodeZen_YAML(t *testing.T) {
	raw := `
openai-compatibility:
  - name: "opencode-zen"
    base-url: "https://opencode.ai/zen/v1"
    opencode-zen: true
    api-key-entries:
      - api-key: ""
    models:
      - name: "deepseek-v4-flash-free"
        alias: "zen-model"
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.OpenAICompatibility) != 1 {
		t.Fatalf("openai-compatibility count = %d, want 1", len(cfg.OpenAICompatibility))
	}
	compat := cfg.OpenAICompatibility[0]
	if !compat.OpencodeZen {
		t.Fatal("opencode-zen must parse to true")
	}
	if compat.BaseURL != "https://opencode.ai/zen/v1" {
		t.Fatalf("base-url = %q", compat.BaseURL)
	}
}

func TestOpenAICompatibilityOpencodeZen_JSON(t *testing.T) {
	raw := `{"name":"opencode-zen","base-url":"https://opencode.ai/zen/v1","opencode-zen":true,"models":[{"name":"deepseek-v4-flash-free","alias":"zen"}]}`
	var compat OpenAICompatibility
	if err := json.Unmarshal([]byte(raw), &compat); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !compat.OpencodeZen {
		t.Fatal("opencode-zen must parse to true")
	}
}
