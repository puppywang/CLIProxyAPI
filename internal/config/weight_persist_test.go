package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSaveConfigPreserveCommentsKeepsWeightZero verifies that a weight: 0
// entry (which means "exclude this credential") survives the comment-preserving
// persist path. Previously isKnownDefaultValue treated 0 as a prunable default,
// so weight: 0 vanished from the YAML and a subsequent hot reload restored the
// credential into rotation.
func TestSaveConfigPreserveCommentsKeepsWeightZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := `
openai-compatibility:
  - name: nvidia-do
    base-url: https://integrate.api.nvidia.com/v1
    api-key-entries:
      - api-key: key-a
      - api-key: key-b
    models:
      - name: deepseek-ai/deepseek-v4-flash
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write original config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if len(cfg.OpenAICompatibility) != 1 || len(cfg.OpenAICompatibility[0].APIKeyEntries) != 2 {
		t.Fatalf("unexpected parsed config: %+v", cfg.OpenAICompatibility)
	}

	zero := 0
	five := 5
	cfg.OpenAICompatibility[0].APIKeyEntries[0].Weight = &zero
	cfg.OpenAICompatibility[0].APIKeyEntries[1].Weight = &five

	if err := SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatalf("SaveConfigPreserveComments error: %v", err)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	savedText := string(saved)
	t.Logf("saved yaml:\n%s", savedText)

	var node yaml.Node
	if err := yaml.Unmarshal(saved, &node); err != nil {
		t.Fatalf("unmarshal saved config: %v", err)
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	entries := reloaded.OpenAICompatibility[0].APIKeyEntries
	if len(entries) != 2 {
		t.Fatalf("reloaded entries = %d, want 2", len(entries))
	}
	if entries[0].Weight == nil || *entries[0].Weight != 0 {
		t.Errorf("reloaded entry[0].Weight = %v, want 0 (must persist weight: 0)", weightPtr(entries[0].Weight))
	}
	if entries[1].Weight == nil || *entries[1].Weight != 5 {
		t.Errorf("reloaded entry[1].Weight = %v, want 5", weightPtr(entries[1].Weight))
	}
}

func weightPtr(w *int) any {
	if w == nil {
		return nil
	}
	return *w
}
