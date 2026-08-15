package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveConfigPreserveCommentsKeepsZenInjectContextFalse verifies that an
// explicit opencode-zen-inject-context: false survives the comment-preserving
// persist path. The toggle defaults to enabled (true), so a persisted false
// is a deliberate operator override; without the isKnownDefaultValue
// exception it was pruned as a "default" and the monitor-panel toggle stopped
// surviving restarts.
func TestSaveConfigPreserveCommentsKeepsZenInjectContextFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := `
openai-compatibility:
  - name: opencode-zen
    base-url: https://opencode.ai/zen/v1
    opencode-zen: true
    models:
      - name: deepseek-v4-flash-free
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write original config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	// Default is enabled.
	if !cfg.OpencodeZenInjectContext {
		t.Fatal("default OpencodeZenInjectContext = false, want true")
	}

	cfg.OpencodeZenInjectContext = false
	if err := SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatalf("SaveConfigPreserveComments error: %v", err)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	savedText := string(saved)
	t.Logf("saved yaml:\n%s", savedText)
	if !containsLine(savedText, "opencode-zen-inject-context: false") {
		t.Fatalf("saved config does not contain opencode-zen-inject-context: false\n%s", savedText)
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if reloaded.OpencodeZenInjectContext {
		t.Fatal("reloaded OpencodeZenInjectContext = true, want false (toggle must survive restart)")
	}
}

func containsLine(text, needle string) bool {
	return len(text) > 0 && indexOf(text, needle) >= 0
}

func indexOf(text, needle string) int {
	for i := 0; i+len(needle) <= len(text); i++ {
		if text[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
