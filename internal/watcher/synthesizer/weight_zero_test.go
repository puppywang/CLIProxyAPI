package synthesizer

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// TestSynthesizeOpenAICompatWeightZero verifies that a weight: 0 entry in
// config produces an auth with attributes["weight"]="0" (so the scheduler
// excludes it under weighted round-robin).
func TestSynthesizeOpenAICompatWeightZero(t *testing.T) {
	zero := 0
	five := 5
	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:    "nvidia-do",
				BaseURL: "https://integrate.api.nvidia.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "key-a", Weight: &zero},
					{APIKey: "key-b", Weight: &five},
					{APIKey: "key-c"},
				},
				Models: []config.OpenAICompatibilityModel{
					{Name: "z-ai/glm-5.2"},
				},
			},
		},
	}

	synth := NewConfigSynthesizer()
	auths, err := synth.Synthesize(&SynthesisContext{
		Config:      cfg,
		Now:         time.Now(),
		IDGenerator: NewStableIDGenerator(),
	})
	if err != nil {
		t.Fatalf("Synthesize error: %v", err)
	}
	if len(auths) != 3 {
		t.Fatalf("auths = %d, want 3", len(auths))
	}

	byKey := map[string]*coreauth.Auth{}
	for _, a := range auths {
		byKey[a.Attributes["api_key"]] = a
	}

	if a := byKey["key-a"]; a == nil {
		t.Fatal("key-a auth missing")
	} else if w := a.Attributes[coreauth.AttributeWeight]; w != "0" {
		t.Errorf("key-a weight attr = %q, want \"0\"", w)
	}

	if a := byKey["key-b"]; a == nil {
		t.Fatal("key-b auth missing")
	} else if w := a.Attributes[coreauth.AttributeWeight]; w != "5" {
		t.Errorf("key-b weight attr = %q, want \"5\"", w)
	}

	if a := byKey["key-c"]; a == nil {
		t.Fatal("key-c auth missing")
	} else if _, ok := a.Attributes[coreauth.AttributeWeight]; ok {
		t.Errorf("key-c should have no weight attr (nil weight), got %q", a.Attributes[coreauth.AttributeWeight])
	}
}
