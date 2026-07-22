package helps

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestIsCodexModelNotSupportedError(t *testing.T) {
	yes := `{"detail":"The 'gpt-5.6-sol' model is not supported when using Codex with a ChatGPT account."}`
	if !IsCodexModelNotSupportedError(400, []byte(yes)) {
		t.Error("expected model_not_supported to be detected on 400")
	}
	if !IsCodexModelNotSupportedError(422, []byte(yes)) {
		t.Error("expected detection on 422 too")
	}
	if IsCodexModelNotSupportedError(429, []byte(yes)) {
		t.Error("must not detect on non-4xx-validation status")
	}
	if IsCodexModelNotSupportedError(400, []byte(`{"error":"context_too_large"}`)) {
		t.Error("must not treat an unrelated 400 as model_not_supported")
	}
}

func TestResolveCodexModelDowngrade_Default(t *testing.T) {
	// Built-in default sol -> terra when config is empty.
	if got := ResolveCodexModelDowngrade(nil, "gpt-5.6-sol"); got != "gpt-5.6-terra" {
		t.Errorf("default sol downgrade = %q, want gpt-5.6-terra", got)
	}
	// A model with no mapping does not downgrade.
	if got := ResolveCodexModelDowngrade(nil, "gpt-5.4"); got != "" {
		t.Errorf("gpt-5.4 downgrade = %q, want empty", got)
	}
	// terra is a terminal target (never a key) -> no further downgrade, bounding the chain.
	if got := ResolveCodexModelDowngrade(nil, "gpt-5.6-terra"); got != "" {
		t.Errorf("terra downgrade = %q, want empty", got)
	}
}

func TestResolveCodexModelDowngrade_PreservesThinkingSuffix(t *testing.T) {
	// A thinking suffix (parenthesized) on the request model must carry over to
	// the fallback so the reasoning level is preserved.
	got := ResolveCodexModelDowngrade(nil, "gpt-5.6-sol(high)")
	if got != "gpt-5.6-terra(high)" {
		t.Errorf("suffix-preserving downgrade = %q, want gpt-5.6-terra(high)", got)
	}
}

func TestResolveCodexModelDowngrade_ConfigOverride(t *testing.T) {
	cfg := &config.Config{}
	cfg.Codex.ModelDowngrades = map[string]string{
		"gpt-5.6-sol": "gpt-5.6-luna", // override the default target
		"gpt-9.9-x":   "gpt-9.9-y",    // extend with a new mapping
	}
	if got := ResolveCodexModelDowngrade(cfg, "gpt-5.6-sol"); got != "gpt-5.6-luna" {
		t.Errorf("override sol downgrade = %q, want gpt-5.6-luna", got)
	}
	if got := ResolveCodexModelDowngrade(cfg, "gpt-9.9-x"); got != "gpt-9.9-y" {
		t.Errorf("extended downgrade = %q, want gpt-9.9-y", got)
	}
	// Explicit empty mapping disables the downgrade for that model.
	cfg.Codex.ModelDowngrades["gpt-5.6-sol"] = ""
	if got := ResolveCodexModelDowngrade(cfg, "gpt-5.6-sol"); got != "" {
		t.Errorf("disabled sol downgrade = %q, want empty", got)
	}
}
