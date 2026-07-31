package helps

import (
	"testing"
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
