package helps

import (
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
)

// defaultCodexModelDowngrades is the built-in fallback applied when
// config.Codex.ModelDowngrades is unset. gpt-5.6-sol ("most capable", a paid
// flagship) is a per-account entitlement that some ChatGPT accounts lack;
// gpt-5.6-terra ("balanced everyday") is available on every plan tier, so it
// is a safe downgrade target that keeps the same gpt-5.6 family, context
// window, and reasoning levels.
var defaultCodexModelDowngrades = map[string]string{
	"gpt-5.6-sol": "gpt-5.6-terra",
}

// IsCodexModelNotSupportedError reports whether an upstream response is the
// per-account "model is not supported when using Codex with a ChatGPT account"
// rejection (HTTP 400/422). This is a durable entitlement condition, distinct
// from a transient rate limit or an oversized-request 400.
func IsCodexModelNotSupportedError(status int, body []byte) bool {
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		return false
	}
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "not supported when using codex") {
		return true
	}
	return strings.Contains(lower, "not supported") && strings.Contains(lower, "chatgpt account")
}

// CodexModelBase returns the base model name with any thinking suffix stripped.
func CodexModelBase(reqModel string) string {
	return thinking.ParseSuffix(reqModel).ModelName
}

// ResolveCodexModelDowngrade returns the downgraded req.Model to retry with on
// a model_not_supported fallback, or "" when no downgrade is configured for the
// request's base model. cfg.Codex.ModelDowngrades takes per-key precedence over
// the built-in default (so an operator can override or disable an entry by
// mapping it to ""). The request's thinking suffix is preserved so the
// reasoning level carries over to the fallback model.
func ResolveCodexModelDowngrade(cfg *config.Config, reqModel string) string {
	base := CodexModelBase(reqModel)
	if base == "" {
		return ""
	}
	target, ok := "", false
	if cfg != nil {
		target, ok = cfg.Codex.ModelDowngrades[base]
	}
	if !ok {
		target = defaultCodexModelDowngrades[base]
	}
	target = strings.TrimSpace(target)
	if target == "" || target == base {
		return ""
	}
	if strings.HasPrefix(reqModel, base) {
		return target + reqModel[len(base):]
	}
	return target
}
