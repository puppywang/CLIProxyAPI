package helps

import (
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
)

// IsCodexModelNotSupportedError reports whether an upstream response is the
// per-account "model is not supported when using Codex with a ChatGPT account"
// rejection (HTTP 400/422). This is a durable entitlement condition, distinct
// from a transient rate limit or an oversized-request 400.
//
// The caller records it against the account so the selector stops routing that
// model there; the request itself fails over to an entitled account rather than
// being served by a different model.
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
