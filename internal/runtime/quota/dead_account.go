package quota

import "strings"

// classifyDeadAccount inspects a quota-fetch error and reports whether it
// signals a PERMANENTLY unusable account — one the operator should clean up
// rather than wait to recover. It deliberately matches only unambiguous,
// terminal upstream signals; transient conditions (429 rate limits, cooldowns,
// network/5xx blips) are NOT treated as dead so a temporarily-throttled
// account never gets flagged for deletion.
//
// The returned reason is a short human-readable label surfaced in the monitor
// quota panel (e.g. "workspace deactivated"). ok=false means the error is not
// a terminal dead signal and no marker should be set.
//
// wham/usage surfaces these as, e.g.:
//
//	wham/usage status 402: {"detail":{"code":"deactivated_workspace"}}
//	wham/usage status 401: {"detail":"This account has been deactivated"}
func classifyDeadAccount(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "deactivated_workspace"),
		strings.Contains(msg, "workspace has been deactivated"),
		strings.Contains(msg, "workspace is deactivated"):
		return "workspace deactivated", true
	case strings.Contains(msg, "account_deactivated"),
		strings.Contains(msg, "account has been deactivated"),
		strings.Contains(msg, "account is deactivated"),
		strings.Contains(msg, "account is disabled"):
		return "account deactivated", true
	default:
		return "", false
	}
}
