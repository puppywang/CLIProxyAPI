package management

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// sub2apiExportType marks a legacy sub2api "export accounts" JSON blob.
// Newer sub2api builds omit this field and instead ship:
//
//	{"exported_at":"...","proxies":[],"accounts":[...]}
//
// Detection therefore accepts either the explicit type or the accounts-array
// shape (see isSub2apiExport).
const sub2apiExportType = "sub2api-data"

type sub2apiExport struct {
	Type       string           `json:"type"`
	ExportedAt string           `json:"exported_at"`
	Accounts   []sub2apiAccount `json:"accounts"`
}

type sub2apiAccount struct {
	Name        string         `json:"name"`
	Platform    string         `json:"platform"`
	Type        string         `json:"type"`
	Credentials map[string]any `json:"credentials"`
	Extra       map[string]any `json:"extra"`
}

type sub2apiConvertedFile struct {
	Name string
	Data []byte
}

type sub2apiSkip struct {
	Index  int    `json:"index"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason"`
}

var sub2apiNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._@-]`)

// isSub2apiExport reports whether data is a sub2api accounts export.
//
// Accepted shapes:
//  1. Legacy: {"type":"sub2api-data","accounts":[...]}
//  2. Current: {"exported_at":"...","accounts":[{platform,credentials,...}, ...]}
//     (type field omitted; each account is a sub2api platform record, NOT a
//     CPA auth file — writing it raw would produce a useless credential)
//
// Plain CPA auth files ({"type":"codex",...} / {"type":"claude",...}) must
// NOT match, even if they happen to contain an "accounts" key.
func isSub2apiExport(data []byte) bool {
	var probe struct {
		Type       string          `json:"type"`
		ExportedAt string          `json:"exported_at"`
		Accounts   json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(probe.Type), sub2apiExportType) {
		return true
	}
	// Reject known CPA auth file types so a normal codex/claude upload is
	// never re-interpreted as a sub2api export.
	switch strings.ToLower(strings.TrimSpace(probe.Type)) {
	case "codex", "claude", "gemini", "antigravity", "qwen", "iflow", "vertex", "openai-compatibility", "xai":
		return false
	}
	if len(probe.Accounts) == 0 || probe.Accounts[0] != '[' {
		return false
	}
	// Require at least one account-shaped object with platform+credentials
	// (or the exported_at marker that current sub2api always sets).
	if strings.TrimSpace(probe.ExportedAt) != "" {
		return true
	}
	var accounts []sub2apiAccount
	if err := json.Unmarshal(probe.Accounts, &accounts); err != nil || len(accounts) == 0 {
		return false
	}
	for _, acc := range accounts {
		if strings.TrimSpace(acc.Platform) != "" && acc.Credentials != nil {
			return true
		}
	}
	return false
}

// convertSub2apiExport parses a sub2api export and converts each supported
// account into a CPA auth file. Currently only the OpenAI/Codex platform is
// mapped (both the agentIdentity/K12 flow and standard OAuth); other platforms
// are returned as skips with a reason.
func convertSub2apiExport(data []byte) (files []sub2apiConvertedFile, skips []sub2apiSkip, err error) {
	if !isSub2apiExport(data) {
		return nil, nil, fmt.Errorf("not a sub2api export")
	}
	var export sub2apiExport
	if errUnmarshal := json.Unmarshal(data, &export); errUnmarshal != nil {
		return nil, nil, fmt.Errorf("invalid sub2api export JSON: %w", errUnmarshal)
	}
	if len(export.Accounts) == 0 {
		return nil, nil, fmt.Errorf("sub2api export contained no accounts")
	}
	seen := make(map[string]int)
	for i, acc := range export.Accounts {
		platform := strings.ToLower(strings.TrimSpace(acc.Platform))
		if platform != "openai" && platform != "codex" {
			skips = append(skips, sub2apiSkip{Index: i, Name: acc.Name, Reason: "unsupported platform: " + acc.Platform})
			continue
		}
		name, fileData, convErr := sub2apiAccountToCodex(acc)
		if convErr != nil {
			skips = append(skips, sub2apiSkip{Index: i, Name: acc.Name, Reason: convErr.Error()})
			continue
		}
		// De-duplicate identical target filenames within one export.
		if n := seen[name]; n > 0 {
			base := strings.TrimSuffix(name, ".json")
			name = fmt.Sprintf("%s-%d.json", base, n+1)
		}
		seen[strings.TrimSuffix(name, ".json")+".json"]++
		files = append(files, sub2apiConvertedFile{Name: name, Data: fileData})
	}
	return files, skips, nil
}

// sub2apiAccountToCodex maps one OpenAI/Codex sub2api account to a CPA codex
// auth file. The flat top-level keys land in auth.Metadata on load.
func sub2apiAccountToCodex(acc sub2apiAccount) (string, []byte, error) {
	c := acc.Credentials
	if c == nil {
		return "", nil, fmt.Errorf("account %q has no credentials", acc.Name)
	}
	str := func(k string) string {
		if v, ok := c[k].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	// Current sub2api OAuth exports put email under credentials.email and/or
	// extra.email; fall back to either before using the account name.
	extraStr := func(k string) string {
		if acc.Extra == nil {
			return ""
		}
		if v, ok := acc.Extra[k].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	first := func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}
		return ""
	}
	// sub2api may emit token expiry as either an RFC3339 string ("expired" /
	// "expires_at") or a unix-seconds number ("expires_at": 1786007956).
	// CPA auth files use the string field "expired".
	expiryString := func() string {
		if exp := str("expired"); exp != "" {
			return exp
		}
		if exp := str("expires_at"); exp != "" {
			return exp
		}
		switch v := c["expires_at"].(type) {
		case float64:
			if v > 0 {
				return time.Unix(int64(v), 0).UTC().Format(time.RFC3339)
			}
		case json.Number:
			if n, err := v.Int64(); err == nil && n > 0 {
				return time.Unix(n, 0).UTC().Format(time.RFC3339)
			}
		}
		return ""
	}

	email := first(str("email"), extraStr("email"), strings.TrimSpace(acc.Name), "codex")
	out := map[string]any{"type": "codex", "email": email}
	planType := first(str("plan_type"), "")

	if strings.EqualFold(str("auth_mode"), "agentIdentity") {
		if str("agent_private_key") == "" || str("agent_runtime_id") == "" || str("task_id") == "" {
			return "", nil, fmt.Errorf("agentIdentity account %q missing agent_private_key/runtime/task", email)
		}
		accountID := first(str("chatgpt_account_id"), str("account_id"))
		out["auth_mode"] = "agentIdentity"
		if planType == "" {
			planType = "k12"
		}
		out["plan_type"] = planType
		out["account_id"] = accountID
		out["chatgpt_account_id"] = accountID
		out["chatgpt_user_id"] = str("chatgpt_user_id")
		out["workspace_id"] = str("workspace_id")
		out["agent_private_key"] = str("agent_private_key")
		out["agent_runtime_id"] = str("agent_runtime_id")
		out["task_id"] = str("task_id")
		out["id_token"] = str("id_token")
		if lr := str("last_refresh"); lr != "" {
			out["last_refresh"] = lr
		}
		// Agent-identity signs per request; keep the record non-expiring so the
		// scheduler never treats it as a stale credential needing a refresh.
		out["expired"] = "2030-01-01T00:00:00Z"
	} else {
		accessToken := str("access_token")
		refreshToken := str("refresh_token")
		if accessToken == "" && refreshToken == "" {
			return "", nil, fmt.Errorf("codex oauth account %q has no access_token/refresh_token", email)
		}
		out["access_token"] = accessToken
		out["refresh_token"] = refreshToken
		out["account_id"] = first(str("account_id"), str("chatgpt_account_id"))
		if accountID := first(str("chatgpt_account_id"), str("account_id")); accountID != "" {
			out["chatgpt_account_id"] = accountID
		}
		if userID := str("chatgpt_user_id"); userID != "" {
			out["chatgpt_user_id"] = userID
		}
		out["id_token"] = str("id_token")
		if planType != "" {
			out["plan_type"] = planType
		}
		if lr := str("last_refresh"); lr != "" {
			out["last_refresh"] = lr
		}
		if exp := expiryString(); exp != "" {
			out["expired"] = exp
		}
	}

	safe := sub2apiNameUnsafe.ReplaceAllString(email, "_")
	name := "codex-" + safe
	if planType != "" {
		name += "-" + planType
	}
	name += ".json"

	fileData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("serialize %q: %w", email, err)
	}
	return name, fileData, nil
}

// ImportSub2api converts a sub2api accounts export (posted as the request body)
// into CPA auth files and registers them. Returns a per-account summary.
func (h *Handler) ImportSub2api(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	files, skips, convErr := convertSub2apiExport(data)
	if convErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": convErr.Error()})
		return
	}

	ctx := c.Request.Context()
	created := make([]string, 0, len(files))
	failed := make([]gin.H, 0)
	for _, f := range files {
		if errWrite := h.writeSingleAuthFile(ctx, f.Name, f.Data); errWrite != nil {
			failed = append(failed, gin.H{"name": f.Name, "error": errWrite.Error()})
			continue
		}
		created = append(created, f.Name)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"created": created,
		"skipped": skips,
		"failed":  failed,
		"summary": gin.H{"created": len(created), "skipped": len(skips), "failed": len(failed)},
	})
}
