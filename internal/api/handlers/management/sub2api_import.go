package management

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// sub2apiExportType marks a sub2api "export accounts" JSON blob.
const sub2apiExportType = "sub2api-data"

type sub2apiExport struct {
	Type     string           `json:"type"`
	Accounts []sub2apiAccount `json:"accounts"`
}

type sub2apiAccount struct {
	Name        string         `json:"name"`
	Platform    string         `json:"platform"`
	Type        string         `json:"type"`
	Credentials map[string]any `json:"credentials"`
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
func isSub2apiExport(data []byte) bool {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(probe.Type), sub2apiExportType)
}

// convertSub2apiExport parses a sub2api export and converts each supported
// account into a CPA auth file. Currently only the OpenAI/Codex platform is
// mapped (both the agentIdentity/K12 flow and standard OAuth); other platforms
// are returned as skips with a reason.
func convertSub2apiExport(data []byte) (files []sub2apiConvertedFile, skips []sub2apiSkip, err error) {
	var export sub2apiExport
	if errUnmarshal := json.Unmarshal(data, &export); errUnmarshal != nil {
		return nil, nil, fmt.Errorf("invalid sub2api export JSON: %w", errUnmarshal)
	}
	if !strings.EqualFold(strings.TrimSpace(export.Type), sub2apiExportType) {
		return nil, nil, fmt.Errorf("not a sub2api export (type=%q)", export.Type)
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
	first := func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}
		return ""
	}

	email := first(str("email"), strings.TrimSpace(acc.Name), "codex")
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
		out["id_token"] = str("id_token")
		if lr := str("last_refresh"); lr != "" {
			out["last_refresh"] = lr
		}
		if exp := str("expired"); exp != "" {
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
