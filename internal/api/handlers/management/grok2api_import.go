package management

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	xaiauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/xai"
)

// grok2apiExportType marks an explicitly typed grok2api "export accounts" blob.
// Current grok2api builds ship a bare {"accounts":[...]} instead, so detection
// accepts either (see isGrok2apiExport).
const grok2apiExportType = "grok2api-data"

// grok2apiExport is a grok2api accounts export:
//
//	{"accounts":[{"provider":"grok_build","email":"...","access_token":"...",
//	              "refresh_token":"...","expires_at":"...","user_id":"..."}]}
//
// Unlike sub2api, credentials are flat on each account and the upstream flavour
// is named per account in "provider".
type grok2apiExport struct {
	Accounts []grok2apiAccount `json:"accounts"`
}

type grok2apiAccount struct {
	Provider     string `json:"provider"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresAt    any    `json:"expires_at"`
	ExpiresIn    int    `json:"expires_in"`
	Email        string `json:"email"`
	Sub          string `json:"sub"`
	UserID       string `json:"user_id"`
	PrincipalID  string `json:"principal_id"`
	TeamID       string `json:"team_id"`
}

// isGrok2apiExport reports whether data is a grok2api accounts export.
//
// Accepted shapes:
//  1. {"type":"grok2api-data","accounts":[...]}
//  2. {"accounts":[{"provider":"grok_build","access_token":...}, ...]}
//
// Plain CPA auth files and sub2api exports must not match: the former carry a
// known "type", the latter describe accounts as {platform, credentials} without
// a flat token.
func isGrok2apiExport(data []byte) bool {
	var probe struct {
		Type     string          `json:"type"`
		Accounts json.RawMessage `json:"accounts"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(probe.Type), grok2apiExportType) {
		return true
	}
	if strings.TrimSpace(probe.Type) != "" {
		return false
	}
	if len(probe.Accounts) == 0 || probe.Accounts[0] != '[' {
		return false
	}
	var accounts []grok2apiAccount
	if err := json.Unmarshal(probe.Accounts, &accounts); err != nil || len(accounts) == 0 {
		return false
	}
	for _, acc := range accounts {
		if strings.TrimSpace(acc.Provider) == "" {
			continue
		}
		if _, ok := grok2apiUsingAPI(acc.Provider); !ok {
			continue
		}
		if strings.TrimSpace(acc.AccessToken) != "" || strings.TrimSpace(acc.RefreshToken) != "" {
			return true
		}
	}
	return false
}

// grok2apiUsingAPI maps a grok2api account provider onto the CPA xAI endpoint
// choice. Grok Build (cli-chat-proxy) draws on the SuperGrok subscription
// allowance; the api flavours are pay-per-credit api.x.ai accounts. The second
// return value reports whether the provider is an xAI OAuth flavour at all —
// grok2api also manages cookie-based grok.com accounts, which CPA cannot use.
func grok2apiUsingAPI(provider string) (usingAPI bool, ok bool) {
	normalized := strings.ToLower(strings.TrimSpace(provider))
	normalized = strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(normalized)
	switch normalized {
	case "grok_build", "grokbuild", "grok_cli", "grokcli", "grok", "xai", "x_ai":
		return false, true
	case "grok_api", "grokapi", "xai_api", "x_ai_api":
		return true, true
	default:
		return false, false
	}
}

// convertGrok2apiExport parses a grok2api export and converts each xAI OAuth
// account into a CPA xai auth file. Accounts of other flavours (e.g. grok.com
// cookie sessions) are returned as skips with a reason.
func convertGrok2apiExport(data []byte) (files []sub2apiConvertedFile, skips []sub2apiSkip, err error) {
	if !isGrok2apiExport(data) {
		return nil, nil, fmt.Errorf("not a grok2api export")
	}
	var export grok2apiExport
	if errUnmarshal := json.Unmarshal(data, &export); errUnmarshal != nil {
		return nil, nil, fmt.Errorf("invalid grok2api export JSON: %w", errUnmarshal)
	}
	if len(export.Accounts) == 0 {
		return nil, nil, fmt.Errorf("grok2api export contained no accounts")
	}
	seen := make(map[string]int)
	for i, acc := range export.Accounts {
		label := firstNonEmpty(acc.Email, acc.Name)
		usingAPI, ok := grok2apiUsingAPI(acc.Provider)
		if !ok {
			skips = append(skips, sub2apiSkip{Index: i, Name: label, Reason: "unsupported provider: " + acc.Provider})
			continue
		}
		name, fileData, convErr := grok2apiAccountToXAI(acc, usingAPI)
		if convErr != nil {
			skips = append(skips, sub2apiSkip{Index: i, Name: label, Reason: convErr.Error()})
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

// grok2apiAccountToXAI maps one grok2api account to a CPA xai auth file. The
// emitted keys match what the xAI OAuth flow persists, so an imported account
// and a browser-authorized one behave identically. token_endpoint is left out
// on purpose: the refresh path resolves it from OIDC discovery when absent.
func grok2apiAccountToXAI(acc grok2apiAccount, usingAPI bool) (string, []byte, error) {
	accessToken := strings.TrimSpace(acc.AccessToken)
	refreshToken := strings.TrimSpace(acc.RefreshToken)
	email := firstNonEmpty(acc.Email, acc.Name)
	if accessToken == "" && refreshToken == "" {
		return "", nil, fmt.Errorf("account %q has no access_token/refresh_token", email)
	}
	// A foreign OAuth client cannot be refreshed: CPA always posts its own
	// grok-cli client_id, so such a credential would die at the first refresh.
	if clientID := strings.TrimSpace(acc.ClientID); clientID != "" && clientID != xaiauth.ClientID {
		return "", nil, fmt.Errorf("account %q uses OAuth client %s, not the grok-cli client", email, clientID)
	}

	subject := firstNonEmpty(acc.Sub, acc.UserID, acc.PrincipalID)
	out := map[string]any{
		"type":          "xai",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"auth_kind":     "oauth",
		"base_url":      xaiauth.DefaultAPIBaseURL,
	}
	if idToken := strings.TrimSpace(acc.IDToken); idToken != "" {
		out["id_token"] = idToken
	}
	if tokenType := strings.TrimSpace(acc.TokenType); tokenType != "" {
		out["token_type"] = tokenType
	}
	if acc.ExpiresIn > 0 {
		out["expires_in"] = acc.ExpiresIn
	}
	if expired := grok2apiExpiry(acc.ExpiresAt); expired != "" {
		out["expired"] = expired
	}
	if email != "" {
		out["email"] = email
	}
	if subject != "" {
		out["sub"] = subject
	}
	if teamID := strings.TrimSpace(acc.TeamID); teamID != "" {
		out["team_id"] = teamID
	}
	// Grok Build is the OAuth default, so only the api flavour needs the
	// explicit override; leaving it unset keeps the monitor toggle authoritative.
	if usingAPI {
		out["using_api"] = true
	}

	name := xaiauth.CredentialFileName(email, subject)
	fileData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("serialize %q: %w", email, err)
	}
	return name, fileData, nil
}

// grok2apiExpiry normalizes a grok2api expires_at value (RFC3339 string, with
// or without fractional seconds, or unix seconds) into the RFC3339 string CPA
// stores in "expired". Unparseable strings are passed through unchanged.
func grok2apiExpiry(value any) string {
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return ""
		}
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano} {
			if ts, err := time.Parse(layout, trimmed); err == nil {
				return ts.UTC().Format(time.RFC3339)
			}
		}
		return trimmed
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

// ImportGrok2api converts a grok2api accounts export (posted as the request
// body) into CPA xai auth files and registers them. Returns a per-account
// summary. Uploading the same export through the auth-files upload endpoint
// takes the same path via writeAuthFile.
func (h *Handler) ImportGrok2api(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	files, skips, convErr := convertGrok2apiExport(data)
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
