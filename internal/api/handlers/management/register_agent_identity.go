package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

// agentRegistrationTimeout caps each upstream call in the registration flow.
// Credential acquisition is one of the few paths where a timeout is allowed
// (see AGENTS.md); once registered, runtime traffic sets none.
const agentRegistrationTimeout = 30 * time.Second

type registerAgentIdentityRequest struct {
	AccessToken string `json:"access_token"`
	ProxyURL    string `json:"proxy_url"`
	PlanType    string `json:"plan_type"`
	HarnessID   string `json:"harness_id"`
	Email       string `json:"email"`
	AccountID   string `json:"account_id"`
	Staging     bool   `json:"staging"`
	Fedramp     bool   `json:"fedramp"`
}

// RegisterAgentIdentity mints a durable Codex agent-identity credential from a
// one-time access token: it generates an ed25519 keypair, registers the runtime
// with OpenAI (POST /v1/agent/register, Bearer access_token), registers the
// first run task, and persists an agentIdentity codex auth file. The access
// token is used ONLY during this call; afterwards the account authenticates
// with the ed25519 identity alone — no refresh token, no SMS verification. This
// lets accounts that cannot receive verification codes or lack a refresh_token
// become permanent credentials.
func (h *Handler) RegisterAgentIdentity(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var body registerAgentIdentityRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	accessToken := strings.TrimSpace(body.AccessToken)
	if accessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access_token is required"})
		return
	}

	// Derive account labels from the token claims; explicit request values win.
	claims, _ := codexauth.DecodeAccessTokenClaims(accessToken)
	accountID := firstNonEmpty(strings.TrimSpace(body.AccountID), claims.AccountID)
	email := firstNonEmpty(strings.TrimSpace(body.Email), claims.Email, "codex-agent-identity")
	planType := firstNonEmpty(strings.TrimSpace(body.PlanType), claims.PlanType)
	fedramp := body.Fedramp || claims.Fedramp

	// Egress through the account's proxy so registration shares the IP the
	// account will use for chat traffic (avoids an IP-mismatch risk flag).
	transport, _, err := proxyutil.BuildHTTPTransport(strings.TrimSpace(body.ProxyURL))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid proxy_url: %v", err)})
		return
	}
	client := &http.Client{Timeout: agentRegistrationTimeout}
	if transport != nil {
		client.Transport = transport
	}

	baseURL := codexauth.AgentIdentityAuthAPIBaseURL
	if body.Staging {
		baseURL = codexauth.AgentIdentityAuthAPIStagingBaseURL
	}

	// 1. Generate key material.
	keyMat, err := codexauth.GenerateAgentKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// 2. Register the runtime (Bearer access_token).
	abom := codexauth.BuildABOM(strings.TrimSpace(body.HarnessID), "")
	runtimeID, err := codexauth.RegisterAgentRuntime(ctx, client, baseURL, accessToken, keyMat.PublicKeySSH, abom, nil, fedramp)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "stage": "register_runtime"})
		return
	}

	// 3. Register the first task (private-key signed, no bearer).
	priv, err := codexauth.ParseAgentPrivateKey(keyMat.PrivateKeyPKCS8Base64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	taskID, err := codexauth.RegisterAgentTask(ctx, client, baseURL, runtimeID, priv, time.Now())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "stage": "register_task", "agent_runtime_id": runtimeID})
		return
	}

	// 4. Build + persist the agentIdentity codex auth file. The flat keys land
	// in auth.Metadata on load (matches the sub2api-import shape).
	out := map[string]any{
		"type":               "codex",
		"email":              email,
		"auth_mode":          codexauth.AgentIdentityAuthMode,
		"account_id":         accountID,
		"chatgpt_account_id": accountID,
		"agent_private_key":  keyMat.PrivateKeyPKCS8Base64,
		"agent_runtime_id":   runtimeID,
		"task_id":            taskID,
		// Agent-identity signs per request; keep the record non-expiring so the
		// scheduler never treats it as a stale credential needing a refresh.
		"expired": "2030-01-01T00:00:00Z",
	}
	if planType != "" {
		out["plan_type"] = planType
	}
	fileData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	name := agentIdentityAuthFileName(email, planType)
	if errWrite := h.writeSingleAuthFile(ctx, name, fileData); errWrite != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errWrite.Error(), "stage": "persist", "agent_runtime_id": runtimeID})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":           "ok",
		"file":             name,
		"agent_runtime_id": runtimeID,
		"account_id":       accountID,
		"email":            email,
		"plan_type":        planType,
	})
}

// agentIdentityAuthFileName builds the codex auth filename, mirroring the
// sub2api-import naming (codex-<safe email>[-<plan>].json).
func agentIdentityAuthFileName(email, planType string) string {
	safe := sub2apiNameUnsafe.ReplaceAllString(email, "_")
	name := "codex-" + safe
	if planType != "" {
		name += "-" + planType
	}
	return name + ".json"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
