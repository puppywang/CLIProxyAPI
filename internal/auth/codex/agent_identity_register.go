package codex

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Agent Identity registration API base URLs (mirrors openai/codex
// codex-rs/agent-identity: PROD/STAGING _AGENT_IDENTITY_AUTHAPI_BASE_URL).
const (
	AgentIdentityAuthAPIBaseURL        = "https://auth.openai.com/api/accounts"
	AgentIdentityAuthAPIStagingBaseURL = "https://auth.api.openai.org/api/accounts"
)

// agentIdentityUserAgent / Originator mirror the Codex CLI so registration
// traffic matches the fingerprint the credential already presents elsewhere.
// Keep aligned with codexUserAgent/codexOriginator in
// internal/runtime/executor/codex_executor.go and defaultUserAgent in
// internal/runtime/quota/codex_wham.go.
const (
	agentIdentityUserAgent  = "codex-tui/0.135.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.135.0)"
	agentIdentityOriginator = "codex-tui"
	// codexAgentVersion is the agent_version reported in the abom block.
	codexAgentVersion = "0.135.0"
)

// GeneratedAgentKey holds a freshly generated agent-identity keypair. The
// private key is PKCS#8 DER base64 (the storage form used across CPA); the
// public key is the SSH ed25519 string ("ssh-ed25519 <base64>"), the exact
// wire form OpenAI's register endpoint expects.
type GeneratedAgentKey struct {
	PrivateKeyPKCS8Base64 string
	PublicKeySSH          string
}

// GenerateAgentKey creates a new ed25519 agent-identity keypair.
func GenerateAgentKey() (GeneratedAgentKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return GeneratedAgentKey{}, fmt.Errorf("codex agent identity: generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return GeneratedAgentKey{}, fmt.Errorf("codex agent identity: marshal key: %w", err)
	}
	return GeneratedAgentKey{
		PrivateKeyPKCS8Base64: base64.StdEncoding.EncodeToString(der),
		PublicKeySSH:          EncodeSSHEd25519PublicKey(pub),
	}, nil
}

// EncodeSSHEd25519PublicKey renders an ed25519 public key in the SSH wire form
// "ssh-ed25519 <base64(blob)>", where blob = ssh-string("ssh-ed25519") +
// ssh-string(rawKey) and an ssh-string is a 4-byte big-endian length prefix
// followed by the bytes. Mirrors codex's encode_ssh_ed25519_public_key.
func EncodeSSHEd25519PublicKey(pub ed25519.PublicKey) string {
	var blob []byte
	blob = appendSSHString(blob, []byte("ssh-ed25519"))
	blob = appendSSHString(blob, pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
}

func appendSSHString(buf, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	buf = append(buf, length[:]...)
	return append(buf, value...)
}

// AgentBillOfMaterials is the abom telemetry block the register request
// carries; values mirror what the Codex CLI sends.
type AgentBillOfMaterials struct {
	AgentVersion    string `json:"agent_version"`
	AgentHarnessID  string `json:"agent_harness_id"`
	RunningLocation string `json:"running_location"`
}

// BuildABOM builds the abom block. harnessID defaults to "codex-cli" and
// runningLocation to "cli-linux" (the CPA host is Linux).
func BuildABOM(harnessID, runningLocation string) AgentBillOfMaterials {
	if strings.TrimSpace(harnessID) == "" {
		harnessID = "codex-cli"
	}
	if strings.TrimSpace(runningLocation) == "" {
		runningLocation = "cli-linux"
	}
	return AgentBillOfMaterials{
		AgentVersion:    codexAgentVersion,
		AgentHarnessID:  harnessID,
		RunningLocation: runningLocation,
	}
}

type registerAgentRequest struct {
	ABOM           AgentBillOfMaterials `json:"abom"`
	AgentPublicKey string               `json:"agent_public_key"`
	Capabilities   []string             `json:"capabilities"`
	TTL            *uint64              `json:"ttl"`
}

type registerAgentResponse struct {
	AgentRuntimeID string `json:"agent_runtime_id"`
}

// RegisterAgentRuntime performs the runtime-registration step: it submits the
// generated public key to OpenAI's agent/register endpoint authenticated by
// the account's access token (Bearer) and returns the minted agent_runtime_id.
// The access token is used ONLY here; the returned runtime id plus the private
// key are durable and self-sign per-run tasks afterwards (no refresh token,
// no re-verification). capabilities defaults to ["responsesapi"] (what the
// Codex CLI sends) when nil.
func RegisterAgentRuntime(ctx context.Context, client *http.Client, baseURL, accessToken, publicKeySSH string, abom AgentBillOfMaterials, capabilities []string, fedramp bool) (string, error) {
	if client == nil {
		return "", errors.New("codex agent identity: http client is nil")
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return "", errors.New("codex agent identity: access token is required for registration")
	}
	if strings.TrimSpace(publicKeySSH) == "" {
		return "", errors.New("codex agent identity: public key is required for registration")
	}
	if capabilities == nil {
		capabilities = []string{"responsesapi"}
	}
	payload, err := json.Marshal(registerAgentRequest{
		ABOM:           abom,
		AgentPublicKey: publicKeySSH,
		Capabilities:   capabilities,
		TTL:            nil,
	})
	if err != nil {
		return "", fmt.Errorf("codex agent identity: marshal register request: %w", err)
	}
	url := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/v1/agent/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("codex agent identity: build register request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", agentIdentityUserAgent)
	req.Header.Set("Originator", agentIdentityOriginator)
	if fedramp {
		req.Header.Set("X-OpenAI-Fedramp", "true")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("codex agent identity: register request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("codex agent identity: register returned status %d: %s", resp.StatusCode, truncateForError(body, 300))
	}
	var result registerAgentResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("codex agent identity: parse register response: %w", err)
	}
	runtimeID := strings.TrimSpace(result.AgentRuntimeID)
	if runtimeID == "" {
		return "", errors.New("codex agent identity: register response omitted agent_runtime_id")
	}
	return runtimeID, nil
}

type registerTaskRequest struct {
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type registerTaskResponse struct {
	TaskID               string `json:"task_id"`
	TaskIDCamel          string `json:"taskId"`
	EncryptedTaskID      string `json:"encrypted_task_id"`
	EncryptedTaskIDCamel string `json:"encryptedTaskId"`
}

// RegisterAgentTask performs the per-runtime task-registration step. It signs
// "<runtimeID>:<timestamp>" with the private key (NO bearer token needed) and
// returns the task_id, decrypting an encrypted_task_id when the server returns
// the sealed form. Mirrors codex register_agent_task / sub2api
// registerAgentIdentityTask. Call this both on fresh registration and to
// recover a runtime whose task_id has expired (upstream 401 invalid_task_id).
func RegisterAgentTask(ctx context.Context, client *http.Client, baseURL, runtimeID string, priv ed25519.PrivateKey, now time.Time) (string, error) {
	if client == nil {
		return "", errors.New("codex agent identity: http client is nil")
	}
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" {
		return "", errors.New("codex agent identity: runtime id is required for task registration")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("codex agent identity: invalid private key")
	}
	timestamp := now.UTC().Format(time.RFC3339)
	sig, err := priv.Sign(nil, []byte(runtimeID+":"+timestamp), crypto.Hash(0))
	if err != nil {
		return "", errors.New("codex agent identity: failed to sign task registration")
	}
	payload, err := json.Marshal(registerTaskRequest{
		Timestamp: timestamp,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return "", fmt.Errorf("codex agent identity: marshal task request: %w", err)
	}
	url := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/v1/agent/" + runtimeID + "/task/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("codex agent identity: build task request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", agentIdentityUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("codex agent identity: task request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("codex agent identity: task registration returned status %d: %s", resp.StatusCode, truncateForError(body, 300))
	}
	var result registerTaskResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("codex agent identity: parse task response: %w", err)
	}
	if taskID := strings.TrimSpace(result.TaskID); taskID != "" {
		return taskID, nil
	}
	if taskID := strings.TrimSpace(result.TaskIDCamel); taskID != "" {
		return taskID, nil
	}
	encrypted := strings.TrimSpace(result.EncryptedTaskID)
	if encrypted == "" {
		encrypted = strings.TrimSpace(result.EncryptedTaskIDCamel)
	}
	if encrypted == "" {
		return "", errors.New("codex agent identity: task registration response omitted task id")
	}
	return DecryptTaskID(priv, encrypted)
}

// DecryptTaskID decrypts a sealed-box encrypted_task_id using the agent's
// ed25519 private key converted to its X25519 form (SHA-512(seed)[:32] with
// the standard curve25519 clamp, then a NaCl anonymous box open). Mirrors
// codex decrypt_task_id_response / sub2api decryptAgentTaskID.
func DecryptTaskID(priv ed25519.PrivateKey, encrypted string) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("codex agent identity: invalid private key")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encrypted))
	if err != nil {
		return "", errors.New("codex agent identity: encrypted task id is not valid base64")
	}
	curvePrivate, curvePublic, err := curve25519KeypairFromEd25519(priv)
	if err != nil {
		return "", err
	}
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, &curvePublic, &curvePrivate)
	if !ok {
		return "", errors.New("codex agent identity: failed to decrypt encrypted task id")
	}
	taskID := strings.TrimSpace(string(plaintext))
	if taskID == "" {
		return "", errors.New("codex agent identity: decrypted task id is empty")
	}
	return taskID, nil
}

// curve25519KeypairFromEd25519 derives the X25519 keypair matching the agent's
// ed25519 private key, the recipient key OpenAI seals the encrypted task id to.
func curve25519KeypairFromEd25519(priv ed25519.PrivateKey) (private, public [32]byte, err error) {
	digest := sha512.Sum512(priv.Seed())
	copy(private[:], digest[:32])
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	pubBytes, deriveErr := curve25519.X25519(private[:], curve25519.Basepoint)
	if deriveErr != nil {
		return [32]byte{}, [32]byte{}, errors.New("codex agent identity: failed to derive decryption key")
	}
	copy(public[:], pubBytes)
	return private, public, nil
}

// AccessTokenClaims are the fields lifted from an OpenAI access-token JWT to
// label the generated auth file. All optional; registration only strictly
// needs a token upstream accepts.
type AccessTokenClaims struct {
	AccountID string
	Email     string
	PlanType  string
	Fedramp   bool
}

// DecodeAccessTokenClaims extracts account/profile fields from an OpenAI
// access-token JWT WITHOUT verifying the signature (upstream verifies the
// token when we register; these claims only label the auth file). Reads the
// namespaced "https://api.openai.com/auth" and ".../profile" claims.
func DecodeAccessTokenClaims(accessToken string) (AccessTokenClaims, error) {
	parts := strings.Split(strings.TrimSpace(accessToken), ".")
	if len(parts) < 2 {
		return AccessTokenClaims{}, errors.New("codex agent identity: access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return AccessTokenClaims{}, errors.New("codex agent identity: access token payload is not valid base64url")
		}
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return AccessTokenClaims{}, errors.New("codex agent identity: access token payload is not valid JSON")
	}
	var auth struct {
		ChatGPTAccountID string `json:"chatgpt_account_id"`
		PlanType         string `json:"chatgpt_plan_type"`
		Fedramp          bool   `json:"chatgpt_account_is_fedramp"`
	}
	if raw, ok := envelope["https://api.openai.com/auth"]; ok {
		_ = json.Unmarshal(raw, &auth)
	}
	var profile struct {
		Email string `json:"email"`
	}
	if raw, ok := envelope["https://api.openai.com/profile"]; ok {
		_ = json.Unmarshal(raw, &profile)
	}
	return AccessTokenClaims{
		AccountID: strings.TrimSpace(auth.ChatGPTAccountID),
		PlanType:  strings.TrimSpace(auth.PlanType),
		Email:     strings.TrimSpace(profile.Email),
		Fedramp:   auth.Fedramp,
	}, nil
}

func truncateForError(payload []byte, max int) string {
	if len(payload) <= max {
		return string(payload)
	}
	return string(payload[:max]) + "..."
}
