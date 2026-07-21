package codex

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// AgentIdentityAuthMode is the auth_mode value marking a codex credential that
// authenticates via OpenAI's agent-identity protocol (an ed25519-signed
// assertion) instead of a bearer access token. ChatGPT education ("k12") plan
// accounts use this because their plain access tokens no longer work upstream.
const AgentIdentityAuthMode = "agentIdentity"

// ParseAgentPrivateKey decodes the base64 PKCS#8 Ed25519 private key stored in
// a credential's agent_private_key field. The wire format matches what sub2api
// exports (base64.StdEncoding of the PKCS#8 DER).
func ParseAgentPrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(encoded)
	if raw == "" {
		return nil, errors.New("codex agent identity: private key is missing")
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("codex agent identity: private key is not valid base64")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("codex agent identity: private key is not valid PKCS#8")
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("codex agent identity: private key is not Ed25519")
	}
	return priv, nil
}

// BuildAgentAssertion produces the Authorization header value for an
// agent-identity request: "AgentAssertion " + base64url(JSON{agent_runtime_id,
// task_id, timestamp, signature}), where signature is the ed25519 signature
// over "<runtimeID>:<taskID>:<timestamp>" (RFC3339 UTC). This mirrors sub2api's
// buildAgentAssertion so the wire format matches what OpenAI expects.
func BuildAgentAssertion(runtimeID, taskID string, priv ed25519.PrivateKey, now time.Time) (string, error) {
	runtimeID = strings.TrimSpace(runtimeID)
	taskID = strings.TrimSpace(taskID)
	if runtimeID == "" || taskID == "" {
		return "", errors.New("codex agent identity: runtime or task id is missing")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("codex agent identity: invalid private key")
	}
	timestamp := now.UTC().Format(time.RFC3339)
	payload := []byte(runtimeID + ":" + taskID + ":" + timestamp)
	// Ed25519 signs the message directly; crypto.Hash(0) means "no prehash".
	signature, err := priv.Sign(nil, payload, crypto.Hash(0))
	if err != nil {
		return "", errors.New("codex agent identity: failed to sign assertion")
	}
	envelope := map[string]string{
		"agent_runtime_id": runtimeID,
		"task_id":          taskID,
		"timestamp":        timestamp,
		"signature":        base64.StdEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", errors.New("codex agent identity: failed to serialize assertion")
	}
	return "AgentAssertion " + base64.RawURLEncoding.EncodeToString(encoded), nil
}

// IsAgentIdentityMetadata reports whether the runtime auth metadata marks an
// agent-identity (k12) credential.
func IsAgentIdentityMetadata(meta map[string]any) bool {
	if meta == nil {
		return false
	}
	if v, ok := meta["auth_mode"].(string); ok {
		return strings.EqualFold(strings.TrimSpace(v), AgentIdentityAuthMode)
	}
	return false
}

// AgentAssertionFromMetadata builds the Authorization assertion from a codex
// auth's runtime metadata (agent_private_key / agent_runtime_id / task_id).
func AgentAssertionFromMetadata(meta map[string]any, now time.Time) (string, error) {
	if meta == nil {
		return "", errors.New("codex agent identity: metadata is nil")
	}
	str := func(k string) string {
		if v, ok := meta[k].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	priv, err := ParseAgentPrivateKey(str("agent_private_key"))
	if err != nil {
		return "", err
	}
	return BuildAgentAssertion(str("agent_runtime_id"), str("task_id"), priv, now)
}
