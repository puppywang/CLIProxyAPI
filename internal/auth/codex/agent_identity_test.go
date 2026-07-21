package codex

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// newTestAgentKey returns a fresh Ed25519 key encoded exactly as an
// agent_private_key credential is stored (base64.StdEncoding of PKCS#8 DER).
func newTestAgentKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pub, base64.StdEncoding.EncodeToString(der)
}

func TestParseAgentPrivateKey(t *testing.T) {
	_, encoded := newTestAgentKey(t)
	if _, err := ParseAgentPrivateKey(encoded); err != nil {
		t.Fatalf("ParseAgentPrivateKey(valid) error: %v", err)
	}
	for _, bad := range []string{"", "not-base64!!", base64.StdEncoding.EncodeToString([]byte("not-pkcs8"))} {
		if _, err := ParseAgentPrivateKey(bad); err == nil {
			t.Errorf("ParseAgentPrivateKey(%q) = nil error, want error", bad)
		}
	}
}

// TestBuildAgentAssertion verifies the wire format and that the signature
// validates against the public key over "<runtime>:<task>:<timestamp>".
func TestBuildAgentAssertion(t *testing.T) {
	pub, encoded := newTestAgentKey(t)
	priv, err := ParseAgentPrivateKey(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	now := time.Unix(1785000000, 0)

	assertion, err := BuildAgentAssertion("agent-rt-123", "task-abc", priv, now)
	if err != nil {
		t.Fatalf("BuildAgentAssertion: %v", err)
	}
	if !strings.HasPrefix(assertion, "AgentAssertion ") {
		t.Fatalf("assertion missing 'AgentAssertion ' prefix: %q", assertion)
	}
	rawJSON, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(assertion, "AgentAssertion "))
	if err != nil {
		t.Fatalf("envelope not base64url: %v", err)
	}
	var env struct {
		RuntimeID string `json:"agent_runtime_id"`
		TaskID    string `json:"task_id"`
		Timestamp string `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(rawJSON, &env); err != nil {
		t.Fatalf("envelope not JSON: %v", err)
	}
	if env.RuntimeID != "agent-rt-123" || env.TaskID != "task-abc" {
		t.Errorf("envelope ids = %q/%q, want agent-rt-123/task-abc", env.RuntimeID, env.TaskID)
	}
	if env.Timestamp != now.UTC().Format(time.RFC3339) {
		t.Errorf("timestamp = %q, want %q", env.Timestamp, now.UTC().Format(time.RFC3339))
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatalf("signature not base64: %v", err)
	}
	msg := []byte("agent-rt-123:task-abc:" + env.Timestamp)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature does not verify against the public key over runtime:task:timestamp")
	}

	// Missing runtime/task must error, not sign.
	if _, err := BuildAgentAssertion("", "task-abc", priv, now); err == nil {
		t.Error("BuildAgentAssertion(empty runtime) = nil error, want error")
	}
}

func TestIsAgentIdentityMetadata(t *testing.T) {
	if !IsAgentIdentityMetadata(map[string]any{"auth_mode": "agentIdentity"}) {
		t.Error("agentIdentity auth_mode not detected")
	}
	if IsAgentIdentityMetadata(map[string]any{"auth_mode": "oauth"}) {
		t.Error("oauth wrongly detected as agent identity")
	}
	if IsAgentIdentityMetadata(nil) {
		t.Error("nil metadata detected as agent identity")
	}
}

func TestAgentAssertionFromMetadata(t *testing.T) {
	pub, encoded := newTestAgentKey(t)
	meta := map[string]any{
		"auth_mode":         "agentIdentity",
		"agent_private_key": encoded,
		"agent_runtime_id":  "agent-rt-xyz",
		"task_id":           "task-xyz",
	}
	now := time.Unix(1785000123, 0)
	assertion, err := AgentAssertionFromMetadata(meta, now)
	if err != nil {
		t.Fatalf("AgentAssertionFromMetadata: %v", err)
	}
	rawJSON, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(assertion, "AgentAssertion "))
	var env struct {
		RuntimeID, TaskID, Timestamp, Signature string
	}
	_ = json.Unmarshal(rawJSON, &struct {
		RuntimeID *string `json:"agent_runtime_id"`
		TaskID    *string `json:"task_id"`
		Timestamp *string `json:"timestamp"`
		Signature *string `json:"signature"`
	}{&env.RuntimeID, &env.TaskID, &env.Timestamp, &env.Signature})
	sig, _ := base64.StdEncoding.DecodeString(env.Signature)
	if !ed25519.Verify(pub, []byte("agent-rt-xyz:task-xyz:"+env.Timestamp), sig) {
		t.Error("AgentAssertionFromMetadata signature does not verify")
	}
}
