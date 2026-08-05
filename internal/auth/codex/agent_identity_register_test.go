package codex

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/ssh"
)

// TestEncodeSSHEd25519PublicKeyMatchesXCryptoSSH cross-checks our hand-rolled
// SSH encoder against the canonical golang.org/x/crypto/ssh output, so the
// agent_public_key we submit is byte-identical to what OpenAI's client sends.
func TestEncodeSSHEd25519PublicKeyMatchesXCryptoSSH(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	got := EncodeSSHEd25519PublicKey(pub)
	if got != want {
		t.Errorf("SSH encoding mismatch\n got=%q\nwant=%q", got, want)
	}
}

// TestGenerateAgentKeyRoundTrips confirms the generated private key parses back
// via the storage-format parser and the public key is well-formed SSH.
func TestGenerateAgentKeyRoundTrips(t *testing.T) {
	key, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("GenerateAgentKey: %v", err)
	}
	priv, err := ParseAgentPrivateKey(key.PrivateKeyPKCS8Base64)
	if err != nil {
		t.Fatalf("ParseAgentPrivateKey: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("parsed key size = %d", len(priv))
	}
	if !strings.HasPrefix(key.PublicKeySSH, "ssh-ed25519 ") {
		t.Errorf("public key not ssh-ed25519: %q", key.PublicKeySSH)
	}
	// The encoded public key must match the one derived from the private key.
	want := EncodeSSHEd25519PublicKey(priv.Public().(ed25519.PublicKey))
	if key.PublicKeySSH != want {
		t.Errorf("public key does not match private key")
	}
}

// TestDecryptTaskIDRoundTrip seals a task id to the agent's derived X25519
// public key (as OpenAI does for encrypted_task_id) and confirms DecryptTaskID
// recovers it — exercising the ed25519->X25519 conversion and anonymous box.
func TestDecryptTaskIDRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, curvePublic, err := curve25519KeypairFromEd25519(priv)
	if err != nil {
		t.Fatalf("derive curve key: %v", err)
	}
	const want = "task-abc-123"
	sealed, err := box.SealAnonymous(nil, []byte(want), &curvePublic, rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := DecryptTaskID(priv, base64.StdEncoding.EncodeToString(sealed))
	if err != nil {
		t.Fatalf("DecryptTaskID: %v", err)
	}
	if got != want {
		t.Errorf("decrypted task id = %q, want %q", got, want)
	}
}

// TestDecodeAccessTokenClaims lifts the namespaced account/profile claims from
// an unsigned JWT payload.
func TestDecodeAccessTokenClaims(t *testing.T) {
	payload := map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id":         "acc-42",
			"chatgpt_plan_type":          "plus",
			"chatgpt_account_is_fedramp": false,
		},
		"https://api.openai.com/profile": map[string]any{
			"email": "user@example.com",
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jwt := "h." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
	claims, err := DecodeAccessTokenClaims(jwt)
	if err != nil {
		t.Fatalf("DecodeAccessTokenClaims: %v", err)
	}
	if claims.AccountID != "acc-42" {
		t.Errorf("account_id = %q, want acc-42", claims.AccountID)
	}
	if claims.PlanType != "plus" {
		t.Errorf("plan_type = %q, want plus", claims.PlanType)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", claims.Email)
	}
	if claims.Fedramp {
		t.Errorf("fedramp should be false")
	}
	if _, err := DecodeAccessTokenClaims("not-a-jwt"); err == nil {
		t.Errorf("expected error for non-JWT input")
	}
}
