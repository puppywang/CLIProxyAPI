package management

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIsSub2apiExport(t *testing.T) {
	if !isSub2apiExport([]byte(`{"type":"sub2api-data","accounts":[]}`)) {
		t.Error("sub2api-data not detected")
	}
	// Current sub2api OAuth export omits type and uses exported_at + accounts[].
	if !isSub2apiExport([]byte(`{"exported_at":"2026-07-27T09:21:09+00:00","proxies":[],"accounts":[{"name":"a","platform":"openai","type":"oauth","credentials":{"access_token":"x","refresh_token":"y"}}]}`)) {
		t.Error("current sub2api export (no type field) not detected")
	}
	// accounts[] with platform+credentials is enough even without exported_at.
	if !isSub2apiExport([]byte(`{"accounts":[{"name":"a","platform":"openai","credentials":{"access_token":"x"}}]}`)) {
		t.Error("accounts-shaped export not detected")
	}
	if isSub2apiExport([]byte(`{"type":"codex","access_token":"x"}`)) {
		t.Error("plain codex file wrongly detected as sub2api export")
	}
	if isSub2apiExport([]byte(`{"type":"claude","access_token":"x","accounts":[]}`)) {
		t.Error("plain claude file with empty accounts wrongly detected")
	}
	if isSub2apiExport([]byte(`not json`)) {
		t.Error("non-JSON detected as sub2api export")
	}
	if isSub2apiExport([]byte(`{"foo":1}`)) {
		t.Error("unrelated JSON detected as sub2api export")
	}
}

func TestConvertSub2apiExport_AgentIdentityAndSkips(t *testing.T) {
	export := `{
      "type": "sub2api-data",
      "accounts": [
        {"name":"wilber@x.com","platform":"openai","type":"oauth","credentials":{
          "auth_mode":"agentIdentity","plan_type":"k12",
          "account_id":"acc-1","chatgpt_account_id":"cg-1","chatgpt_user_id":"user-1","workspace_id":"ws-1",
          "agent_private_key":"MC4CAQ-fake","agent_runtime_id":"agent-rt","task_id":"task-1",
          "id_token":"eyJ-fake","email":"wilber@x.com"}},
        {"name":"claude-acc","platform":"claude","type":"oauth","credentials":{"access_token":"x"}},
        {"name":"bad-openai","platform":"openai","type":"oauth","credentials":{"auth_mode":"agentIdentity"}}
      ]
    }`
	files, skips, err := convertSub2apiExport([]byte(export))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %d, want 1", len(files))
	}
	if len(skips) != 2 {
		t.Fatalf("skips = %d, want 2 (claude platform + incomplete openai)", len(skips))
	}
	f := files[0]
	if f.Name != "codex-wilber@x.com-k12.json" {
		t.Errorf("name = %q, want codex-wilber@x.com-k12.json", f.Name)
	}
	var out map[string]any
	if err := json.Unmarshal(f.Data, &out); err != nil {
		t.Fatalf("converted file not JSON: %v", err)
	}
	for k, want := range map[string]string{
		"type": "codex", "auth_mode": "agentIdentity", "plan_type": "k12",
		"account_id": "cg-1", "chatgpt_account_id": "cg-1",
		"agent_private_key": "MC4CAQ-fake", "agent_runtime_id": "agent-rt", "task_id": "task-1",
	} {
		if got, _ := out[k].(string); got != want {
			t.Errorf("converted[%q] = %q, want %q", k, got, want)
		}
	}
	// non-agentIdentity openai (with a token) must convert as standard oauth.
	oauthExport := `{"type":"sub2api-data","accounts":[{"name":"o@x.com","platform":"openai","type":"oauth","credentials":{"access_token":"at","refresh_token":"rt","account_id":"a1","email":"o@x.com"}}]}`
	files2, _, err := convertSub2apiExport([]byte(oauthExport))
	if err != nil || len(files2) != 1 {
		t.Fatalf("oauth convert: files=%d err=%v", len(files2), err)
	}
	if !strings.Contains(string(files2[0].Data), `"access_token": "at"`) {
		t.Errorf("oauth file missing access_token: %s", files2[0].Data)
	}
}

// TestConvertSub2apiExport_CurrentOAuthShape covers the 2026-07 sub2api export
// format that omits type:"sub2api-data", uses exported_at, and stores token
// expiry as a unix-seconds expires_at number.
func TestConvertSub2apiExport_CurrentOAuthShape(t *testing.T) {
	export := `{
      "exported_at": "2026-07-27T09:21:09+00:00",
      "proxies": [],
      "accounts": [
        {
          "name": "bournealvin27093+a2",
          "notes": "Sub2API OAuth export only; account was not imported automatically",
          "platform": "openai",
          "type": "oauth",
          "credentials": {
            "access_token": "at-value",
            "refresh_token": "rt-value",
            "id_token": "id-value",
            "expires_at": 1786007956,
            "chatgpt_account_id": "4f0058c4-92b7-40df-8d5b-76bf57e976f8",
            "chatgpt_user_id": "user-Ze5rrMwxNNrxFN5hDbZEo6Xf",
            "organization_id": "org-KlkHefYprbywgMvkbQEkfTcB",
            "plan_type": "team",
            "email": "bournealvin27093+a2@gmail.com"
          },
          "extra": {
            "email": "bournealvin27093+a2@gmail.com",
            "auth_provider": "openai",
            "import_source": "oauth_export_only"
          }
        }
      ]
    }`
	if !isSub2apiExport([]byte(export)) {
		t.Fatal("current export shape not detected as sub2api")
	}
	files, skips, err := convertSub2apiExport([]byte(export))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("skips = %#v, want none", skips)
	}
	if len(files) != 1 {
		t.Fatalf("files = %d, want 1", len(files))
	}
	if files[0].Name != "codex-bournealvin27093_a2@gmail.com-team.json" {
		// '+' in email is sanitized to '_'
		t.Errorf("name = %q, want codex-bournealvin27093_a2@gmail.com-team.json", files[0].Name)
	}
	var out map[string]any
	if err := json.Unmarshal(files[0].Data, &out); err != nil {
		t.Fatalf("converted file not JSON: %v", err)
	}
	for k, want := range map[string]string{
		"type":               "codex",
		"email":              "bournealvin27093+a2@gmail.com",
		"access_token":       "at-value",
		"refresh_token":      "rt-value",
		"id_token":           "id-value",
		"account_id":         "4f0058c4-92b7-40df-8d5b-76bf57e976f8",
		"chatgpt_account_id": "4f0058c4-92b7-40df-8d5b-76bf57e976f8",
		"chatgpt_user_id":    "user-Ze5rrMwxNNrxFN5hDbZEo6Xf",
		"plan_type":          "team",
		"expired":            "2026-08-06T09:19:16Z", // 1786007956 UTC
	} {
		if got, _ := out[k].(string); got != want {
			t.Errorf("converted[%q] = %q, want %q", k, got, want)
		}
	}
}
