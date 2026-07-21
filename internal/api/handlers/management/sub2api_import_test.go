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
	if isSub2apiExport([]byte(`{"type":"codex","access_token":"x"}`)) {
		t.Error("plain codex file wrongly detected as sub2api export")
	}
	if isSub2apiExport([]byte(`not json`)) {
		t.Error("non-JSON detected as sub2api export")
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
