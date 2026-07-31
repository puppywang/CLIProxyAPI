package management

import (
	"encoding/json"
	"testing"

	xaiauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/xai"
)

// grok2apiTestExport mirrors a real grok2api "export selected accounts" file:
// bare accounts array, flat tokens, RFC3339-nano expires_at, empty sub with the
// identity in user_id.
const grok2apiTestExport = `{
  "accounts": [
    {
      "provider": "grok_build",
      "name": "allisongriselda7@hotmail.com",
      "client_id": "b1a00492-073a-47ea-816f-4c329264a828",
      "access_token": "at-value",
      "refresh_token": "rt-value",
      "id_token": "",
      "token_type": "Bearer",
      "scope": "",
      "expires_at": "2026-07-31T21:29:51.313962207Z",
      "expires_in": 0,
      "email": "allisongriselda7@hotmail.com",
      "sub": "",
      "user_id": "7bfcb671-e3e6-47c5-a0d5-22a5fd9b2c61",
      "principal_id": "",
      "team_id": "a7793e18-9847-4fc3-a6aa-b15466ca8753"
    }
  ]
}`

func TestIsGrok2apiExport(t *testing.T) {
	if !isGrok2apiExport([]byte(grok2apiTestExport)) {
		t.Error("grok2api export not detected")
	}
	if !isGrok2apiExport([]byte(`{"type":"grok2api-data","accounts":[]}`)) {
		t.Error("explicitly typed grok2api export not detected")
	}
	if isGrok2apiExport([]byte(`{"type":"xai","access_token":"x"}`)) {
		t.Error("plain xai auth file wrongly detected as grok2api export")
	}
	if isGrok2apiExport([]byte(`{"accounts":[{"provider":"grok_web","cookie":"sso=x"}]}`)) {
		t.Error("cookie-only grok account wrongly detected as importable export")
	}
	if isGrok2apiExport([]byte(`{"accounts":[{"provider":"grok_build"}]}`)) {
		t.Error("token-less account wrongly detected as grok2api export")
	}
	if isGrok2apiExport([]byte(`not json`)) {
		t.Error("non-JSON detected as grok2api export")
	}
	if isGrok2apiExport([]byte(`{"foo":1}`)) {
		t.Error("unrelated JSON detected as grok2api export")
	}
}

// TestGrok2apiAndSub2apiDetectionAreDisjoint guards the shared writeAuthFile
// dispatch: each export format must be claimed by exactly one converter.
func TestGrok2apiAndSub2apiDetectionAreDisjoint(t *testing.T) {
	sub2api := `{"exported_at":"2026-07-27T09:21:09+00:00","proxies":[],"accounts":[{"name":"a","platform":"openai","type":"oauth","credentials":{"access_token":"x","refresh_token":"y"}}]}`
	if isGrok2apiExport([]byte(sub2api)) {
		t.Error("sub2api export wrongly detected as grok2api")
	}
	if isSub2apiExport([]byte(grok2apiTestExport)) {
		t.Error("grok2api export wrongly detected as sub2api")
	}
}

func TestConvertGrok2apiExport_GrokBuild(t *testing.T) {
	files, skips, err := convertGrok2apiExport([]byte(grok2apiTestExport))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("skips = %#v, want none", skips)
	}
	if len(files) != 1 {
		t.Fatalf("files = %d, want 1", len(files))
	}
	if files[0].Name != "xai-allisongriselda7@hotmail.com.json" {
		t.Errorf("name = %q, want xai-allisongriselda7@hotmail.com.json", files[0].Name)
	}
	var out map[string]any
	if err := json.Unmarshal(files[0].Data, &out); err != nil {
		t.Fatalf("converted file not JSON: %v", err)
	}
	for k, want := range map[string]string{
		"type":          "xai",
		"access_token":  "at-value",
		"refresh_token": "rt-value",
		"auth_kind":     "oauth",
		"base_url":      xaiauth.DefaultAPIBaseURL,
		"email":         "allisongriselda7@hotmail.com",
		"sub":           "7bfcb671-e3e6-47c5-a0d5-22a5fd9b2c61", // falls back to user_id
		"team_id":       "a7793e18-9847-4fc3-a6aa-b15466ca8753",
		"token_type":    "Bearer",
		"expired":       "2026-07-31T21:29:51Z", // nanos normalized away
	} {
		if got, _ := out[k].(string); got != want {
			t.Errorf("converted[%q] = %q, want %q", k, got, want)
		}
	}
	// Grok Build is the OAuth default; the file must not pin using_api.
	if _, ok := out["using_api"]; ok {
		t.Errorf("grok_build account set using_api = %v, want unset", out["using_api"])
	}
	// Empty optional fields are omitted rather than written blank.
	for _, k := range []string{"id_token", "expires_in"} {
		if _, ok := out[k]; ok {
			t.Errorf("empty %q was written: %v", k, out[k])
		}
	}
}

func TestConvertGrok2apiExport_APIFlavourAndSkips(t *testing.T) {
	export := `{
      "accounts": [
        {"provider":"grok_api","email":"api@x.com","access_token":"at","refresh_token":"rt","expires_at":1786007956},
        {"provider":"grok_web","email":"cookie@x.com","access_token":"at"},
        {"provider":"grok_build","email":"empty@x.com"},
        {"provider":"grok_build","email":"foreign@x.com","access_token":"at","client_id":"deadbeef-0000-0000-0000-000000000000"}
      ]
    }`
	files, skips, err := convertGrok2apiExport([]byte(export))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %d, want 1", len(files))
	}
	if len(skips) != 3 {
		t.Fatalf("skips = %#v, want 3 (cookie provider + token-less + foreign client)", skips)
	}
	var out map[string]any
	if err := json.Unmarshal(files[0].Data, &out); err != nil {
		t.Fatalf("converted file not JSON: %v", err)
	}
	if usingAPI, _ := out["using_api"].(bool); !usingAPI {
		t.Errorf("grok_api account using_api = %v, want true", out["using_api"])
	}
	if got, _ := out["expired"].(string); got != "2026-08-06T09:19:16Z" { // 1786007956 UTC
		t.Errorf("expired = %q, want 2026-08-06T09:19:16Z", got)
	}
}

// TestConvertGrok2apiExport_DuplicateEmails ensures two accounts that sanitize
// to the same filename do not overwrite each other within one import.
func TestConvertGrok2apiExport_DuplicateEmails(t *testing.T) {
	export := `{
      "accounts": [
        {"provider":"grok_build","email":"dup@x.com","refresh_token":"rt1"},
        {"provider":"grok_build","email":"dup@x.com","refresh_token":"rt2"}
      ]
    }`
	files, _, err := convertGrok2apiExport([]byte(export))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d, want 2", len(files))
	}
	if files[0].Name == files[1].Name {
		t.Errorf("duplicate emails produced the same filename %q", files[0].Name)
	}
}

func TestGrok2apiUsingAPI(t *testing.T) {
	cases := []struct {
		provider string
		usingAPI bool
		ok       bool
	}{
		{"grok_build", false, true},
		{"grok-build", false, true},
		{"GROK_BUILD", false, true},
		{"xai", false, true},
		{"grok_api", true, true},
		{"x.ai_api", true, true},
		{"grok_web", false, false},
		{"", false, false},
	}
	for _, tc := range cases {
		usingAPI, ok := grok2apiUsingAPI(tc.provider)
		if usingAPI != tc.usingAPI || ok != tc.ok {
			t.Errorf("grok2apiUsingAPI(%q) = (%v, %v), want (%v, %v)", tc.provider, usingAPI, ok, tc.usingAPI, tc.ok)
		}
	}
}
