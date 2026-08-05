package codex

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestIsTaskInvalidResponse(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{401, `{"detail":{"code":"invalid_task_id"}}`, true},
		{401, `{"detail":{"code":"task_expired"}}`, true},
		{401, `{"error":"invalid_task_id"}`, true},
		{401, `task not found`, true},
		{401, `{"detail":"Could not parse your authentication token."}`, false}, // real auth failure, not task
		{403, `{"detail":{"code":"invalid_task_id"}}`, false},                   // wrong status
		{200, `ok`, false},
	}
	for i, c := range cases {
		if got := IsTaskInvalidResponse(c.status, []byte(c.body)); got != c.want {
			t.Errorf("case %d: IsTaskInvalidResponse(%d,%q)=%v, want %v", i, c.status, c.body, got, c.want)
		}
	}
}

func TestRecoveredTaskSupersedesMetadata(t *testing.T) {
	key, err := GenerateAgentKey()
	if err != nil {
		t.Fatalf("GenerateAgentKey: %v", err)
	}
	const runtimeID = "agent-recover-test-1"
	meta := map[string]any{
		"agent_runtime_id":  runtimeID,
		"task_id":           "task-stale",
		"agent_private_key": key.PrivateKeyPKCS8Base64,
	}
	// Before recovery, the effective task id is the stored one.
	if got := CurrentTaskID(meta); got != "task-stale" {
		t.Fatalf("CurrentTaskID before recovery = %q, want task-stale", got)
	}
	// After recovery, the cached id supersedes the (stale) metadata id.
	SetRecoveredTaskID(runtimeID, "task-fresh")
	if got := CurrentTaskID(meta); got != "task-fresh" {
		t.Fatalf("CurrentTaskID after recovery = %q, want task-fresh", got)
	}
	// The assertion must sign with the recovered task id, not the stale one.
	assertion, err := AgentAssertionFromMetadata(meta, time.Now())
	if err != nil {
		t.Fatalf("AgentAssertionFromMetadata: %v", err)
	}
	const prefix = "AgentAssertion "
	if len(assertion) <= len(prefix) {
		t.Fatalf("assertion too short: %q", assertion)
	}
	raw, err := base64.RawURLEncoding.DecodeString(assertion[len(prefix):])
	if err != nil {
		t.Fatalf("decode assertion: %v", err)
	}
	var env struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.TaskID != "task-fresh" {
		t.Errorf("assertion task_id = %q, want task-fresh", env.TaskID)
	}
}
