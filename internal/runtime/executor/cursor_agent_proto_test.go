package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func TestCursorEncodeJSONValueRoundTrip(t *testing.T) {
	raw := json.RawMessage(`{"a":1,"b":"two","c":[true,null,3.5],"d":{"e":false}}`)
	decoded := cursorDecodeJSONValue(cursorEncodeJSONValue(raw, 0), 0)
	if gjson.GetBytes(decoded, "b").String() != "two" {
		t.Fatalf("%s", decoded)
	}
	if gjson.GetBytes(decoded, "c.0").Bool() != true {
		t.Fatalf("%s", decoded)
	}
	if gjson.GetBytes(decoded, "d.e").Bool() != false {
		t.Fatalf("%s", decoded)
	}
}

func TestCursorExtractAnswerAndToolCall(t *testing.T) {
	leaf := pbFieldStr(1, "OK")
	mid := pbFieldLD(1, leaf)
	top := pbFieldLD(1, mid)
	if got := cursorExtractAnswerText(top); got != "OK" {
		t.Fatalf("text = %q", got)
	}

	mcp := pbFieldStr(5, "read_file")
	entry := pbFieldStr(1, "path")
	entry = append(entry, pbFieldLD(2, cursorEncodeJSONValue(json.RawMessage(`"a.go"`), 0))...)
	mcp = append(mcp, pbFieldLD(2, entry)...)
	mcp = append(mcp, pbFieldStr(3, "call_abc")...)
	exec := pbFieldVarint(1, 7)
	exec = append(exec, pbFieldStr(15, "exec-1")...)
	exec = append(exec, pbFieldLD(11, mcp)...)
	payload := pbFieldLD(2, exec)
	got, args, ok := cursorExtractMcpToolCall(payload)
	if !ok || got.Name != "read_file" || got.CallID != "call_abc" || got.ID != 7 || got.ExecID != "exec-1" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if !strings.Contains(args, "a.go") {
		t.Fatalf("args = %s", args)
	}
}

func TestCursorBuildRunFramesContainPromptTools(t *testing.T) {
	frames := cursorBuildRunFrames("PROMPT_MARKER", "grok-4.6", `C:\workspace`, nil, []cursorClientTool{
		{Name: "read_file", Description: "Read a file", Parameters: json.RawMessage(`{"type":"object"}`)},
	})
	if len(frames) != 1 {
		t.Fatalf("frames = %d", len(frames))
	}
	frame, err := cursorDecodeConnectFrame(bytes.NewReader(frames[0]))
	if err != nil {
		t.Fatal(err)
	}
	run := pbFirstLD(pbIter(frame.Payload), 1)
	if run == nil {
		t.Fatalf("missing AgentClientMessage.run_request: %x", frame.Payload)
	}
	runFields := pbIter(run)
	if pbFirstLD(runFields, 3) == nil {
		t.Fatalf("missing AgentRunRequest.model_details: %x", run)
	}
	if pbFirstStr(runFields, 25) == "" {
		t.Fatalf("missing AgentRunRequest.run_id: %x", run)
	}
	action := pbFirstLD(runFields, 2)
	userAction := pbFirstLD(pbIter(action), 1)
	userMessage := pbFirstLD(pbIter(userAction), 1)
	if pbFirstStr(pbIter(userMessage), 1) != "PROMPT_MARKER" {
		t.Fatalf("prompt = %q", pbFirstStr(pbIter(userMessage), 1))
	}
	mcpTools := pbFirstLD(runFields, 4)
	descriptor := pbFirstLD(pbIter(mcpTools), 1)
	descriptorFields := pbIter(descriptor)
	if pbFirstStr(descriptorFields, 1) != "read_file" || pbFirstStr(descriptorFields, 3) != "Read a file" {
		t.Fatalf("descriptor = %x", descriptor)
	}
	if pbFirstLD(descriptorFields, 4) == nil {
		t.Fatalf("missing descriptor input_schema struct: %x", descriptor)
	}
	if _, ok := pbFirst(descriptorFields, 5); ok {
		t.Fatalf("descriptor unexpectedly uses legacy input_schema_json: %x", descriptor)
	}
	hb := cursorConnectHeartbeatFrame()
	if hb[0] != 0 || len(hb) != 5+2 {
		t.Fatalf("heartbeat frame = %x", hb)
	}
}

func TestCursorAgentServiceURLUsesOfficialDefault(t *testing.T) {
	if got := cursorAgentServiceURL(""); got != "https://api2.cursor.sh"+cursorAgentServicePath {
		t.Fatalf("url = %s", got)
	}
}

func TestCursorAgentEndpointOverrides(t *testing.T) {
	t.Setenv("CURSOR_AGENT_ENDPOINT", "https://env-agent.cursor.sh")
	t.Setenv("CURSOR_AUTH_ENDPOINT", "https://env-auth.cursor.sh")
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"cursor_agent_endpoint": "https://auth-agent.cursor.sh/",
		"cursor_auth_endpoint":  "https://auth-auth.cursor.sh/",
	}}
	exec := NewCursorExecutor(nil)
	if got := cursorAgentEndpoint(exec, auth); got != "https://auth-agent.cursor.sh/" {
		t.Fatalf("auth agent endpoint = %q", got)
	}
	if got := cursorAuthExchangeEndpoint(exec, auth); got != "https://auth-auth.cursor.sh/" {
		t.Fatalf("auth exchange endpoint = %q", got)
	}
	exec.agentEndpoint = "https://field-agent.cursor.sh"
	exec.authEndpoint = "https://field-auth.cursor.sh"
	if got := cursorAgentEndpoint(exec, auth); got != "https://field-agent.cursor.sh" {
		t.Fatalf("executor agent endpoint = %q", got)
	}
	if got := cursorAuthExchangeEndpoint(exec, auth); got != "https://field-auth.cursor.sh" {
		t.Fatalf("executor auth endpoint = %q", got)
	}
	if got := cursorAgentEndpoint(nil, nil); got != "https://env-agent.cursor.sh" {
		t.Fatalf("environment agent endpoint = %q", got)
	}
	if got := cursorAuthExchangeEndpoint(nil, nil); got != "https://env-auth.cursor.sh" {
		t.Fatalf("environment auth endpoint = %q", got)
	}
}

func TestCursorEncodeMcpToolResult(t *testing.T) {
	raw := cursorEncodeMcpToolResult(cursorBidiExec{ID: 3, ExecID: "e1", Name: "read_file"}, "package main")
	if !bytes.Contains(raw, []byte("package main")) || !bytes.Contains(raw, []byte("e1")) {
		t.Fatalf("result = %q", raw)
	}
}

func TestCursorExtractAndEncodeLocalExecShell(t *testing.T) {
	args := pbFieldStr(1, "echo hello")
	args = append(args, pbFieldStr(2, ".")...)
	args = append(args, pbFieldVarint(3, 5000)...)
	serverExec := pbFieldVarint(1, 17)
	serverExec = append(serverExec, pbFieldStr(15, "shell-exec")...)
	serverExec = append(serverExec, pbFieldLD(2, args)...)

	got, ok := cursorExtractLocalExec(pbFieldLD(2, serverExec))
	if !ok || got.Kind != cursorLocalExecShell || got.ID != 17 || got.ExecID != "shell-exec" || got.Command != "echo hello" {
		t.Fatalf("exec = %+v, ok=%v", got, ok)
	}

	result := cursorEncodeLocalExecResult(context.Background(), t.TempDir(), got)
	client := pbFirstLD(pbIter(result), 2)
	if client == nil {
		t.Fatalf("missing ExecClientMessage: %x", result)
	}
	clientFields := pbIter(client)
	if gotID, ok := cursorFirstVarint(clientFields, 1); !ok || gotID != 17 {
		t.Fatalf("id = %d, ok=%v", gotID, ok)
	}
	if pbFirstStr(clientFields, 15) != "shell-exec" {
		t.Fatalf("exec id = %q", pbFirstStr(clientFields, 15))
	}
	shellResult := pbFirstLD(clientFields, 2)
	if shellResult == nil || pbFirstLD(pbIter(shellResult), 1) == nil {
		t.Fatalf("missing shell success: %x", client)
	}
}

func TestCursorExtractEmptyLocalExecMessage(t *testing.T) {
	serverExec := pbFieldVarint(1, 18)
	serverExec = append(serverExec, pbFieldLD(2, nil)...)
	got, ok := cursorExtractLocalExec(pbFieldLD(2, serverExec))
	if !ok || got.Kind != cursorLocalExecShell || got.ID != 18 {
		t.Fatalf("exec = %+v, ok=%v", got, ok)
	}
}

func TestCursorLocalExecReadRangeIsLineBased(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "lines.txt"), []byte("one\ntwo\nthree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	request := cursorLocalExecRequest{Kind: cursorLocalExecRead, Path: "lines.txt", ReadOffset: 1, ReadLimit: 1, ReadLimitSet: true}
	result := cursorEncodeLocalExecResult(context.Background(), root, request)
	client := pbFirstLD(pbIter(result), 2)
	readResult := pbFirstLD(pbIter(client), 7)
	success := pbFirstLD(pbIter(readResult), 1)
	if got := pbFirstStr(pbIter(success), 2); got != "two\n" {
		t.Fatalf("content = %q", got)
	}
	got, ok := cursorFirstVarint(pbIter(success), 3)
	if !ok || got != 3 {
		t.Fatalf("total lines = %d ok=%v", got, ok)
	}
}

func TestCursorWorkspaceEnvironmentIsAuthoritative(t *testing.T) {
	configured := t.TempDir()
	t.Setenv("CURSOR_AGENT_WORKSPACE", configured)
	if got := cursorDefaultWorkspace(filepath.Join(t.TempDir(), "untrusted")); got != configured {
		t.Fatalf("workspace = %q, want %q", got, configured)
	}
}

func TestCursorBackgroundShellIsRejected(t *testing.T) {
	root := t.TempDir()
	request := cursorLocalExecRequest{Kind: cursorLocalExecShell, Command: "echo no", IsBackground: true}
	result := cursorEncodeLocalExecResult(context.Background(), root, request)
	client := pbFirstLD(pbIter(result), 2)
	shellResult := pbFirstLD(pbIter(client), 2)
	if pbFirstLD(pbIter(shellResult), 4) == nil {
		t.Fatalf("expected rejected shell: %x", shellResult)
	}
}

func TestCursorLocalExecWorkspaceBoundary(t *testing.T) {
	root := t.TempDir()
	request := cursorLocalExecRequest{Kind: cursorLocalExecWrite, Path: "../outside.txt", FileText: "blocked"}
	result := cursorEncodeLocalExecResult(context.Background(), root, request)
	writeResult := pbFirstLD(pbIter(pbFirstLD(pbIter(result), 2)), 3)
	if writeResult == nil {
		t.Fatalf("expected write result: %x", result)
	}
	if pbFirstLD(pbIter(writeResult), 6) == nil {
		t.Fatalf("expected rejected write: %x", writeResult)
	}
}

func TestCursorLocalExecReadWriteDelete(t *testing.T) {
	root := t.TempDir()
	write := cursorLocalExecRequest{Kind: cursorLocalExecWrite, Path: "note.txt", FileText: "one\ntwo\n", ReturnContent: true}
	writeResult := cursorEncodeLocalExecResult(context.Background(), root, write)
	writeEnvelope := pbFirstLD(pbIter(pbFirstLD(pbIter(writeResult), 2)), 3)
	if writeEnvelope == nil || pbFirstLD(pbIter(writeEnvelope), 1) == nil {
		t.Fatalf("write failed: %x", writeResult)
	}

	read := cursorLocalExecRequest{Kind: cursorLocalExecRead, Path: "note.txt"}
	readResult := cursorEncodeLocalExecResult(context.Background(), root, read)
	readEnvelope := pbFirstLD(pbIter(pbFirstLD(pbIter(readResult), 2)), 7)
	readSuccess := pbFirstLD(pbIter(readEnvelope), 1)
	if readSuccess == nil || pbFirstStr(pbIter(readSuccess), 2) != "one\ntwo\n" {
		t.Fatalf("read failed: %x", readResult)
	}

	delete := cursorLocalExecRequest{Kind: cursorLocalExecDelete, Path: "note.txt"}
	deleteResult := cursorEncodeLocalExecResult(context.Background(), root, delete)
	deleteEnvelope := pbFirstLD(pbIter(pbFirstLD(pbIter(deleteResult), 2)), 4)
	deleteSuccess := pbFirstLD(pbIter(deleteEnvelope), 1)
	if deleteSuccess == nil {
		t.Fatalf("delete failed: %x", deleteResult)
	}
	deleteFields := pbIter(deleteSuccess)
	if pbFirstStr(deleteFields, 2) == "one\ntwo\n" {
		t.Fatalf("deleted_file must be the deleted path, not previous content: %x", deleteSuccess)
	}
	if pbFirstStr(deleteFields, 4) != "one\ntwo\n" {
		t.Fatalf("prev_content = %q", pbFirstStr(deleteFields, 4))
	}
}

func TestCursorLocalExecGrepUsesOfficialNestedResults(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("before\nneedle\nafter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	request := cursorLocalExecRequest{
		Kind:          cursorLocalExecGrep,
		Pattern:       "needle",
		Path:          ".",
		OutputMode:    "content",
		ContextBefore: 1,
		ContextAfter:  1,
	}
	result := cursorEncodeLocalExecResult(context.Background(), root, request)
	client := pbFirstLD(pbIter(result), 2)
	grepResult := pbFirstLD(pbIter(client), 5)
	success := pbFirstLD(pbIter(grepResult), 1)
	entry := pbFirstLD(pbIter(success), 4)
	union := pbFirstLD(pbIter(entry), 2)
	content := pbFirstLD(pbIter(union), 3)
	fileMatch := pbFirstLD(pbIter(content), 1)
	if pbFirstStr(pbIter(fileMatch), 1) != "a.txt" {
		t.Fatalf("file = %q", pbFirstStr(pbIter(fileMatch), 1))
	}
	matches := make([]pbField, 0)
	for _, field := range pbIter(fileMatch) {
		if field.Num == 2 {
			matches = append(matches, field)
		}
	}
	if len(matches) != 3 {
		t.Fatalf("matches = %d, want context + hit + context", len(matches))
	}
	contextField, contextOK := pbFirst(pbIter(matches[0].Data), 4)
	if pbFirstStr(pbIter(matches[1].Data), 2) != "needle" || !contextOK || pbVarintValue(contextField.Data) != 1 {
		t.Fatalf("unexpected grep matches: %x", fileMatch)
	}
}

func TestCursorLocalExecGrepFilesWithMatchesMode(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("needle here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// files_with_matches (official Cursor mode) must produce the files listing,
	// not fall through to the default content mode.
	request := cursorLocalExecRequest{
		Kind:       cursorLocalExecGrep,
		Pattern:    "needle",
		Path:       ".",
		OutputMode: "files_with_matches",
	}
	result := cursorEncodeLocalExecResult(context.Background(), root, request)
	client := pbFirstLD(pbIter(result), 2)
	grepResult := pbFirstLD(pbIter(client), 5)
	success := pbFirstLD(pbIter(grepResult), 1)
	entry := pbFirstLD(pbIter(success), 4)
	union := pbFirstLD(pbIter(entry), 2)
	filesField, ok := pbFirst(pbIter(union), 2)
	if !ok {
		t.Fatalf("files listing missing in files_with_matches mode: %x", union)
	}
	var names []string
	for _, f := range pbIter(filesField.Data) {
		if f.Num == 1 && f.Wire == 2 {
			names = append(names, string(f.Data))
		}
	}
	if len(names) != 1 || names[0] != "a.txt" {
		t.Fatalf("files_with_matches names = %v, want [a.txt]", names)
	}
}

func TestCursorBaseModelExtraHigh(t *testing.T) {
	cases := map[string]string{
		"cursor-gpt-5.5":                 "gpt-5.5",
		"cursor-gpt-5.5-fast":            "gpt-5.5",
		"cursor-gpt-5.5-extra-high":      "gpt-5.5",
		"cursor-gpt-5.5-extra-high-fast": "gpt-5.5",
		"cursor-gpt-5.4-extra-high":      "gpt-5.4",
		"cursor-gpt-5.6-sol-xhigh-fast":  "gpt-5.6-sol",
	}
	for in, want := range cases {
		if got := cursorBaseModel(in); got != want {
			t.Errorf("cursorBaseModel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCursorBidiFallbackOnAuthFailure(t *testing.T) {
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	t.Cleanup(authSrv.Close)
	exec := NewCursorExecutor(nil)
	exec.authEndpoint = authSrv.URL
	exec.agentEndpoint = "http://127.0.0.1:1"
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "crsr_test"}}
	_, err := dialBidiCursorAgent(context.Background(), exec, auth, cursorAgentStart{Prompt: "hi", BaseModel: "grok-4.6"})
	if err == nil {
		t.Fatal("expected auth failure")
	}
}
