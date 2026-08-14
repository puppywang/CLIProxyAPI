package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestCursorClientToolsAndResults(t *testing.T) {
	payload := []byte(`{
		"messages":[
			{"role":"user","content":"read it"},
			{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.go\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"package main"}
		],
		"tools":[{"type":"function","function":{"name":"read_file","description":"Read a file","parameters":{"type":"object"}}}]
	}`)
	tools := cursorClientTools(payload)
	if len(tools) != 1 || tools[0].Name != "read_file" {
		t.Fatalf("tools = %+v", tools)
	}
	results := cursorToolResults(payload)
	if len(results) != 1 || results[0].CallID != "call_1" || results[0].Name != "read_file" || !strings.Contains(results[0].Content, "package main") {
		t.Fatalf("results = %+v", results)
	}
	if !cursorShouldUseAgentLoop(payload) {
		t.Fatal("expected agent loop")
	}
}

func TestCursorAgentPayloadsTranslateResponsesToolContinuation(t *testing.T) {
	raw := []byte(`{
		"model":"cursor-grok-4.6",
		"instructions":"Use the local tools",
		"input":[
			{"role":"user","content":[{"type":"input_text","text":"read it"}]},
			{"type":"function_call","call_id":"call_1","name":"read_file","arguments":"{\"path\":\"a.go\"}"},
			{"type":"function_call_output","call_id":"call_1","output":"package main"}
		],
		"tools":[{"type":"function","name":"read_file","description":"Read a file","parameters":{"type":"object"}}]
	}`)
	_, translated := cursorAgentPayloads(
		cliproxyexecutor.Request{Model: "cursor-grok-4.6", Payload: raw},
		cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse},
		false,
	)
	if gjson.GetBytes(translated, "messages.#").Int() != 4 {
		t.Fatalf("translated messages = %s", translated)
	}
	results := cursorToolResults(translated)
	if len(results) != 1 || results[0].CallID != "call_1" || results[0].Name != "read_file" || results[0].Content != "package main" {
		t.Fatalf("results = %+v translated=%s", results, translated)
	}
	if len(cursorClientTools(translated)) != 1 {
		t.Fatalf("tools = %s", translated)
	}
	if !strings.Contains(cursorPromptFromPayload(translated), "read it") {
		t.Fatalf("prompt = %q", cursorPromptFromPayload(translated))
	}
}

func TestCursorAgentLoopStreamTranslatesToResponses(t *testing.T) {
	exec := NewCursorExecutor(nil)
	exec.dialAgent = dialLoopbackCursorAgent
	auth := &cliproxyauth.Auth{ID: "cursor-test-responses", Provider: "cursor", Attributes: map[string]string{"api_key": "test"}}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
		Headers:      map[string][]string{"X-Session-ID": {"sess-responses"}},
	}
	payload := []byte(`{"model":"cursor-grok-4.6","instructions":"hello","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}`)
	stream, err := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{Model: "cursor-grok-4.6", Payload: payload}, opts)
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	chunks := drainCursorStream(t, stream)
	joined := strings.Join(chunks, "\n")
	if !strings.Contains(joined, "response.output_text.delta") {
		t.Fatalf("missing Responses text delta: %s", joined)
	}
	if !strings.Contains(joined, "response.completed") {
		t.Fatalf("missing Responses completion: %s", joined)
	}
}

func TestCursorParseToolCallBlocks(t *testing.T) {
	text := "preamble\n" + cursorToolCallMarker + "\n{\"name\":\"grep_search\",\"arguments\":{\"query\":\"foo\"}}\n" + cursorToolCallMarker + "\n"
	remaining, calls, args := cursorParseToolCallBlocks(text)
	if strings.TrimSpace(remaining) != "preamble" {
		t.Fatalf("remaining = %q", remaining)
	}
	if len(calls) != 1 || calls[0].Name != "grep_search" {
		t.Fatalf("calls = %+v", calls)
	}
	if len(args) != 1 || !strings.Contains(args[0], "foo") {
		t.Fatalf("args = %v", args)
	}
}

func TestCursorAgentServiceURL(t *testing.T) {
	if got := cursorAgentServiceURL(""); !strings.HasSuffix(got, cursorAgentServicePath) {
		t.Fatalf("url = %s", got)
	}
}

func TestCursorEncodeConnectFrameRoundTrip(t *testing.T) {
	raw := cursorEncodeConnectFrame(0, []byte("hello"))
	got, err := cursorDecodeConnectFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags != 0 || string(got.Payload) != "hello" {
		t.Fatalf("got %+v", got)
	}
}

func TestCursorAgentLoopStreamToolRoundTrip(t *testing.T) {
	exec := NewCursorExecutor(nil)
	exec.dialAgent = dialLoopbackCursorAgent
	auth := &cliproxyauth.Auth{ID: "cursor-test-auth", Provider: "cursor", Attributes: map[string]string{"api_key": "test"}}
	opts := cliproxyexecutor.Options{SourceFormat: "openai", Headers: map[string][]string{"X-Session-ID": {"sess-loop"}}}

	first := []byte(`{
		"model":"cursor-grok-4.6",
		"messages":[{"role":"user","content":"read the file"}],
		"tools":[{"type":"function","function":{"name":"read_file","parameters":{"type":"object"}}}]
	}`)
	stream, err := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{Model: "cursor-grok-4.6", Payload: first}, opts)
	if err != nil {
		t.Fatalf("first ExecuteStream: %v", err)
	}
	firstChunks := drainCursorStream(t, stream)
	if cursorStreamFinish(firstChunks) != "tool_calls" {
		t.Fatalf("first finish = %q chunks=%v", cursorStreamFinish(firstChunks), firstChunks)
	}
	name, callID := cursorStreamToolCall(firstChunks)
	if name != "read_file" || callID == "" {
		t.Fatalf("missing tool call in %v", firstChunks)
	}

	second := []byte(`{
		"model":"cursor-grok-4.6",
		"messages":[
			{"role":"user","content":"read the file"},
			{"role":"assistant","tool_calls":[{"id":"` + callID + `","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"loopback.txt\"}"}}]},
			{"role":"tool","tool_call_id":"` + callID + `","content":"ok-from-local-tool"}
		],
		"tools":[{"type":"function","function":{"name":"read_file","parameters":{"type":"object"}}}]
	}`)
	stream2, err := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{Model: "cursor-grok-4.6", Payload: second}, opts)
	if err != nil {
		t.Fatalf("second ExecuteStream: %v", err)
	}
	secondChunks := drainCursorStream(t, stream2)
	joined := strings.Join(secondChunks, "\n")
	if !strings.Contains(joined, "ok-from-local-tool") && !strings.Contains(joined, "loopback-tool-ok") {
		t.Fatalf("second body missing tool result echo: %s", joined)
	}
	if cursorStreamFinish(secondChunks) == "tool_calls" {
		t.Fatalf("second turn should finish stop, body=%s", joined)
	}
}

func TestCursorAgentLoopStreamWithoutTools(t *testing.T) {
	exec := NewCursorExecutor(nil)
	exec.dialAgent = dialLoopbackCursorAgent
	auth := &cliproxyauth.Auth{ID: "cursor-test-auth-notools", Provider: "cursor", Attributes: map[string]string{"api_key": "test"}}
	opts := cliproxyexecutor.Options{SourceFormat: "openai", Headers: map[string][]string{"X-Session-ID": {"sess-notools"}}}
	payload := []byte(`{"model":"cursor-grok-4.6","messages":[{"role":"user","content":"hello"}]}`)
	stream, err := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{Model: "cursor-grok-4.6", Payload: payload}, opts)
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	chunks := drainCursorStream(t, stream)
	joined := strings.Join(chunks, "\n")
	if !strings.Contains(joined, "loopback-hello") {
		t.Fatalf("expected agent loop text, got %s", joined)
	}
	if cursorStreamFinish(chunks) == "tool_calls" {
		t.Fatalf("no-tools turn should finish stop, body=%s", joined)
	}
}

func TestCursorAgentLoopNonStreamUsesDirectAgentService(t *testing.T) {
	exec := NewCursorExecutor(nil)
	exec.dialAgent = dialLoopbackCursorAgent
	auth := &cliproxyauth.Auth{ID: "cursor-test-nonstream", Provider: "cursor", Attributes: map[string]string{"api_key": "test"}}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      map[string][]string{"X-Session-ID": {"sess-nonstream"}},
	}
	payload := []byte(`{"model":"cursor-grok-4.6","messages":[{"role":"user","content":"hello"}]}`)
	resp, err := exec.Execute(context.Background(), auth, cliproxyexecutor.Request{Model: "cursor-grok-4.6", Payload: payload}, opts)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := gjson.GetBytes(resp.Payload, "choices.0.message.content").String(); got != "loopback-hello" {
		t.Fatalf("content = %q, response = %s", got, resp.Payload)
	}
}

func TestCursorAgentLoopNonStreamTranslatesToResponses(t *testing.T) {
	exec := NewCursorExecutor(nil)
	exec.dialAgent = dialLoopbackCursorAgent
	auth := &cliproxyauth.Auth{ID: "cursor-test-nonstream-responses", Provider: "cursor", Attributes: map[string]string{"api_key": "test"}}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
		Headers:      map[string][]string{"X-Session-ID": {"sess-nonstream-responses"}},
	}
	payload := []byte(`{"model":"cursor-grok-4.6","instructions":"hello","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}`)
	resp, err := exec.Execute(context.Background(), auth, cliproxyexecutor.Request{Model: "cursor-grok-4.6", Payload: payload}, opts)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := gjson.GetBytes(resp.Payload, "output.0.content.0.text").String(); got != "loopback-hello" {
		t.Fatalf("output text = %q, response = %s", got, resp.Payload)
	}
}

func TestCursorBidiHTTPWireRoundTrip(t *testing.T) {
	var wireErr error
	var wireMu sync.Mutex
	setWireErr := func(err error) {
		wireMu.Lock()
		defer wireMu.Unlock()
		if wireErr == nil {
			wireErr = err
		}
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case cursorAgentAuthExchange:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				setWireErr(err)
				return
			}
			if string(body) != "{}" || r.Header.Get("Authorization") != "Bearer crsr-wire-test" {
				setWireErr(fmt.Errorf("unexpected auth exchange: body=%q authorization=%q", body, r.Header.Get("Authorization")))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"accessToken":"jwt-wire-test"}`)
		case cursorAgentServicePath:
			if got := r.Header.Get("Content-Type"); got != "application/connect+proto" {
				setWireErr(fmt.Errorf("content type = %q", got))
			}
			if got := r.Header.Get("Accept"); got != "application/connect+proto" {
				setWireErr(fmt.Errorf("accept = %q", got))
			}
			if got := r.Header.Get("Connect-Protocol-Version"); got != "1" {
				setWireErr(fmt.Errorf("connect protocol version = %q", got))
			}
			frame, err := cursorDecodeConnectFrame(r.Body)
			if err != nil {
				setWireErr(err)
				return
			}
			runRequest := pbFirstLD(pbIter(frame.Payload), 1)
			if runRequest == nil || pbFirstStr(pbIter(runRequest), 25) == "" {
				setWireErr(fmt.Errorf("missing run_request/run_id in first frame: %x", frame.Payload))
				return
			}
			w.Header().Set("Content-Type", "application/connect+proto")
			flusher, ok := w.(http.Flusher)
			if !ok {
				setWireErr(fmt.Errorf("test response is not flushable"))
				return
			}
			_, _ = w.Write(cursorEncodeConnectFrame(0, pbFieldLD(1, pbFieldLD(1, pbFieldStr(1, "wire-hello")))))
			flusher.Flush()
			_, _ = w.Write(cursorEncodeConnectFrame(0, pbFieldLD(1, pbFieldLD(14, nil))))
			flusher.Flush()
		default:
			setWireErr(fmt.Errorf("unexpected path %s", r.URL.Path))
			http.NotFound(w, r)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	exec := NewCursorExecutor(nil)
	exec.authEndpoint = server.URL
	exec.agentEndpoint = server.URL
	exec.httpClient = server.Client()
	auth := &cliproxyauth.Auth{ID: "cursor-wire-test", Provider: "cursor", Attributes: map[string]string{"api_key": "crsr-wire-test"}}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      map[string][]string{"X-Session-ID": {"sess-wire"}},
	}
	resp, err := exec.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "cursor-grok-4.6",
		Payload: []byte(`{"model":"cursor-grok-4.6","messages":[{"role":"user","content":"hello"}]}`),
	}, opts)
	if err != nil {
		t.Fatalf("wire Execute: %v", err)
	}
	wireMu.Lock()
	validationErr := wireErr
	wireMu.Unlock()
	if validationErr != nil {
		t.Fatalf("wire validation: %v", validationErr)
	}
	if got := gjson.GetBytes(resp.Payload, "choices.0.message.content").String(); got != "wire-hello" {
		t.Fatalf("content = %q, response = %s", got, resp.Payload)
	}
}

func drainCursorStream(t *testing.T, stream *cliproxyexecutor.StreamResult) []string {
	t.Helper()
	var out []string
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream err: %v", chunk.Err)
		}
		if len(bytes.TrimSpace(chunk.Payload)) == 0 {
			continue
		}
		out = append(out, string(chunk.Payload))
	}
	return out
}

func cursorStreamFinish(chunks []string) string {
	for i := len(chunks) - 1; i >= 0; i-- {
		reason := gjson.Get(chunks[i], "choices.0.finish_reason").String()
		if reason != "" && reason != "null" {
			return reason
		}
	}
	return ""
}

func cursorStreamToolCall(chunks []string) (name, id string) {
	for _, chunk := range chunks {
		gjson.Get(chunk, "choices.0.delta.tool_calls").ForEach(func(_, tc gjson.Result) bool {
			if n := tc.Get("function.name").String(); n != "" {
				name = n
			}
			if v := tc.Get("id").String(); v != "" {
				id = v
			}
			return true
		})
	}
	return name, id
}

func TestCursorExchangeAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cursorAgentAuthExchange {
			t.Fatalf("path = %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "{}" {
			t.Fatalf("body = %s", body)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer crsr_test" {
			t.Fatalf("authorization = %q", got)
		}
		_, _ = io.WriteString(w, `{"token":"jwt-1","expiresIn":120}`)
	}))
	t.Cleanup(server.Close)
	exec := NewCursorExecutor(nil)
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "crsr_test"}}
	got, err := exec.cursorExchangeAPIKey(context.Background(), auth, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "jwt-1" {
		t.Fatalf("token = %q", got.Token)
	}
}

func TestCursorOpenAINonStreamToolMessage(t *testing.T) {
	raw, err := cursorOpenAINonStreamToolMessage("m", "", []cursorPendingCall{{ID: "c1", Name: "read_file"}}, []string{`{"path":"a.go"}`})
	if err != nil {
		t.Fatal(err)
	}
	if gjson.GetBytes(raw, "choices.0.finish_reason").String() != "tool_calls" {
		t.Fatalf("%s", raw)
	}
	if gjson.GetBytes(raw, "choices.0.message.tool_calls.0.function.name").String() != "read_file" {
		t.Fatalf("%s", raw)
	}
}
