package executor

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// errCursorAgentRestart asks the loop to reopen the direct upstream turn when
// a transport cannot continue in-place. The bidi transport must not return it
// because tool results are written to the same AgentService stream.
var errCursorAgentRestart = errors.New("cursor agent transport needs a new turn")

type cursorAgentEventType string

const (
	cursorAgentEventText        cursorAgentEventType = "text-delta"
	cursorAgentEventToolCall    cursorAgentEventType = "tool-call"
	cursorAgentEventAwaitClient cursorAgentEventType = "await-client"
	cursorAgentEventDone        cursorAgentEventType = "done"
	cursorAgentEventError       cursorAgentEventType = "error"
)

type cursorAgentToolCallEvent struct {
	Call      cursorPendingCall
	Arguments string
}

type cursorAgentEvent struct {
	Type     cursorAgentEventType
	Text     string
	ToolCall *cursorAgentToolCallEvent
	Err      error
}

type cursorAgentStart struct {
	Model           string
	BaseModel       string
	ReasoningEffort string
	Prompt          string
	Workspace       string
	Tools           []cursorClientTool
	Payload         []byte
	ToolResults     []cursorToolResult
	Continuation    bool
}

type cursorAgentTransport interface {
	Events() <-chan cursorAgentEvent
	SubmitToolResults(ctx context.Context, results []cursorToolResult) error
	Close() error
}

type cursorAgentDialer func(ctx context.Context, exec *CursorExecutor, auth *cliproxyauth.Auth, start cursorAgentStart) (cursorAgentTransport, error)

// loopbackCursorAgent is an in-process transport used by tests to prove the
// local tool loop: first turn emits a tool call, SubmitToolResults continues
// the same stream with text, then done.
type loopbackCursorAgent struct {
	events chan cursorAgentEvent
	mu     sync.Mutex
	closed bool
}

func newLoopbackCursorAgent(start cursorAgentStart) *loopbackCursorAgent {
	t := &loopbackCursorAgent{events: make(chan cursorAgentEvent, 8)}
	go t.run(start)
	return t
}

func (t *loopbackCursorAgent) Events() <-chan cursorAgentEvent { return t.events }

func (t *loopbackCursorAgent) run(start cursorAgentStart) {
	if start.Continuation && len(start.ToolResults) > 0 {
		t.emit(cursorAgentEvent{Type: cursorAgentEventText, Text: "loopback-continued"})
		t.emit(cursorAgentEvent{Type: cursorAgentEventDone})
		return
	}
	if len(start.Tools) == 0 {
		t.emit(cursorAgentEvent{Type: cursorAgentEventText, Text: "loopback-hello"})
		t.emit(cursorAgentEvent{Type: cursorAgentEventDone})
		return
	}
	args, _ := json.Marshal(map[string]string{"path": "loopback.txt"})
	t.emit(cursorAgentEvent{
		Type: cursorAgentEventToolCall,
		ToolCall: &cursorAgentToolCallEvent{
			Call:      cursorPendingCall{ID: "call_loopback", Name: start.Tools[0].Name},
			Arguments: string(args),
		},
	})
	t.emit(cursorAgentEvent{Type: cursorAgentEventAwaitClient})
}

func (t *loopbackCursorAgent) SubmitToolResults(_ context.Context, results []cursorToolResult) error {
	text := "loopback-tool-ok"
	if len(results) > 0 && results[0].Content != "" {
		text = "loopback-tool-ok:" + results[0].Content
	}
	t.emit(cursorAgentEvent{Type: cursorAgentEventText, Text: text})
	t.emit(cursorAgentEvent{Type: cursorAgentEventDone})
	return nil
}

func (t *loopbackCursorAgent) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.events)
	return nil
}

func (t *loopbackCursorAgent) emit(ev cursorAgentEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.events <- ev
}

func dialLoopbackCursorAgent(_ context.Context, _ *CursorExecutor, _ *cliproxyauth.Auth, start cursorAgentStart) (cursorAgentTransport, error) {
	return newLoopbackCursorAgent(start), nil
}
