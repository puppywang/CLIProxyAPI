package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	cursorAgentCLIVersion     = "cli-2026.08.11-e8db854"
	cursorAgentHeartbeatEvery = 5 * time.Second
)

type cursorJWTCache struct {
	mu    sync.Mutex
	items map[string]cursorAgentJWT
}

func (c *cursorJWTCache) get(key string) (cursorAgentJWT, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	got, ok := c.items[key]
	if !ok || time.Now().After(got.ExpiresAt.Add(-2*time.Minute)) {
		return cursorAgentJWT{}, false
	}
	return got, true
}

func (c *cursorJWTCache) put(key string, jwt cursorAgentJWT) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = make(map[string]cursorAgentJWT)
	}
	c.items[key] = jwt
}

var cursorAgentJWTs = &cursorJWTCache{items: make(map[string]cursorAgentJWT)}

type bidiCursorAgent struct {
	events    chan cursorAgentEvent
	pw        *io.PipeWriter
	writeMu   sync.Mutex
	submitMu  sync.Mutex
	pending   []cursorBidiExec
	cancel    context.CancelFunc
	ctx       context.Context
	root      string
	closed    bool
	closeMu   sync.Mutex
	submitted *sync.Cond
}

func (t *bidiCursorAgent) Events() <-chan cursorAgentEvent { return t.events }

func (t *bidiCursorAgent) writePayload(payload []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.closeMu.Lock()
	closed := t.closed
	pw := t.pw
	t.closeMu.Unlock()
	if closed || pw == nil {
		return fmt.Errorf("cursor agent stream closed")
	}
	_, err := pw.Write(cursorEncodeConnectFrame(0, payload))
	return err
}

func (t *bidiCursorAgent) SubmitToolResults(_ context.Context, results []cursorToolResult) error {
	// Serialize concurrent tool-result submissions on the same transport:
	// without this, two racing requests could both read the same pending exec
	// list, write duplicate results and clear each other's pending state.
	t.submitMu.Lock()
	defer t.submitMu.Unlock()

	t.closeMu.Lock()
	pending := append([]cursorBidiExec(nil), t.pending...)
	t.closeMu.Unlock()
	if len(pending) == 0 {
		return fmt.Errorf("cursor agent: no pending exec to complete")
	}
	used := map[int]bool{}
	for _, res := range results {
		idx := cursorMatchBidiExec(pending, used, res)
		if idx < 0 {
			continue
		}
		used[idx] = true
		if err := t.writePayload(cursorEncodeMcpToolResult(pending[idx], res.Content)); err != nil {
			return err
		}
	}
	for i, exec := range pending {
		if used[i] {
			continue
		}
		if err := t.writePayload(cursorEncodeMcpToolError(exec, "tool result missing from client")); err != nil {
			return err
		}
	}
	t.closeMu.Lock()
	t.pending = nil
	if t.submitted != nil {
		t.submitted.Broadcast()
	}
	t.closeMu.Unlock()
	return nil
}

func cursorMatchBidiExec(pending []cursorBidiExec, used map[int]bool, res cursorToolResult) int {
	if res.CallID != "" {
		for i, p := range pending {
			if !used[i] && p.CallID == res.CallID {
				return i
			}
		}
	}
	if res.Name != "" {
		for i, p := range pending {
			if !used[i] && p.Name == res.Name {
				return i
			}
		}
	}
	for i := range pending {
		if !used[i] {
			return i
		}
	}
	return -1
}

func (t *bidiCursorAgent) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.submitted != nil {
		t.submitted.Broadcast()
	}
	if t.cancel != nil {
		t.cancel()
	}
	if t.pw != nil {
		_ = t.pw.Close()
	}
	return nil
}

func (t *bidiCursorAgent) emit(ev cursorAgentEvent) {
	select {
	case t.events <- ev:
	default:
		select {
		case t.events <- ev:
		case <-time.After(5 * time.Second):
		}
	}
}

func dialBidiCursorAgent(ctx context.Context, exec *CursorExecutor, auth *cliproxyauth.Auth, start cursorAgentStart) (cursorAgentTransport, error) {
	if exec == nil {
		return nil, statusErr{code: 500, msg: "cursor executor: missing executor"}
	}
	jwt, err := exec.cursorJWT(ctx, auth)
	if err != nil {
		return nil, err
	}

	// The bidi transport outlives the HTTP request that created it: after a
	// tool-calling turn the client submits tool results in a follow-up
	// request, and the underlying Cursor run must stay alive across those
	// requests. Deriving the transport context from the request context would
	// cancel the stream the moment the first request finishes (handler-level
	// cliCancel), breaking continuation. The transport therefore gets its own
	// lifecycle: it lives until the session TTL cleanup, an explicit Close
	// (session replacement/eviction), or the server closing the stream.
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	t := &bidiCursorAgent{
		events: make(chan cursorAgentEvent, 32),
		pw:     pw,
		cancel: cancel,
		ctx:    runCtx,
		root:   cursorDefaultWorkspace(start.Workspace),
	}
	t.submitted = sync.NewCond(&t.closeMu)

	frames := cursorBuildRunFrames(
		start.Prompt,
		start.BaseModel,
		start.Workspace,
		cursorVariantParams(start.Model, start.ReasoningEffort),
		start.Tools,
	)

	go t.paceAndHeartbeat(runCtx, frames)

	endpoint := cursorAgentEndpoint(exec, auth)
	req, err := http.NewRequestWithContext(runCtx, http.MethodPost, cursorAgentServiceURL(endpoint), pr)
	if err != nil {
		cancel()
		_ = pw.Close()
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt.Token)
	req.Header.Set("Accept", "application/connect+proto")
	req.Header.Set("Content-Type", "application/connect+proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Connect-Accept-Encoding", "gzip")
	req.Header.Set("x-cursor-streaming", "true")
	req.Header.Set("User-Agent", "connect-es/1.6.1")
	req.Header.Set("x-cursor-client-type", "cli")
	req.Header.Set("x-cursor-client-version", cursorAgentCLIVersion)
	req.Header.Set("x-ghost-mode", "true")
	requestID := uuid.NewString()
	req.Header.Set("x-request-id", requestID)
	req.Header.Set("x-original-request-id", requestID)
	req.ContentLength = -1

	client := exec.cursorHTTPClient(runCtx, auth)
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		_ = pw.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		cancel()
		_ = pw.Close()
		return nil, statusErr{code: resp.StatusCode, msg: string(b)}
	}

	go t.readLoop(resp)
	return t, nil
}

func (t *bidiCursorAgent) paceAndHeartbeat(ctx context.Context, frames [][]byte) {
	defer func() {
		// Keep the pipe open for heartbeats / tool results until Close.
	}()
	for i, frame := range frames {
		select {
		case <-ctx.Done():
			return
		default:
		}
		t.writeMu.Lock()
		_, err := t.pw.Write(frame)
		t.writeMu.Unlock()
		if err != nil {
			return
		}
		delay := 400 * time.Millisecond
		switch i {
		case 0:
			delay = 1500 * time.Millisecond
		case 1:
			delay = 800 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	ticker := time.NewTicker(cursorAgentHeartbeatEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.writeMu.Lock()
			_, err := t.pw.Write(cursorConnectHeartbeatFrame())
			t.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (t *bidiCursorAgent) readLoop(resp *http.Response) {
	defer func() {
		_ = resp.Body.Close()
		_ = t.Close()
		close(t.events)
	}()
	for {
		flags, payload, err := cursorDecodeStreamFrame(resp.Body)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				t.emit(cursorAgentEvent{Type: cursorAgentEventError, Err: err})
			} else {
				t.emit(cursorAgentEvent{Type: cursorAgentEventDone})
			}
			return
		}
		if flags&cursorConnectFlagEnd != 0 {
			if err := cursorExtractConnectError(payload); err != nil {
				t.emit(cursorAgentEvent{Type: cursorAgentEventError, Err: err})
			} else {
				t.emit(cursorAgentEvent{Type: cursorAgentEventDone})
			}
			return
		}
		topFields := pbIter(payload)
		if localExec, ok := cursorExtractLocalExec(payload); ok {
			result := cursorEncodeLocalExecResult(t.ctx, t.root, localExec)
			if len(result) == 0 {
				t.emit(cursorAgentEvent{Type: cursorAgentEventError, Err: fmt.Errorf("cursor agent: unsupported local exec %d", localExec.Kind)})
				return
			}
			t.writeMu.Lock()
			_, writeErr := t.pw.Write(cursorEncodeConnectFrame(0, result))
			t.writeMu.Unlock()
			if writeErr != nil {
				t.emit(cursorAgentEvent{Type: cursorAgentEventError, Err: writeErr})
				return
			}
			continue
		}
		if exec, args, ok := cursorExtractMcpToolCall(payload); ok {
			t.closeMu.Lock()
			t.pending = append(t.pending, exec)
			t.closeMu.Unlock()
			t.emit(cursorAgentEvent{
				Type: cursorAgentEventToolCall,
				ToolCall: &cursorAgentToolCallEvent{
					Call:      cursorPendingCall{ID: exec.CallID, Name: exec.Name},
					Arguments: args,
				},
			})
			t.emit(cursorAgentEvent{Type: cursorAgentEventAwaitClient})
			t.closeMu.Lock()
			for len(t.pending) > 0 && !t.closed {
				t.submitted.Wait()
			}
			closed := t.closed
			t.closeMu.Unlock()
			if closed {
				return
			}
			continue
		}
		// ExecServerMessage and ExecServerControlMessage are tagged unions. If
		// the server sends a kind the local bridge does not implement yet, fail
		// explicitly instead of silently dropping the request and leaving the
		// agent stuck.
		if _, present := pbFirst(topFields, 2); present {
			t.emit(cursorAgentEvent{Type: cursorAgentEventError, Err: fmt.Errorf("cursor agent: unsupported ExecServerMessage variant")})
			return
		}
		if _, present := pbFirst(topFields, 5); present {
			t.emit(cursorAgentEvent{Type: cursorAgentEventError, Err: fmt.Errorf("cursor agent: unsupported ExecServerControlMessage")})
			return
		}
		if _, present := pbFirst(topFields, 7); present {
			t.emit(cursorAgentEvent{Type: cursorAgentEventError, Err: fmt.Errorf("cursor agent: unsupported interaction query")})
			return
		}
		if text := cursorExtractAnswerText(payload); text != "" {
			t.emit(cursorAgentEvent{Type: cursorAgentEventText, Text: text})
		}
		if cursorExtractTurnEnded(payload) {
			t.emit(cursorAgentEvent{Type: cursorAgentEventDone})
			return
		}
	}
}

func (e *CursorExecutor) cursorJWT(ctx context.Context, auth *cliproxyauth.Auth) (cursorAgentJWT, error) {
	info := cursorInfoFromAuth(auth)
	if info.apiKey == "" {
		return cursorAgentJWT{}, statusErr{code: http.StatusUnauthorized, msg: "cursor executor: missing api key"}
	}
	if got, ok := cursorAgentJWTs.get(info.apiKey); ok {
		return got, nil
	}
	bases := []string{cursorAuthExchangeEndpoint(e, auth)}
	var last error
	for _, base := range bases {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}
		jwt, err := e.cursorExchangeAPIKey(ctx, auth, base)
		if err != nil {
			last = err
			continue
		}
		cursorAgentJWTs.put(info.apiKey, jwt)
		return jwt, nil
	}
	if last == nil {
		last = fmt.Errorf("cursor executor: auth exchange failed")
	}
	return cursorAgentJWT{}, last
}
