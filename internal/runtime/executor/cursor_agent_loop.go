package executor

import (
	"context"
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func (e *CursorExecutor) agentDialer() cursorAgentDialer {
	if e != nil && e.dialAgent != nil {
		return e.dialAgent
	}
	return dialBidiCursorAgent
}

func cursorAgentAnchor(auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) string {
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	payload := req.Payload
	if len(opts.OriginalRequest) > 0 {
		payload = opts.OriginalRequest
	}
	anchor := metadataString(opts.Metadata, cliproxyexecutor.ExecutionSessionMetadataKey)
	if anchor == "" {
		anchor = metadataString(req.Metadata, cliproxyexecutor.ExecutionSessionMetadataKey)
	}
	if anchor == "" {
		anchor = cliproxyauth.StableSessionAnchor(opts.Headers, payload, opts.Metadata)
	}
	return cursorAgentSessionKey(authID, anchor)
}

func cursorAgentPayloads(req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) (original, translated []byte) {
	original = req.Payload
	if len(opts.OriginalRequest) > 0 {
		original = opts.OriginalRequest
	}
	from := opts.SourceFormat
	if from == "" {
		from = sdktranslator.FormatOpenAI
	}
	translated = sdktranslator.TranslateRequest(from, sdktranslator.FormatOpenAI, cursorBaseModel(req.Model), req.Payload, stream)
	if len(translated) == 0 {
		translated = req.Payload
	}
	return original, translated
}

func (e *CursorExecutor) executeAgent(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) (cliproxyexecutor.Response, *cliproxyexecutor.StreamResult, error) {
	baseModel := cursorBaseModel(req.Model)
	originalPayload, payload := cursorAgentPayloads(req, opts, stream)
	start := cursorAgentStart{
		Model:           req.Model,
		BaseModel:       baseModel,
		ReasoningEffort: cursorReasoningEffort(opts),
		Tools:           cursorClientTools(payload),
		Payload:         payload,
		ToolResults:     cursorToolResults(payload),
		Prompt:          cursorPromptFromPayload(payload),
		Workspace:       cursorDefaultWorkspace(cursorWorkspaceHint(opts.Headers)),
	}
	if strings.TrimSpace(start.Prompt) == "" {
		return cliproxyexecutor.Response{}, nil, statusErr{code: 400, msg: "cursor executor: empty prompt"}
	}

	key := cursorAgentAnchor(auth, req, opts)
	sess := cursorAgentSessions.get(key)
	if sess != nil && len(start.ToolResults) > 0 && sess.Transport != nil {
		start.Continuation = true
		err := sess.Transport.SubmitToolResults(ctx, start.ToolResults)
		if err != nil {
			if err != errCursorAgentRestart {
				cursorAgentSessions.drop(key)
				return cliproxyexecutor.Response{}, nil, err
			}
			_ = sess.Transport.Close()
			sess.Transport = nil
		}
	}

	if sess == nil || sess.Transport == nil {
		transport, err := e.agentDialer()(ctx, e, auth, start)
		if err != nil {
			return cliproxyexecutor.Response{}, nil, err
		}
		if sess == nil {
			sess = &cursorAgentSession{Key: key}
			if auth != nil {
				sess.AuthID = auth.ID
			}
		}
		sess.Model = req.Model
		sess.Transport = transport
		sess.Generation++
		cursorAgentSessions.put(sess)
	}

	if stream {
		result, err := e.consumeAgentStream(ctx, req, opts, sess, originalPayload, payload)
		return cliproxyexecutor.Response{}, result, err
	}
	resp, err := e.consumeAgentNonStream(ctx, req, opts, sess, originalPayload, payload)
	return resp, nil, err
}

func (e *CursorExecutor) consumeAgentStream(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, sess *cursorAgentSession, originalPayload, translatedPayload []byte) (*cliproxyexecutor.StreamResult, error) {
	chunks := make(chan cliproxyexecutor.StreamChunk, 64)
	go func() {
		defer close(chunks)
		// NOTE: do NOT drop the session when the request context is cancelled.
		// The transport has its own lifecycle (see dialBidiCursorAgent) so a
		// tool-calling turn survives the first HTTP request ending; the client
		// submits tool results in a follow-up request. Sessions are reclaimed
		// by TTL cleanup or explicit Close.
		var param any
		sendJSON := func(raw []byte) bool {
			return cursorSendTranslatedChunk(ctx, req, opts, originalPayload, translatedPayload, raw, &param, chunks)
		}
		sendErr := func(err error) {
			if err == nil {
				return
			}
			select {
			case <-ctx.Done():
			case chunks <- cliproxyexecutor.StreamChunk{Err: err}:
			}
		}

		model := sess.Model
		if model == "" {
			model = req.Model
		}
		var pending []cursorPendingCall
		stop := false

		for !stop {
			var ev cursorAgentEvent
			var ok bool
			select {
			case <-ctx.Done():
				sendErr(ctx.Err())
				return
			case ev, ok = <-sess.Transport.Events():
				if !ok {
					ev = cursorAgentEvent{Type: cursorAgentEventDone}
				}
			}
			switch ev.Type {
			case cursorAgentEventError:
				sendErr(ev.Err)
				cursorAgentSessions.drop(sess.Key)
				return
			case cursorAgentEventText:
				if ev.Text == "" {
					continue
				}
				raw, err := cursorOpenAITextDelta(model, ev.Text)
				if err != nil {
					sendErr(err)
					return
				}
				if !sendJSON(raw) {
					return
				}
			case cursorAgentEventToolCall:
				if ev.ToolCall == nil {
					continue
				}
				idx := len(pending)
				pending = append(pending, ev.ToolCall.Call)
				start, err := cursorOpenAIToolCallStart(model, idx, ev.ToolCall.Call)
				if err != nil {
					sendErr(err)
					return
				}
				if !sendJSON(start) {
					return
				}
				if ev.ToolCall.Arguments != "" {
					args, err := cursorOpenAIToolCallArgs(model, idx, ev.ToolCall.Arguments)
					if err != nil {
						sendErr(err)
						return
					}
					if !sendJSON(args) {
						return
					}
				}
			case cursorAgentEventAwaitClient, cursorAgentEventDone:
				stop = true
			}
		}

		finish := "stop"
		if len(pending) > 0 {
			finish = "tool_calls"
			sess.mu.Lock()
			sess.Pending = pending
			sess.mu.Unlock()
			cursorAgentSessions.put(sess)
		} else {
			cursorAgentSessions.drop(sess.Key)
		}
		end, err := cursorOpenAIFinish(model, finish)
		if err != nil {
			sendErr(err)
			return
		}
		_ = sendJSON(end)
		doneChunks := sdktranslator.TranslateStream(ctx, sdktranslator.FromString("openai"), cliproxyexecutor.ResponseFormatOrSource(opts), req.Model, originalPayload, translatedPayload, []byte("data: [DONE]"), &param)
		for i := range doneChunks {
			select {
			case <-ctx.Done():
				return
			case chunks <- cliproxyexecutor.StreamChunk{Payload: doneChunks[i]}:
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func (e *CursorExecutor) consumeAgentNonStream(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, sess *cursorAgentSession, originalPayload, translatedPayload []byte) (cliproxyexecutor.Response, error) {
	defer func() {
		if ctx.Err() != nil {
			cursorAgentSessions.drop(sess.Key)
		}
	}()
	model := sess.Model
	if model == "" {
		model = req.Model
	}
	var text strings.Builder
	var pending []cursorPendingCall
	var pendingArgs []string
	for {
		select {
		case <-ctx.Done():
			return cliproxyexecutor.Response{}, ctx.Err()
		case ev, ok := <-sess.Transport.Events():
			if !ok {
				ev = cursorAgentEvent{Type: cursorAgentEventDone}
			}
			switch ev.Type {
			case cursorAgentEventError:
				cursorAgentSessions.drop(sess.Key)
				return cliproxyexecutor.Response{}, ev.Err
			case cursorAgentEventText:
				text.WriteString(ev.Text)
			case cursorAgentEventToolCall:
				if ev.ToolCall != nil {
					pending = append(pending, ev.ToolCall.Call)
					pendingArgs = append(pendingArgs, ev.ToolCall.Arguments)
				}
			case cursorAgentEventAwaitClient, cursorAgentEventDone:
				if len(pending) > 0 {
					sess.Pending = pending
					cursorAgentSessions.put(sess)
				} else {
					cursorAgentSessions.drop(sess.Key)
				}
				raw, err := cursorOpenAINonStreamToolMessage(model, strings.TrimSpace(text.String()), pending, pendingArgs)
				if err != nil {
					return cliproxyexecutor.Response{}, err
				}
				responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
				out := sdktranslator.TranslateNonStream(ctx, "openai", responseFormat, req.Model, originalPayload, translatedPayload, raw, nil)
				return cliproxyexecutor.Response{Payload: out}, nil
			}
		}
	}
}

func cursorSendTranslatedChunk(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, originalPayload, translatedPayload, openaiJSON []byte, param *any, chunks chan cliproxyexecutor.StreamChunk) bool {
	line := append([]byte("data: "), openaiJSON...)
	translated := sdktranslator.TranslateStream(ctx, sdktranslator.FromString("openai"), cliproxyexecutor.ResponseFormatOrSource(opts), req.Model, originalPayload, translatedPayload, line, param)
	for i := range translated {
		select {
		case <-ctx.Done():
			return false
		case chunks <- cliproxyexecutor.StreamChunk{Payload: translated[i]}:
		}
	}
	return true
}
