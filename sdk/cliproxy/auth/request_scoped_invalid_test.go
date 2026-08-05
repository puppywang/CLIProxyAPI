package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

// TestIsRequestScopedInvalidResultError checks the classifier that keeps a
// request-scoped 400/422 (the client's request is at fault) from benching a
// model, while leaving durable model-not-supported 400s to their suspension.
func TestIsRequestScopedInvalidResultError(t *testing.T) {
	cases := []struct {
		name string
		err  *Error
		want bool
	}{
		{
			name: "context_too_large 400 is request-scoped",
			err:  &Error{HTTPStatus: http.StatusBadRequest, Message: `{"error":{"message":"Your input exceeds the context window of this model.","type":"invalid_request_error","code":"context_too_large"}}`},
			want: true,
		},
		{
			name: "invalid tool value 400 is request-scoped",
			err:  &Error{HTTPStatus: http.StatusBadRequest, Message: "Invalid Value: 'tools'. Function conflicts with a hosted tool."},
			want: true,
		},
		{
			name: "model-not-supported 400 is NOT request-scoped (keeps suspension)",
			err:  &Error{HTTPStatus: http.StatusBadRequest, Message: `{"detail":"The 'gpt-5.6-sol' model is not supported when using Codex with a ChatGPT account."}`},
			want: false,
		},
		{
			name: "429 is not a 400/422",
			err:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "invalid_request_error"},
			want: false,
		},
		{
			name: "generic 400 without a known signal stays conservative",
			err:  &Error{HTTPStatus: http.StatusBadRequest, Message: "something odd happened"},
			want: false,
		},
		{name: "nil", err: nil, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRequestScopedInvalidResultError(tc.err); got != tc.want {
				t.Errorf("isRequestScopedInvalidResultError = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMarkResult_ContextTooLargeDoesNotBenchModel is the end-to-end contract:
// a context_too_large 400 for a model must leave that model available on the
// auth, so the next well-formed request can still use it.
func TestMarkResult_ContextTooLargeDoesNotBenchModel(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	t.Cleanup(func() { reg.UnregisterClient("auth-ctl-400") })

	m := NewManager(nil, &bindingCountingSelector{}, nil)
	m.SetRetryConfig(0, 0, 0)

	auth := &Auth{
		ID:          "auth-ctl-400",
		Provider:    "codex",
		ModelStates: map[string]*ModelState{},
	}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}

	m.MarkResult(context.Background(), Result{
		AuthID:   "auth-ctl-400",
		Provider: "codex",
		Model:    "gpt-5.6-sol",
		Success:  false,
		Error: &Error{
			HTTPStatus: http.StatusBadRequest,
			Message:    `{"error":{"message":"Your input exceeds the context window of this model.","type":"invalid_request_error","code":"context_too_large"}}`,
		},
	})

	got, ok := m.GetByID("auth-ctl-400")
	if !ok || got == nil {
		t.Fatal("auth not found after MarkResult")
	}
	if st := got.ModelStates["gpt-5.6-sol"]; st != nil && st.Unavailable {
		t.Error("model gpt-5.6-sol was benched (Unavailable=true) by a request-scoped context_too_large 400; want it to stay available")
	}
}
