package monitor

import (
	"strings"
	"testing"
)

func TestClassifyErrorReasonZenReasoning400(t *testing.T) {
	cases := []struct {
		name    string
		code    int
		snippet string
		want    string
	}{
		{
			name:    "zen reasoning_content rejection",
			code:    400,
			snippet: `{"error":{"type":"invalid_request_error","message":"Error from provider (Console): Upstream request failed: [invalid_request_error] The reasoning_content in the thinking mode must be passed back to the API."}}`,
			want:    "zen_reasoning_400",
		},
		{
			name:    "plain 400",
			code:    400,
			snippet: `{"error":{"message":"bad request"}}`,
			want:    "client_4xx",
		},
		{
			name:    "400 with reasoning but different error",
			code:    400,
			snippet: `{"error":{"message":"reasoning_content too long"}}`,
			want:    "client_4xx",
		},
		{
			name:    "empty snippet 400",
			code:    400,
			snippet: "",
			want:    "client_4xx",
		},
		{
			name:    "401 still auth",
			code:    401,
			snippet: `reasoning_content must be passed back`,
			want:    "auth",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyErrorReason(Entry{StatusCode: tc.code, ErrorSnippet: tc.snippet})
			if got != tc.want {
				t.Fatalf("classifyErrorReason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestZenReasoningRejectionCounter(t *testing.T) {
	reg := NewRegistry()
	cancel := func() {}
	snippet := `{"error":{"message":"Error from provider (Console): Upstream request failed: [invalid_request_error] The reasoning_content in the thinking mode must be passed back to the API."}}`

	for i := 0; i < 3; i++ {
		entry := reg.Register("zenrc-"+strings.Repeat("x", i), "POST", "", "/v1/chat/completions", "127.0.0.1", "copilot", 0, cancel)
		reg.SetStatusCode(entry, 400)
		reg.SetErrorSnippet(entry, snippet)
		reg.Finish(entry)
	}
	if got := reg.ZenReasoningRejections(); got != 3 {
		t.Fatalf("counter = %d, want 3", got)
	}
	recs := reg.RecentErrors(10)
	if len(recs) != 3 {
		t.Fatalf("RecentErrors = %d records, want 3", len(recs))
	}
	for _, r := range recs {
		if r.Reason != "zen_reasoning_400" {
			t.Fatalf("record reason = %q, want zen_reasoning_400", r.Reason)
		}
	}
	reg.ZenReasoningAlertReset()
	if got := reg.ZenReasoningRejections(); got != 0 {
		t.Fatalf("after reset counter = %d, want 0", got)
	}
	// plain 400 does not bump the counter
	entry := reg.Register("zenrc-plain", "POST", "", "/v1/chat/completions", "127.0.0.1", "copilot", 0, cancel)
	reg.SetStatusCode(entry, 400)
	reg.SetErrorSnippet(entry, `{"error":{"message":"bad"}}`)
	reg.Finish(entry)
	if got := reg.ZenReasoningRejections(); got != 0 {
		t.Fatalf("plain 400 bumped counter to %d, want 0", got)
	}
}
