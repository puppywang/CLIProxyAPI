package quota

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// codexProbeURL is the codex backend's responses endpoint, the same
// endpoint the Codex executor uses for real generation requests.
const codexProbeURL = "https://chatgpt.com/backend-api/codex/responses"

// ProbePin fires one minimal real generation request on an account whose
// quota window has never started counting. ChatGPT's wham/usage returns a
// *floating* reset_at for accounts that have never made a request: every
// fetch reports reset_at ≈ fetched_at + 7d, so the window keeps sliding and
// the account permanently wastes its daily allowance (100/7 ≈ 15 points a
// day on a fresh plus account). A single real request anchors the window —
// reset_at stops following the clock and the full 7d budget is usable.
//
// The probe is deliberately minimal: the cheapest model in the catalog with
// max_output_tokens=1 so the cost is a rounding error while the effect
// (window pinned) is identical to any other first request.
//
// Returns a non-nil error only when the request itself failed (network /
// non-2xx). A success response — even one claiming quota exhaustion — still
// means the window is now anchored; callers should treat any completed HTTP
// round-trip as "window pinned".
func (f *CodexWhamFetcher) ProbePin(ctx context.Context, auth *coreauth.Auth) error {
	if auth == nil {
		return fmt.Errorf("quota probe: nil auth")
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return fmt.Errorf("quota probe: %s is not a codex auth", auth.ID)
	}
	accessToken := metaString(auth.Metadata, "access_token")
	agentIdentity := codexauth.IsAgentIdentityMetadata(auth.Metadata)
	if accessToken == "" && !agentIdentity {
		return fmt.Errorf("quota probe: %s has no access token", auth.ID)
	}

	rt, err := f.transportFor(auth.ProxyURL)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: rt}

	payload := []byte(`{"model":"gpt-5.4-mini","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],"max_output_tokens":1,"stream":true,"store":false}`)
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, codexProbeURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if agentIdentity {
		assertion, errAssert := codexauth.AgentAssertionFromMetadata(auth.Metadata, time.Now())
		if errAssert != nil {
			return errAssert
		}
		req.Header.Set("Authorization", assertion)
	} else {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	if accountID := metaString(auth.Metadata, "account_id"); accountID != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("quota probe: status %d: %s", resp.StatusCode, truncate(body, 200))
	}
	return nil
}
