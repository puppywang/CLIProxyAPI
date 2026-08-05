// Package quota provides per-credential quota lookups for the auth selectors.
// Today this is a thin wrapper around ChatGPT's backend wham/usage endpoint,
// the same call exposed by the management UI's "remaining quota" widgets.
package quota

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

// whamUsageURL is the ChatGPT backend endpoint that returns per-account
// remaining-quota information. It is undocumented but used by the Codex CLI
// and by CPA's own management panel.
const whamUsageURL = "https://chatgpt.com/backend-api/wham/usage"

// defaultUserAgent matches the Codex CLI's user-agent so that wham/usage
// behaves consistently with the rest of the Codex traffic the credential
// already sees. Keep this aligned with codexUserAgent in
// internal/runtime/executor/codex_executor.go.
const defaultUserAgent = "codex-tui/0.135.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.135.0)"

// DefaultFetchTimeout caps each individual wham/usage call. Because the
// fetcher is now invoked from a background refresher rather than the
// request hot path, we can afford a more generous deadline that survives
// a slow SOCKS5 handshake on the first request through a fresh transport.
const DefaultFetchTimeout = 5 * time.Second

// CodexWhamFetcher implements coreauth.QuotaFetcher by querying
// chatgpt.com/backend-api/wham/usage with each candidate auth's bearer
// token and per-auth proxy. Non-Codex auths return ok=false so the
// selector can degrade gracefully for mixed pools.
//
// Transports are cached per proxy URL so consecutive fetches reuse the
// underlying TCP / TLS / SOCKS5 connection pool instead of paying for
// a fresh handshake on every call. The pool is unbounded — codex auths
// realistically share a handful of proxy URLs at most.
type CodexWhamFetcher struct {
	timeout    time.Duration
	transports sync.Map // proxyURL string -> *http.Transport
}

// NewCodexWhamFetcher returns a fetcher with default settings. The fetcher
// is safe for concurrent use — Fetch calls share a per-proxy transport
// pool but never mutate one in flight.
func NewCodexWhamFetcher() *CodexWhamFetcher {
	return &CodexWhamFetcher{timeout: DefaultFetchTimeout}
}

// transportFor returns the cached transport for the given proxy URL,
// constructing one on first use. A nil transport means "use net/http
// defaults" — preserved as the empty-key entry so subsequent calls also
// reuse the default RoundTripper instead of constructing fresh clients.
func (f *CodexWhamFetcher) transportFor(proxyURL string) (http.RoundTripper, error) {
	key := strings.TrimSpace(proxyURL)
	if cached, ok := f.transports.Load(key); ok {
		if rt, ok := cached.(http.RoundTripper); ok {
			return rt, nil
		}
	}
	transport, _, err := proxyutil.BuildHTTPTransport(key)
	if err != nil {
		return nil, err
	}
	var rt http.RoundTripper
	if transport != nil {
		rt = transport
	}
	// Store nil values too — that lets us avoid re-parsing the empty
	// proxy URL on every call when the auth has no proxy configured.
	actual, _ := f.transports.LoadOrStore(key, rt)
	if cached, ok := actual.(http.RoundTripper); ok {
		return cached, nil
	}
	return rt, nil
}

// Fetch implements coreauth.QuotaFetcher. ok=false means "no data for this
// auth, do not include it in quota-driven ranking"; err covers transient
// failures (network, parse, non-2xx response).
func (f *CodexWhamFetcher) Fetch(ctx context.Context, auth *coreauth.Auth) (coreauth.QuotaSnapshot, bool, error) {
	if auth == nil {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	accessToken := metaString(auth.Metadata, "access_token")
	// K12 / agent-identity codex accounts have no bearer access token — they
	// authenticate (chat AND wham/usage) with a per-request ed25519 assertion.
	agentIdentity := codexauth.IsAgentIdentityMetadata(auth.Metadata)
	if accessToken == "" && !agentIdentity {
		return coreauth.QuotaSnapshot{}, false, nil
	}

	rt, err := f.transportFor(auth.ProxyURL)
	if err != nil {
		return coreauth.QuotaSnapshot{}, false, err
	}
	client := &http.Client{Transport: rt}

	timeout := f.timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, whamUsageURL, nil)
	if err != nil {
		return coreauth.QuotaSnapshot{}, false, err
	}
	req.Header.Set("Accept", "application/json")
	if agentIdentity {
		assertion, errAssert := codexauth.AgentAssertionFromMetadata(auth.Metadata, time.Now())
		if errAssert != nil {
			return coreauth.QuotaSnapshot{}, false, errAssert
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
		return coreauth.QuotaSnapshot{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return coreauth.QuotaSnapshot{}, false, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return coreauth.QuotaSnapshot{}, false, fmt.Errorf("wham/usage status %d: %s", resp.StatusCode, truncate(body, 200))
	}
	return parseWhamUsage(body)
}

// parseWhamUsage extracts the fields the selector needs from a wham/usage
// response body. The endpoint is undocumented and has shipped extra fields
// over time; we read defensively via gjson rather than binding to a
// fixed-shape struct.
func parseWhamUsage(body []byte) (coreauth.QuotaSnapshot, bool, error) {
	if len(body) == 0 {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	if !gjson.GetBytes(body, "rate_limit").Exists() {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	snap := coreauth.QuotaSnapshot{
		UsedPercentPrimary:   int(gjson.GetBytes(body, "rate_limit.primary_window.used_percent").Int()),
		UsedPercentSecondary: int(gjson.GetBytes(body, "rate_limit.secondary_window.used_percent").Int()),
		LimitReached:         gjson.GetBytes(body, "rate_limit.limit_reached").Bool(),
		FetchedAt:            time.Now(),
		// Top-level plan_type is the live ChatGPT subscription tier
		// (free/plus/team/pro/…). Agent-identity credentials freeze plan
		// at registration; the refresher uses this field to re-sync.
		PlanType: strings.TrimSpace(gjson.GetBytes(body, "plan_type").String()),
	}
	if v := gjson.GetBytes(body, "rate_limit.primary_window.reset_at").Int(); v > 0 {
		snap.ResetAtPrimary = time.Unix(v, 0)
	}
	if v := gjson.GetBytes(body, "rate_limit.secondary_window.reset_at").Int(); v > 0 {
		snap.ResetAtSecondary = time.Unix(v, 0)
	}
	if !snap.LimitReached {
		if gjson.GetBytes(body, "rate_limit.allowed").Exists() && !gjson.GetBytes(body, "rate_limit.allowed").Bool() {
			snap.LimitReached = true
		}
	}
	// Saturation heuristic: wham sometimes reports used_percent=100
	// while still leaving limit_reached=false (the "approval review
	// failed: hit usage limit" case observed on the codex reasoning
	// model — the weekly window is at 100% and the upstream API IS
	// blocking, but the flag doesn't flip). Treat >=100% on either
	// window as limit-reached so downstream cooldown logic kicks in
	// without waiting for an HTTP-429 from the next user request.
	if !snap.LimitReached && (snap.UsedPercentPrimary >= 100 || snap.UsedPercentSecondary >= 100) {
		snap.LimitReached = true
	}
	return snap, true, nil
}

func metaString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	if v, ok := metadata[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func truncate(payload []byte, max int) string {
	if len(payload) <= max {
		return string(payload)
	}
	return string(payload[:max]) + "..."
}
