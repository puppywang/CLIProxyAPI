package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// Defaults lifted from LTbinglingfeng/cpa-plugin-codex-invite. The
// referral_key is OpenAI's campaign identifier (not a per-account
// secret) and the Originator/User-Agent fields impersonate the official
// Codex desktop client so the wham backend does not refuse the call.
const (
	defaultInviteReferralKey = "codex_referral_persistent_invite"
	defaultInviteBaseURL     = "https://chatgpt.com"
	defaultInviteLanguage    = "zh-CN"
	defaultInviteOriginator  = "Codex Desktop"
	defaultInviteUserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	inviteEndpointPath       = "/backend-api/wham/referrals/invite"
	// Hard cap matches the campaign rule: each Plus/Pro account may
	// invite up to 3 friends between 2026-06-11 and 2026-06-24. Sending
	// more in one batch would silently burn the per-account allowance
	// without producing rewards, per OpenAI's referral_promotions docs.
	inviteMaxEmails = 3
	inviteBodyLimit = 1 << 20
)

var inviteEmailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// In-memory cache for InviteCodexStatus responses. Keeps OpenAI's anti-abuse
// system from seeing repeated /wham/* + eligibility-helper fan-outs each time
// the operator opens the invite modal. TTL is short enough that operator
// changes (sending an invite, redeeming a credit) become visible within a
// few minutes, and the cache is bypassed entirely when ?refresh=1 is set or
// after a successful POST /codex-invite/:id (we invalidate the entry there).
var (
	inviteStatusCache    sync.Map // key=auth.ID  value=*cachedInviteStatus
	inviteStatusCacheTTL = 5 * time.Minute
)

type cachedInviteStatus struct {
	body      inviteStatusResponse
	fetchedAt time.Time
}

// inviteRequest is the body accepted by POST /v0/management/codex-invite/:id.
// emails is required; emails_text is a convenience for newline/comma
// separated lists pasted from the UI. referral_key, language, base_url,
// proxy_url override the defaults — leave empty to use them.
type inviteRequest struct {
	Emails      []string `json:"emails"`
	EmailsText  string   `json:"emails_text"`
	ReferralKey string   `json:"referral_key"`
	BaseURL     string   `json:"base_url"`
	ProxyURL    string   `json:"proxy_url"`
	Language    string   `json:"language"`
	Cookie      string   `json:"cookie"`
}

// inviteResponse is what we return to the caller. Upstream is the raw
// wham response when it parses as JSON; UpstreamRaw is the literal body
// when it doesn't. StatusCode mirrors the wham response code so the UI
// can distinguish 4xx (e.g. quota / referral disabled) from 5xx.
type inviteResponse struct {
	OK          bool     `json:"ok"`
	StatusCode  int      `json:"status_code"`
	RequestID   string   `json:"request_id,omitempty"`
	AuthID      string   `json:"auth_id"`
	Email       string   `json:"email,omitempty"`
	AccountID   string   `json:"account_id,omitempty"`
	Emails      []string `json:"emails"`
	ReferralKey string   `json:"referral_key"`
	Upstream    any      `json:"upstream,omitempty"`
	UpstreamRaw string   `json:"upstream_raw,omitempty"`
}

// InviteCodex sends a referral invite from the selected Codex auth.
// Body: { emails: [...], emails_text?, referral_key?, base_url?,
// proxy_url?, language?, cookie? }. Returns 502 with the upstream body
// when wham itself rejects the call.
func (h *Handler) InviteCodex(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager not configured"})
		return
	}

	identifier := strings.TrimSpace(c.Param("id"))
	if identifier == "" {
		identifier = strings.TrimSpace(c.Query("id"))
	}
	if identifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing auth id"})
		return
	}
	if strings.ContainsAny(identifier, "/\\") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid auth id"})
		return
	}

	var auth *coreauth.Auth
	for _, a := range h.authManager.List() {
		if a == nil {
			continue
		}
		if a.ID == identifier || a.FileName == identifier {
			auth = a
			break
		}
	}
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth not found"})
		return
	}
	if auth.Provider != "codex" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invite requires a codex auth, got provider=%s", auth.Provider)})
		return
	}

	accessToken := tokenValueFromMetadata(auth.Metadata)
	if accessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth has no access_token"})
		return
	}
	accountID := ""
	if v, ok := auth.Metadata["account_id"].(string); ok {
		accountID = strings.TrimSpace(v)
	}
	email := ""
	if v, ok := auth.Metadata["email"].(string); ok {
		email = strings.TrimSpace(v)
	}

	var body inviteRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid body: %v", err)})
		return
	}
	emails, errEmails := collectInviteEmails(body)
	if errEmails != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errEmails.Error()})
		return
	}

	referralKey := strings.TrimSpace(body.ReferralKey)
	if referralKey == "" {
		referralKey = defaultInviteReferralKey
	}
	baseURL := strings.TrimSpace(body.BaseURL)
	if baseURL == "" {
		baseURL = defaultInviteBaseURL
	}
	language := strings.TrimSpace(body.Language)
	if language == "" {
		language = defaultInviteLanguage
	}

	proxyURL := strings.TrimSpace(body.ProxyURL)
	if proxyURL == "" {
		if v, ok := auth.Metadata["proxy_url"].(string); ok {
			proxyURL = strings.TrimSpace(v)
		}
	}
	if proxyURL == "" && h.cfg != nil {
		proxyURL = strings.TrimSpace(h.cfg.ProxyURL)
	}

	endpoint, errEndpoint := inviteEndpointURL(baseURL)
	if errEndpoint != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errEndpoint.Error()})
		return
	}

	client, errClient := inviteHTTPClient(proxyURL)
	if errClient != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errClient.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()

	payload, _ := json.Marshal(map[string]any{
		"referral_key": referralKey,
		"emails":       emails,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Oai-Language", language)
	req.Header.Set("Originator", defaultInviteOriginator)
	req.Header.Set("User-Agent", defaultInviteUserAgent)
	if accountID != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}
	if cookie := strings.TrimSpace(body.Cookie); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	resp, errDo := client.Do(req)
	if errDo != nil {
		log.Warnf("codex-invite: request failed for auth=%s: %v", auth.ID, errDo)
		c.JSON(http.StatusBadGateway, gin.H{"error": errDo.Error()})
		return
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codex-invite: close body: %v", errClose)
		}
	}()

	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, inviteBodyLimit))
	if errRead != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("read upstream body: %v", errRead)})
		return
	}

	out := inviteResponse{
		OK:          resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode:  resp.StatusCode,
		RequestID:   resp.Header.Get("x-oai-request-id"),
		AuthID:      auth.ID,
		Email:       email,
		AccountID:   accountID,
		Emails:      emails,
		ReferralKey: referralKey,
	}
	var parsed any
	if len(raw) > 0 && json.Unmarshal(raw, &parsed) == nil {
		out.Upstream = parsed
	} else {
		out.UpstreamRaw = string(raw)
	}

	log.Infof("codex-invite: auth=%s emails=%d status=%d ok=%v", auth.ID, len(emails), resp.StatusCode, out.OK)
	// Invite changes invites_sent / remaining / history fields; drop the
	// cached status snapshot so the next /status call refetches.
	if out.OK {
		inviteStatusCache.Delete(auth.ID)
	}
	c.JSON(http.StatusOK, out)
}

// collectInviteEmails normalises the emails+emails_text inputs into a
// deduped, validated list. Lowercase keys are used for dedup so the
// same address is not invited twice if the user pastes both upper and
// lower case variants. Mirrors the plugin's collectEmails so behaviour
// matches the reference implementation.
func collectInviteEmails(req inviteRequest) ([]string, error) {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	add := func(raw string) {
		for _, item := range splitInviteEmailList(raw) {
			email := strings.TrimSpace(item)
			if email == "" {
				continue
			}
			key := strings.ToLower(email)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, email)
		}
	}
	for _, item := range req.Emails {
		add(item)
	}
	add(req.EmailsText)

	if len(out) == 0 {
		return nil, fmt.Errorf("at least one email is required")
	}
	if len(out) > inviteMaxEmails {
		return nil, fmt.Errorf("too many emails: got %d, max %d", len(out), inviteMaxEmails)
	}
	for _, email := range out {
		if !inviteEmailPattern.MatchString(email) {
			return nil, fmt.Errorf("invalid email address %q", email)
		}
	}
	return out, nil
}

func splitInviteEmailList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
}

func inviteEndpointURL(baseURL string) (string, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	parsed, errParse := url.Parse(baseURL)
	if errParse != nil {
		return "", errParse
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported base URL scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("base URL host is required")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + inviteEndpointPath
	return parsed.String(), nil
}

func inviteHTTPClient(proxyURL string) (*http.Client, error) {
	if proxyURL == "" {
		return http.DefaultClient, nil
	}
	parsed, errParse := url.Parse(proxyURL)
	if errParse != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", errParse)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("proxy URL needs scheme and host")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy URL scheme %q", parsed.Scheme)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(parsed)
	return &http.Client{Transport: transport}, nil
}

// inviteStatusResponse is the unified result of GET /v0/management/codex-invite/:id/status.
// It bundles five upstream calls (usage, eligibility rules, sent referrals,
// reset-credit ledger, invite/eligibility) so the management UI only does one
// round trip. Each upstream source's failure goes into Errors keyed by source
// name; the other sources still surface their data. Mirrors how the upstream
// userscript handles partial failures.
type inviteStatusResponse struct {
	AuthID    string            `json:"auth_id"`
	Email     string            `json:"email,omitempty"`
	AccountID string            `json:"account_id,omitempty"`
	PlanType  string            `json:"plan_type,omitempty"`
	Errors    map[string]string `json:"errors,omitempty"`

	Eligibility *inviteEligibility  `json:"eligibility,omitempty"`
	Rules       *inviteRules        `json:"rules,omitempty"`
	History     []inviteHistoryItem `json:"history"`
	Credits     *inviteCredits      `json:"credits,omitempty"`
}

// inviteEligibility mirrors the JSON returned by
// /backend-api/referrals/invite/eligibility. When the account is ineligible
// the body still parses cleanly with should_show=false and a structured
// ineligible_reason_code (e.g. "referrer_plan_type"); this is the only
// upstream surface that exposes the *reason* an account is excluded.
type inviteEligibility struct {
	ShouldShow           bool   `json:"should_show"`
	IneligibleReason     string `json:"ineligible_reason,omitempty"`
	IneligibleReasonCode string `json:"ineligible_reason_code,omitempty"`
	RemainingReferrals   *int   `json:"remaining_referrals,omitempty"`
	GrantAction          string `json:"grant_action,omitempty"`
	GrantAmount          int    `json:"grant_amount,omitempty"`
	Title                string `json:"title,omitempty"`
	Description          string `json:"description,omitempty"`
}

// inviteRules surfaces the per-account cap from
// /backend-api/wham/referrals/eligibility_rules. Authoritative replacement
// for our previous localStorage counter — these counters live server-side.
type inviteRules struct {
	InvitesSent  int    `json:"invites_sent"`
	InvitesTotal int    `json:"invites_total"`
	Remaining    int    `json:"remaining"`
	TimeFrame    string `json:"time_frame,omitempty"`
}

type inviteGrant struct {
	Recipient string `json:"recipient,omitempty"`
	GrantType string `json:"grant_type,omitempty"`
	Amount    int    `json:"amount,omitempty"`
}

type inviteHistoryItem struct {
	Email        string        `json:"email,omitempty"`
	Status       string        `json:"status,omitempty"`
	ExpiresAt    string        `json:"expires_at,omitempty"`
	ReferralID   string        `json:"referral_id,omitempty"`
	ReferralLink string        `json:"referral_link,omitempty"`
	Grants       []inviteGrant `json:"grants,omitempty"`
}

type inviteCreditItem struct {
	ID              string `json:"id,omitempty"`
	Status          string `json:"status,omitempty"`
	Title           string `json:"title,omitempty"`
	Description     string `json:"description,omitempty"`
	ProfileUserID   string `json:"profile_user_id,omitempty"`
	GrantedAt       string `json:"granted_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	RedeemedAt      string `json:"redeemed_at,omitempty"`
	RedeemStartedAt string `json:"redeem_started_at,omitempty"`
}

type inviteCredits struct {
	AvailableCount   int                `json:"available_count"`
	TotalEarnedCount int                `json:"total_earned_count,omitempty"`
	Items            []inviteCreditItem `json:"items,omitempty"`
}

// InviteCodexStatus aggregates the upstream surfaces the codex desktop
// userscript pulls before deciding whether to show the invite panel.
// Read-only — no quota is consumed by calling this. If a specific upstream
// endpoint is filtered (Cloudflare blocks /referrals/invite/eligibility on
// non-browser TLS fingerprints), the body parse fails and the error lands
// in the errors map; the other sources still produce their data.
func (h *Handler) InviteCodexStatus(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager not configured"})
		return
	}

	identifier := strings.TrimSpace(c.Param("id"))
	if identifier == "" {
		identifier = strings.TrimSpace(c.Query("id"))
	}
	if identifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing auth id"})
		return
	}
	if strings.ContainsAny(identifier, "/\\") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid auth id"})
		return
	}

	var auth *coreauth.Auth
	for _, a := range h.authManager.List() {
		if a == nil {
			continue
		}
		if a.ID == identifier || a.FileName == identifier {
			auth = a
			break
		}
	}
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth not found"})
		return
	}
	if auth.Provider != "codex" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("status requires a codex auth, got provider=%s", auth.Provider)})
		return
	}

	// Cache short-circuit. ?refresh=1 (or any truthy value) bypasses.
	refreshOnly := strings.EqualFold(strings.TrimSpace(c.Query("refresh")), "1") ||
		strings.EqualFold(strings.TrimSpace(c.Query("refresh")), "true")
	if !refreshOnly {
		if cached, ok := inviteStatusCache.Load(auth.ID); ok {
			entry := cached.(*cachedInviteStatus)
			if time.Since(entry.fetchedAt) < inviteStatusCacheTTL {
				body := entry.body
				c.Header("X-Cache", "hit")
				c.Header("X-Cache-Age-Seconds", fmt.Sprintf("%d", int(time.Since(entry.fetchedAt).Seconds())))
				c.JSON(http.StatusOK, body)
				return
			}
		}
	}

	accessToken := tokenValueFromMetadata(auth.Metadata)
	if accessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth has no access_token"})
		return
	}
	accountID := ""
	if v, ok := auth.Metadata["account_id"].(string); ok {
		accountID = strings.TrimSpace(v)
	}
	email := ""
	if v, ok := auth.Metadata["email"].(string); ok {
		email = strings.TrimSpace(v)
	}
	proxyURL := ""
	if v, ok := auth.Metadata["proxy_url"].(string); ok {
		proxyURL = strings.TrimSpace(v)
	}
	if proxyURL == "" && h.cfg != nil {
		proxyURL = strings.TrimSpace(h.cfg.ProxyURL)
	}

	client, errClient := inviteHTTPClient(proxyURL)
	if errClient != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errClient.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	out := inviteStatusResponse{
		AuthID:    auth.ID,
		Email:     email,
		AccountID: accountID,
		Errors:    map[string]string{},
		History:   []inviteHistoryItem{},
	}
	var mu sync.Mutex
	var wg sync.WaitGroup

	keyEsc := url.QueryEscape(defaultInviteReferralKey)
	fetch := func(name, target string, parse func([]byte) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, errGet := codexInviteGet(ctx, client, target, accessToken, accountID)
			if errGet != nil {
				mu.Lock()
				out.Errors[name] = errGet.Error()
				mu.Unlock()
				return
			}
			if errParse := parse(body); errParse != nil {
				mu.Lock()
				out.Errors[name] = "decode: " + errParse.Error()
				mu.Unlock()
			}
		}()
	}

	fetch("usage", defaultInviteBaseURL+"/backend-api/wham/usage", func(b []byte) error {
		var raw struct {
			PlanType string `json:"plan_type"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		mu.Lock()
		if raw.PlanType != "" {
			out.PlanType = raw.PlanType
		}
		mu.Unlock()
		return nil
	})

	fetch("rules", defaultInviteBaseURL+"/backend-api/wham/referrals/eligibility_rules?referral_key="+keyEsc, func(b []byte) error {
		var raw struct {
			TimeFrameRules []struct {
				InvitesSent  int    `json:"invites_sent"`
				InvitesTotal int    `json:"invites_total"`
				TimeFrame    string `json:"time_frame"`
			} `json:"time_frame_rules"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		if len(raw.TimeFrameRules) == 0 {
			return nil
		}
		r := raw.TimeFrameRules[0]
		remaining := r.InvitesTotal - r.InvitesSent
		if remaining < 0 {
			remaining = 0
		}
		mu.Lock()
		out.Rules = &inviteRules{
			InvitesSent:  r.InvitesSent,
			InvitesTotal: r.InvitesTotal,
			Remaining:    remaining,
			TimeFrame:    r.TimeFrame,
		}
		mu.Unlock()
		return nil
	})

	fetch("referrals", defaultInviteBaseURL+"/backend-api/wham/referrals?referral_key="+keyEsc, func(b []byte) error {
		var raw struct {
			Items []inviteHistoryItem `json:"items"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		mu.Lock()
		out.History = raw.Items
		mu.Unlock()
		return nil
	})

	fetch("credits", defaultInviteBaseURL+"/backend-api/wham/rate-limit-reset-credits", func(b []byte) error {
		var raw struct {
			AvailableCount   int                `json:"available_count"`
			TotalEarnedCount int                `json:"total_earned_count"`
			Credits          []inviteCreditItem `json:"credits"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		mu.Lock()
		out.Credits = &inviteCredits{
			AvailableCount:   raw.AvailableCount,
			TotalEarnedCount: raw.TotalEarnedCount,
			Items:            raw.Credits,
		}
		mu.Unlock()
		return nil
	})

	// Eligibility endpoint sits behind Cloudflare's UA-Client-Hints
	// enforcement and refuses Go's stdlib TLS fingerprint. If a Python
	// helper using curl_cffi chrome116 impersonation is configured via
	// CODEX_INVITE_HELPER_PYTHON + CODEX_INVITE_HELPER_SCRIPT, route
	// through it; otherwise fall back to the direct Go GET (will fail
	// for most accounts but at least the failure mode stays uniform).
	if pyPath, scriptPath := codexInviteHelperPaths(); pyPath != "" && scriptPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := runEligibilityHelper(ctx, pyPath, scriptPath, accessToken, accountID, proxyURL, defaultInviteReferralKey)
			if err != nil {
				mu.Lock()
				out.Errors["eligibility"] = err.Error()
				mu.Unlock()
				return
			}
			mu.Lock()
			out.Eligibility = e
			mu.Unlock()
		}()
	} else {
		fetch("eligibility", defaultInviteBaseURL+"/backend-api/referrals/invite/eligibility?referral_key="+keyEsc, func(b []byte) error {
			var e inviteEligibility
			if err := json.Unmarshal(b, &e); err != nil {
				return err
			}
			mu.Lock()
			out.Eligibility = &e
			mu.Unlock()
			return nil
		})
	}

	wg.Wait()

	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	// Store result in the in-memory cache so subsequent opens of the modal
	// reuse this snapshot for inviteStatusCacheTTL. Errored fetches still
	// get cached — re-trying the same failing call within seconds gives
	// the same answer and just generates more outbound noise. Operator
	// can force a refetch from the modal at any time.
	inviteStatusCache.Store(auth.ID, &cachedInviteStatus{
		body:      out,
		fetchedAt: time.Now(),
	})
	c.Header("X-Cache", "miss")
	c.JSON(http.StatusOK, out)
}

// codexInviteHelperPaths returns the configured (python, script) pair for
// the curl_cffi eligibility helper, or two empty strings if unset.
// Configuration is env-only so the binary is happy to run without the
// helper installed and degrades gracefully.
func codexInviteHelperPaths() (string, string) {
	py := strings.TrimSpace(os.Getenv("CODEX_INVITE_HELPER_PYTHON"))
	script := strings.TrimSpace(os.Getenv("CODEX_INVITE_HELPER_SCRIPT"))
	if py == "" || script == "" {
		return "", ""
	}
	return py, script
}

// runEligibilityHelper shells out to the Python helper, feeding it the
// account credentials on stdin and parsing the JSON envelope back into
// inviteEligibility. The helper exits 0 on every path and reports its
// own failure inside the {"ok": false, ...} body — we only need to
// distinguish "helper returned ok=true with data" from anything else.
func runEligibilityHelper(ctx context.Context, py, script, token, accountID, proxyURL, referralKey string) (*inviteEligibility, error) {
	input := map[string]string{
		"access_token": token,
		"account_id":   accountID,
		"proxy_url":    proxyURL,
		"referral_key": referralKey,
		"base_url":     defaultInviteBaseURL,
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal helper input: %w", err)
	}

	cmd := exec.CommandContext(ctx, py, script)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		snippet := strings.TrimSpace(stderr.String())
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return nil, fmt.Errorf("helper exec: %w (stderr: %s)", err, snippet)
	}

	var envelope struct {
		OK     bool               `json:"ok"`
		Status int                `json:"status"`
		Error  string             `json:"error"`
		Data   *inviteEligibility `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		snippet := stdout.String()
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return nil, fmt.Errorf("decode helper output: %w (got: %s)", err, snippet)
	}
	if !envelope.OK {
		if envelope.Error != "" {
			return nil, fmt.Errorf("helper: %s", envelope.Error)
		}
		return nil, fmt.Errorf("helper returned ok=false with no error message")
	}
	if envelope.Data == nil {
		return nil, fmt.Errorf("helper returned ok=true but no data")
	}
	return envelope.Data, nil
}

// codexInviteGet is a small authenticated GET helper used by InviteCodexStatus.
// On non-2xx it returns an error containing the upstream status code plus a
// short prefix of the body (helpful for distinguishing OpenAI's JSON errors
// from Cloudflare's HTML challenge pages).
func codexInviteGet(ctx context.Context, client *http.Client, endpoint, token, accountID string) ([]byte, error) {
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if errReq != nil {
		return nil, errReq
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if accountID != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}
	req.Header.Set("Oai-Language", defaultInviteLanguage)
	req.Header.Set("Originator", defaultInviteOriginator)
	req.Header.Set("User-Agent", defaultInviteUserAgent)
	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codex-invite-status: close body: %v", errClose)
		}
	}()
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, inviteBodyLimit))
	if errRead != nil {
		return nil, errRead
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return nil, fmt.Errorf("upstream %d: %s", resp.StatusCode, snippet)
	}
	return body, nil
}
