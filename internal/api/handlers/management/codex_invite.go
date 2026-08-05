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

// Codex desktop referral invites (program_id + entrypoint).
//
// The old wham campaign used referral_key=codex_referral_persistent_invite and
// /backend-api/wham/referrals/*. That path now 404s. The desktop app switched
// to program_id + entrypoint against /backend-api/referrals/invite/*.
//
// Personal Plus/Pro accounts use:
//
//	program_id=codex_referral_consumer
//	entrypoint=persistent   (profile menu) or rate_limit (limit banner)
//
// Offer amount is NOT fixed in the client. OpenAI returns offer_id / title /
// grants[] from eligibility (observed: credits_250, credits_500, credits_1000).
// Monthly send/reward caps and batch size also come from that response; the
// desktop UI further clamps a single batch to min(5, send, reward).
const (
	defaultInviteProgramID  = "codex_referral_consumer"
	defaultInviteEntrypoint = "persistent"
	defaultInviteBaseURL    = "https://chatgpt.com"
	defaultInviteLanguage   = "zh-CN"
	defaultInviteOriginator = "Codex Desktop"
	defaultInviteUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	inviteEndpointPath      = "/backend-api/referrals/invite"
	// Hard cap matches the desktop client: Math.min(5, remaining_send, remaining_reward).
	inviteMaxEmails = 5
	inviteBodyLimit = 1 << 20
)

var inviteEmailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

var (
	inviteStatusCache    sync.Map // key=auth.ID|program|entrypoint  value=*cachedInviteStatus
	inviteStatusCacheTTL = 5 * time.Minute
)

type cachedInviteStatus struct {
	body      inviteStatusResponse
	fetchedAt time.Time
}

// inviteRequest is the body accepted by POST /v0/management/codex-invite/:id.
type inviteRequest struct {
	Emails      []string `json:"emails"`
	EmailsText  string   `json:"emails_text"`
	ProgramID   string   `json:"program_id"`
	Entrypoint  string   `json:"entrypoint"`
	ReferralKey string   `json:"referral_key"` // legacy, ignored
	BaseURL     string   `json:"base_url"`
	ProxyURL    string   `json:"proxy_url"`
	Language    string   `json:"language"`
	Cookie      string   `json:"cookie"`
}

type inviteResponse struct {
	OK          bool     `json:"ok"`
	StatusCode  int      `json:"status_code"`
	RequestID   string   `json:"request_id,omitempty"`
	AuthID      string   `json:"auth_id"`
	Email       string   `json:"email,omitempty"`
	AccountID   string   `json:"account_id,omitempty"`
	Emails      []string `json:"emails"`
	ProgramID   string   `json:"program_id"`
	Entrypoint  string   `json:"entrypoint"`
	ReferralKey string   `json:"referral_key,omitempty"`
	Upstream    any      `json:"upstream,omitempty"`
	UpstreamRaw string   `json:"upstream_raw,omitempty"`
}

func resolveInviteProgram(body inviteRequest, queryProgram, queryEntrypoint string) (string, string) {
	programID := strings.TrimSpace(body.ProgramID)
	if programID == "" {
		programID = strings.TrimSpace(queryProgram)
	}
	if programID == "" {
		programID = defaultInviteProgramID
	}
	entrypoint := strings.TrimSpace(body.Entrypoint)
	if entrypoint == "" {
		entrypoint = strings.TrimSpace(queryEntrypoint)
	}
	if entrypoint == "" {
		entrypoint = defaultInviteEntrypoint
	}
	return programID, entrypoint
}

func findCodexAuth(h *Handler, identifier string) (*coreauth.Auth, error) {
	if h == nil {
		return nil, fmt.Errorf("handler not initialized")
	}
	if h.authManager == nil {
		return nil, fmt.Errorf("auth manager not configured")
	}
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, fmt.Errorf("missing auth id")
	}
	if strings.ContainsAny(identifier, `/\\`) {
		return nil, fmt.Errorf("invalid auth id")
	}
	for _, a := range h.authManager.List() {
		if a == nil {
			continue
		}
		if a.ID == identifier || a.FileName == identifier {
			return a, nil
		}
	}
	return nil, fmt.Errorf("auth not found")
}

// InviteCodex sends a referral invite from the selected Codex auth.
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
	auth, errAuth := findCodexAuth(h, identifier)
	if errAuth != nil {
		switch errAuth.Error() {
		case "missing auth id", "invalid auth id":
			c.JSON(http.StatusBadRequest, gin.H{"error": errAuth.Error()})
		case "auth not found":
			c.JSON(http.StatusNotFound, gin.H{"error": errAuth.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": errAuth.Error()})
		}
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

	programID, entrypoint := resolveInviteProgram(body, "", "")
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

	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()

	var (
		statusCode int
		requestID  string
		raw        []byte
		errDo      error
	)
	if pyPath, scriptPath := codexInviteHelperPaths(); pyPath != "" && scriptPath != "" {
		statusCode, raw, errDo = runInviteHelper(ctx, pyPath, scriptPath, accessToken, accountID, proxyURL, programID, entrypoint, emails)
	} else {
		statusCode, requestID, raw, errDo = inviteViaGoHTTP(ctx, baseURL, language, accessToken, accountID, proxyURL, programID, entrypoint, strings.TrimSpace(body.Cookie), emails)
	}
	if errDo != nil {
		log.Warnf("codex-invite: request failed for auth=%s: %v", auth.ID, errDo)
		c.JSON(http.StatusBadGateway, gin.H{"error": errDo.Error()})
		return
	}

	out := inviteResponse{
		OK:         statusCode >= 200 && statusCode < 300,
		StatusCode: statusCode,
		RequestID:  requestID,
		AuthID:     auth.ID,
		Email:      email,
		AccountID:  accountID,
		Emails:     emails,
		ProgramID:  programID,
		Entrypoint: entrypoint,
	}
	var parsed any
	if len(raw) > 0 && json.Unmarshal(raw, &parsed) == nil {
		out.Upstream = parsed
	} else {
		out.UpstreamRaw = string(raw)
	}

	log.Infof("codex-invite: auth=%s program=%s entry=%s emails=%d status=%d ok=%v",
		auth.ID, programID, entrypoint, len(emails), statusCode, out.OK)
	if out.OK {
		inviteStatusCache.Delete(auth.ID + "|" + programID + "|" + entrypoint)
		inviteStatusCache.Delete(auth.ID)
	}
	c.JSON(http.StatusOK, out)
}

func inviteViaGoHTTP(ctx context.Context, baseURL, language, accessToken, accountID, proxyURL, programID, entrypoint, cookie string, emails []string) (int, string, []byte, error) {
	endpoint, errEndpoint := inviteEndpointURL(baseURL)
	if errEndpoint != nil {
		return 0, "", nil, errEndpoint
	}
	client, errClient := inviteHTTPClient(proxyURL)
	if errClient != nil {
		return 0, "", nil, errClient
	}
	payload, _ := json.Marshal(map[string]any{
		"program_id": programID,
		"entrypoint": entrypoint,
		"emails":     emails,
	})
	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if errReq != nil {
		return 0, "", nil, errReq
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Oai-Language", language)
	req.Header.Set("Originator", defaultInviteOriginator)
	req.Header.Set("User-Agent", defaultInviteUserAgent)
	req.Header.Set("Referer", strings.TrimRight(baseURL, "/")+"/codex")
	if accountID != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return 0, "", nil, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codex-invite: close body: %v", errClose)
		}
	}()
	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, inviteBodyLimit))
	if errRead != nil {
		return resp.StatusCode, resp.Header.Get("x-oai-request-id"), nil, fmt.Errorf("read upstream body: %w", errRead)
	}
	return resp.StatusCode, resp.Header.Get("x-oai-request-id"), raw, nil
}

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
	parsed.RawQuery = ""
	parsed.Fragment = ""
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

type inviteStatusResponse struct {
	AuthID     string            `json:"auth_id"`
	Email      string            `json:"email,omitempty"`
	AccountID  string            `json:"account_id,omitempty"`
	PlanType   string            `json:"plan_type,omitempty"`
	ProgramID  string            `json:"program_id,omitempty"`
	Entrypoint string            `json:"entrypoint,omitempty"`
	Errors     map[string]string `json:"errors,omitempty"`

	Eligibility *inviteEligibility  `json:"eligibility,omitempty"`
	Rules       *inviteRules        `json:"rules,omitempty"`
	History     []inviteHistoryItem `json:"history"`
	Credits     *inviteCredits      `json:"credits,omitempty"`
}

type inviteEligibility struct {
	ShouldShow              bool          `json:"should_show"`
	IneligibleReason        string        `json:"ineligible_reason,omitempty"`
	IneligibleReasonCode    string        `json:"ineligible_reason_code,omitempty"`
	ProgramID               string        `json:"program_id,omitempty"`
	Entrypoint              string        `json:"entrypoint,omitempty"`
	OfferID                 string        `json:"offer_id,omitempty"`
	Title                   string        `json:"title,omitempty"`
	Description             string        `json:"description,omitempty"`
	RulesText               []string      `json:"rules,omitempty"`
	Grants                  []inviteGrant `json:"grants,omitempty"`
	RemainingSendCapacity   *int          `json:"remaining_send_capacity,omitempty"`
	RemainingRewardCapacity *int          `json:"remaining_reward_capacity,omitempty"`
	RequiresExplicitConfirm *bool         `json:"requires_explicit_confirmation,omitempty"`
	// Legacy fields for older UI.
	RemainingReferrals *int `json:"remaining_referrals,omitempty"`
	GrantAmount        int  `json:"grant_amount,omitempty"`
}

type inviteRules struct {
	InvitesSent  int    `json:"invites_sent"`
	InvitesTotal int    `json:"invites_total"`
	Remaining    int    `json:"remaining"`
	TimeFrame    string `json:"time_frame,omitempty"`
	CapacityType string `json:"capacity_type,omitempty"`
	RewardSent   int    `json:"reward_sent,omitempty"`
	RewardTotal  int    `json:"reward_total,omitempty"`
	RewardRemain int    `json:"reward_remaining,omitempty"`
}

type inviteGrant struct {
	Recipient string `json:"recipient,omitempty"`
	GrantType string `json:"grant_type,omitempty"`
	Amount    int    `json:"amount,omitempty"`
	RewardID  string `json:"reward_id,omitempty"`
}

type inviteHistoryItem struct {
	Email             string        `json:"email,omitempty"`
	Status            string        `json:"status,omitempty"`
	ExpiresAt         string        `json:"expires_at,omitempty"`
	CreatedAt         string        `json:"created_at,omitempty"`
	ReferralID        string        `json:"referral_id,omitempty"`
	ReferralLink      string        `json:"referral_link,omitempty"`
	InviteURL         string        `json:"invite_url,omitempty"`
	CanResend         bool          `json:"can_resend,omitempty"`
	ResendAvailableAt string        `json:"resend_available_at,omitempty"`
	Grants            []inviteGrant `json:"grants,omitempty"`
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

// InviteCodexStatus aggregates eligibility, tracking history, usage plan and
// rate-limit-reset credits for the monitor invite modal.
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
	auth, errAuth := findCodexAuth(h, identifier)
	if errAuth != nil {
		switch errAuth.Error() {
		case "missing auth id", "invalid auth id":
			c.JSON(http.StatusBadRequest, gin.H{"error": errAuth.Error()})
		case "auth not found":
			c.JSON(http.StatusNotFound, gin.H{"error": errAuth.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": errAuth.Error()})
		}
		return
	}
	if auth.Provider != "codex" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("status requires a codex auth, got provider=%s", auth.Provider)})
		return
	}

	programID, entrypoint := resolveInviteProgram(inviteRequest{}, c.Query("program_id"), c.Query("entrypoint"))
	cacheKey := auth.ID + "|" + programID + "|" + entrypoint
	refreshOnly := strings.EqualFold(strings.TrimSpace(c.Query("refresh")), "1") ||
		strings.EqualFold(strings.TrimSpace(c.Query("refresh")), "true")
	if !refreshOnly {
		if cached, ok := inviteStatusCache.Load(cacheKey); ok {
			entry := cached.(*cachedInviteStatus)
			if time.Since(entry.fetchedAt) < inviteStatusCacheTTL {
				c.Header("X-Cache", "hit")
				c.Header("X-Cache-Age-Seconds", fmt.Sprintf("%d", int(time.Since(entry.fetchedAt).Seconds())))
				c.JSON(http.StatusOK, entry.body)
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

	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()

	out := inviteStatusResponse{
		AuthID:     auth.ID,
		Email:      email,
		AccountID:  accountID,
		ProgramID:  programID,
		Entrypoint: entrypoint,
		Errors:     map[string]string{},
		History:    []inviteHistoryItem{},
	}
	var mu sync.Mutex
	var wg sync.WaitGroup

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

	if pyPath, scriptPath := codexInviteHelperPaths(); pyPath != "" && scriptPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, rules, err := runEligibilityHelper(ctx, pyPath, scriptPath, accessToken, accountID, proxyURL, programID, entrypoint)
			if err != nil {
				mu.Lock()
				out.Errors["eligibility"] = err.Error()
				mu.Unlock()
				return
			}
			mu.Lock()
			applyEligibility(&out, e, rules)
			mu.Unlock()
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			items, err := runTrackingHelper(ctx, pyPath, scriptPath, accessToken, accountID, proxyURL, programID)
			if err != nil {
				mu.Lock()
				out.Errors["referrals"] = err.Error()
				mu.Unlock()
				return
			}
			mu.Lock()
			out.History = items
			mu.Unlock()
		}()
	} else {
		eligURL := defaultInviteBaseURL + "/backend-api/referrals/invite/eligibility?" +
			url.Values{"program_id": {programID}, "entrypoint": {entrypoint}}.Encode()
		fetch("eligibility", eligURL, func(b []byte) error {
			e, rules, err := parseEligibilityPayload(b)
			if err != nil {
				return err
			}
			mu.Lock()
			applyEligibility(&out, e, rules)
			mu.Unlock()
			return nil
		})
		trackURL := defaultInviteBaseURL + "/backend-api/referrals/invite/tracking?" +
			url.Values{"program_id": {programID}, "period": {"past_90_days"}, "limit": {"100"}}.Encode()
		fetch("referrals", trackURL, func(b []byte) error {
			var raw struct {
				Items []inviteHistoryItem `json:"items"`
			}
			if err := json.Unmarshal(b, &raw); err != nil {
				return err
			}
			mu.Lock()
			out.History = normalizeHistory(raw.Items)
			mu.Unlock()
			return nil
		})
	}

	wg.Wait()
	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	inviteStatusCache.Store(cacheKey, &cachedInviteStatus{body: out, fetchedAt: time.Now()})
	c.Header("X-Cache", "miss")
	c.JSON(http.StatusOK, out)
}

func applyEligibility(out *inviteStatusResponse, e *inviteEligibility, rules *inviteRules) {
	if out == nil || e == nil {
		return
	}
	if e.GrantAmount == 0 {
		for _, g := range e.Grants {
			if strings.EqualFold(g.Recipient, "referrer") && g.Amount > 0 {
				e.GrantAmount = g.Amount
				break
			}
		}
	}
	if e.RemainingReferrals == nil && e.RemainingRewardCapacity != nil {
		v := *e.RemainingRewardCapacity
		e.RemainingReferrals = &v
	}
	out.Eligibility = e
	if rules != nil {
		out.Rules = rules
		return
	}
	// Fallback synthesis when time_frame_rules were absent.
	synth := &inviteRules{TimeFrame: "month", CapacityType: "reward"}
	if e.RemainingSendCapacity != nil {
		synth.Remaining = *e.RemainingSendCapacity
		synth.CapacityType = "send"
	}
	if e.RemainingRewardCapacity != nil {
		synth.RewardRemain = *e.RemainingRewardCapacity
		if len(e.Grants) > 0 {
			synth.Remaining = *e.RemainingRewardCapacity
			synth.CapacityType = "reward"
		}
	}
	out.Rules = synth
}

func parseEligibilityPayload(raw []byte) (*inviteEligibility, *inviteRules, error) {
	var e inviteEligibility
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, nil, err
	}
	var side struct {
		TimeFrameRules []struct {
			InvitesSent  int    `json:"invites_sent"`
			InvitesTotal int    `json:"invites_total"`
			TimeFrame    string `json:"time_frame"`
			CapacityType string `json:"capacity_type"`
		} `json:"time_frame_rules"`
	}
	_ = json.Unmarshal(raw, &side)
	var rules *inviteRules
	if len(side.TimeFrameRules) > 0 {
		rules = &inviteRules{TimeFrame: "month"}
		for _, r := range side.TimeFrameRules {
			remaining := r.InvitesTotal - r.InvitesSent
			if remaining < 0 {
				remaining = 0
			}
			switch strings.ToLower(r.CapacityType) {
			case "reward":
				rules.RewardSent = r.InvitesSent
				rules.RewardTotal = r.InvitesTotal
				rules.RewardRemain = remaining
			default: // send
				rules.InvitesSent = r.InvitesSent
				rules.InvitesTotal = r.InvitesTotal
				rules.Remaining = remaining
				rules.CapacityType = "send"
				if r.TimeFrame != "" {
					rules.TimeFrame = r.TimeFrame
				}
			}
		}
		// Primary remaining for the send button: reward capacity when grants
		// exist (matches desktop Math.min(send, reward)), else send capacity.
		if len(e.Grants) > 0 && rules.RewardTotal > 0 {
			rules.Remaining = rules.RewardRemain
			rules.CapacityType = "reward"
			// Keep invites_* as the send counters for display.
		}
	}
	return &e, rules, nil
}

func normalizeHistory(items []inviteHistoryItem) []inviteHistoryItem {
	out := make([]inviteHistoryItem, 0, len(items))
	for _, it := range items {
		if strings.TrimSpace(it.Email) == "" {
			continue
		}
		if it.ReferralLink == "" && it.InviteURL != "" {
			it.ReferralLink = it.InviteURL
		}
		out = append(out, it)
	}
	return out
}

func codexInviteHelperPaths() (string, string) {
	py := strings.TrimSpace(os.Getenv("CODEX_INVITE_HELPER_PYTHON"))
	script := strings.TrimSpace(os.Getenv("CODEX_INVITE_HELPER_SCRIPT"))
	if py == "" || script == "" {
		return "", ""
	}
	return py, script
}

type helperEnvelope struct {
	OK     bool            `json:"ok"`
	Status int             `json:"status"`
	Error  string          `json:"error"`
	Data   json.RawMessage `json:"data"`
}

func runHelperRaw(ctx context.Context, py, script string, input map[string]any) (*helperEnvelope, error) {
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
	var envelope helperEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		snippet := stdout.String()
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return nil, fmt.Errorf("decode helper output: %w (got: %s)", err, snippet)
	}
	return &envelope, nil
}

func runEligibilityHelper(ctx context.Context, py, script, token, accountID, proxyURL, programID, entrypoint string) (*inviteEligibility, *inviteRules, error) {
	input := map[string]any{
		"action":       "eligibility",
		"access_token": token,
		"account_id":   accountID,
		"proxy_url":    proxyURL,
		"program_id":   programID,
		"entrypoint":   entrypoint,
		"base_url":     defaultInviteBaseURL,
	}
	envelope, err := runHelperRaw(ctx, py, script, input)
	if err != nil {
		return nil, nil, err
	}
	if !envelope.OK {
		if envelope.Error != "" {
			return nil, nil, fmt.Errorf("helper: %s", envelope.Error)
		}
		return nil, nil, fmt.Errorf("helper returned ok=false")
	}
	if len(envelope.Data) == 0 {
		return nil, nil, fmt.Errorf("helper returned ok=true but no data")
	}
	return parseEligibilityPayload(envelope.Data)
}

func runTrackingHelper(ctx context.Context, py, script, token, accountID, proxyURL, programID string) ([]inviteHistoryItem, error) {
	input := map[string]any{
		"action":       "tracking",
		"access_token": token,
		"account_id":   accountID,
		"proxy_url":    proxyURL,
		"program_id":   programID,
		"period":       "past_90_days",
		"limit":        100,
		"base_url":     defaultInviteBaseURL,
	}
	envelope, err := runHelperRaw(ctx, py, script, input)
	if err != nil {
		return nil, err
	}
	if !envelope.OK {
		if envelope.Error != "" {
			return nil, fmt.Errorf("helper: %s", envelope.Error)
		}
		return nil, fmt.Errorf("helper returned ok=false")
	}
	var raw struct {
		Items []inviteHistoryItem `json:"items"`
	}
	if len(envelope.Data) > 0 {
		if err := json.Unmarshal(envelope.Data, &raw); err != nil {
			return nil, fmt.Errorf("decode tracking: %w", err)
		}
	}
	return normalizeHistory(raw.Items), nil
}

func runInviteHelper(ctx context.Context, py, script, token, accountID, proxyURL, programID, entrypoint string, emails []string) (int, []byte, error) {
	input := map[string]any{
		"action":       "invite",
		"access_token": token,
		"account_id":   accountID,
		"proxy_url":    proxyURL,
		"program_id":   programID,
		"entrypoint":   entrypoint,
		"emails":       emails,
		"base_url":     defaultInviteBaseURL,
	}
	envelope, err := runHelperRaw(ctx, py, script, input)
	if err != nil {
		return 0, nil, err
	}
	status := envelope.Status
	if status == 0 {
		if envelope.OK {
			status = 200
		} else {
			status = 502
		}
	}
	raw := envelope.Data
	if len(raw) == 0 && envelope.Error != "" {
		raw, _ = json.Marshal(map[string]string{"error": envelope.Error})
	}
	return status, raw, nil
}

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
