// Package quota — xAI/Grok billing polling.
//
// Unlike the Codex wham/usage path (which is wired into the selector and drives
// credential ranking + cooldown), grok has no short rate-limit window that
// affects selection. This file implements a standalone, display-only poller
// that fetches each xai auth's monthly credit pool from grok's /v1/billing
// endpoint and caches a QuotaSnapshot for the management UI to render. It does
// NOT touch the LeastRemainingQuotaSelector, so grok billing data can never
// perturb codex (or grok) credential selection.
package quota

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// xaiBillingURL is grok's per-account billing endpoint. Plain, it reports the
// monthly credit pool (config.monthlyLimit.val, config.used.val, and the
// billing period bounds). With ?format=credits it reports the current *weekly*
// usage window (config.creditUsagePercent, config.currentPeriod.{start,end}) —
// the SuperGrok weekly cap that actually gates the account independently of the
// monthly pool. Both are fetched so the UI can show which one is binding.
const (
	xaiBillingURL        = "https://cli-chat-proxy.grok.com/v1/billing"
	xaiBillingCreditsURL = xaiBillingURL + "?format=credits"
)

// grok-cli identity headers, mirroring the official grok pager/shell client.
// The plain monthly endpoint tolerates their absence, but ?format=credits is
// only reliably served to grok-cli-identified clients, so send them on both.
const (
	xaiTokenAuthHeader     = "x-xai-token-auth"
	xaiTokenAuthValue      = "xai-grok-cli"
	xaiClientVersionHeader = "x-grok-client-version"
	xaiClientVersionValue  = "0.2.91"
	xaiBillingUserAgent    = "grok-pager/0.2.91 grok-shell/0.2.91 (macos; aarch64)"
)

// XAIBillingFetcher queries grok's /v1/billing endpoint for an xai auth and
// maps its two usage windows onto a QuotaSnapshot by horizon: the weekly
// SuperGrok cap in the Primary (shorter) window and the monthly credit pool in
// the Secondary (longer) window. Non-xai auths return ok=false. Safe for
// concurrent use; transports are pooled per proxy URL.
type XAIBillingFetcher struct {
	timeout    time.Duration
	transports sync.Map // proxyURL string -> http.RoundTripper
}

// NewXAIBillingFetcher returns a fetcher with default settings.
func NewXAIBillingFetcher() *XAIBillingFetcher {
	return &XAIBillingFetcher{timeout: DefaultFetchTimeout}
}

func (f *XAIBillingFetcher) transportFor(proxyURL string) (http.RoundTripper, error) {
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
	actual, _ := f.transports.LoadOrStore(key, rt)
	if cached, ok := actual.(http.RoundTripper); ok {
		return cached, nil
	}
	return rt, nil
}

// Fetch retrieves the grok billing snapshot for a single xai auth. ok=false
// means "no data for this auth" (wrong provider / missing token / empty body);
// err covers transient failures (network, non-2xx).
func (f *XAIBillingFetcher) Fetch(ctx context.Context, auth *coreauth.Auth) (coreauth.QuotaSnapshot, bool, error) {
	if auth == nil {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "xai") {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	token := metaString(auth.Metadata, "access_token")
	if token == "" && auth.Attributes != nil {
		token = strings.TrimSpace(auth.Attributes["api_key"])
	}
	if token == "" {
		return coreauth.QuotaSnapshot{}, false, nil
	}

	rt, err := f.transportFor(auth.ProxyURL)
	if err != nil {
		return coreauth.QuotaSnapshot{}, false, err
	}
	client := &http.Client{Transport: rt}

	snap := coreauth.QuotaSnapshot{FetchedAt: time.Now()}
	got := false
	var firstErr error

	// Window mapping follows the QuotaSnapshot convention of Primary =
	// shorter-horizon window, Secondary = longer-horizon window, so the two UI
	// columns read consistently across providers (codex: 5h / 7d; grok: weekly
	// / monthly). grok's SuperGrok *weekly* cap is the shorter window -> Primary
	// (and it is the cap that actually blocks the account, so it drives
	// LimitReached); the monthly credit pool is the longer window -> Secondary.
	// Display-only data; the ordering never affects credential selection.
	if body, errW := f.get(ctx, client, token, xaiBillingCreditsURL); errW != nil {
		firstErr = errW
	} else if pct, reset, reached, ok := parseXAIWeekly(body); ok {
		snap.UsedPercentPrimary = pct
		snap.ResetAtPrimary = reset
		if reached {
			snap.LimitReached = true
		}
		got = true
	}

	if body, errM := f.get(ctx, client, token, xaiBillingURL); errM != nil {
		if firstErr == nil {
			firstErr = errM
		}
	} else if pct, reset, reached, ok := parseXAIMonthly(body); ok {
		snap.UsedPercentSecondary = pct
		snap.ResetAtSecondary = reset
		if reached {
			snap.LimitReached = true
		}
		got = true
	}

	if !got {
		return coreauth.QuotaSnapshot{}, false, firstErr
	}
	return snap, true, nil
}

// get performs one authenticated GET against a grok billing URL and returns the
// response body, applying the grok-cli identity headers.
func (f *XAIBillingFetcher) get(ctx context.Context, client *http.Client, token, url string) ([]byte, error) {
	timeout := f.timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(xaiTokenAuthHeader, xaiTokenAuthValue)
	req.Header.Set(xaiClientVersionHeader, xaiClientVersionValue)
	req.Header.Set("User-Agent", xaiBillingUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("xai billing status %d: %s", resp.StatusCode, truncate(body, 200))
	}
	return body, nil
}

// parseXAIMonthly maps a plain /v1/billing body onto the monthly credit pool:
// used/limit percent and the monthly reset (billingPeriodEnd).
func parseXAIMonthly(body []byte) (pct int, reset time.Time, limitReached bool, ok bool) {
	cfg := gjson.GetBytes(body, "config")
	if !cfg.Exists() {
		return 0, time.Time{}, false, false
	}
	limit := cfg.Get("monthlyLimit.val").Float()
	used := cfg.Get("used.val").Float()
	if limit > 0 {
		pct = int(used * 100 / limit)
		if pct < 0 {
			pct = 0
		}
		limitReached = used >= limit
	}
	if end := strings.TrimSpace(cfg.Get("billingPeriodEnd").String()); end != "" {
		reset = parseXAITime(end)
	}
	return pct, reset, limitReached, true
}

// parseXAIWeekly maps a /v1/billing?format=credits body onto the current weekly
// window: config.creditUsagePercent (already a 0-100 percent) and the weekly
// reset (config.currentPeriod.end). Only treated as weekly when currentPeriod
// is a WEEKLY period, so a schema change never silently mislabels a window.
func parseXAIWeekly(body []byte) (pct int, reset time.Time, limitReached bool, ok bool) {
	cfg := gjson.GetBytes(body, "config")
	if !cfg.Exists() {
		return 0, time.Time{}, false, false
	}
	if !strings.Contains(strings.ToUpper(cfg.Get("currentPeriod.type").String()), "WEEKLY") {
		return 0, time.Time{}, false, false
	}
	used := cfg.Get("creditUsagePercent").Float()
	pct = int(used + 0.5)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	limitReached = used >= 100
	if end := strings.TrimSpace(cfg.Get("currentPeriod.end").String()); end != "" {
		reset = parseXAITime(end)
	}
	return pct, reset, limitReached, true
}

// parseXAITime parses grok's RFC3339 timestamps, tolerating fractional seconds
// (the weekly currentPeriod carries microsecond precision).
func parseXAITime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}

// xaiBillingCache is a small concurrent map of authID -> latest snapshot.
type xaiBillingCache struct {
	mu sync.RWMutex
	m  map[string]coreauth.QuotaSnapshot
}

func (c *xaiBillingCache) set(id string, snap coreauth.QuotaSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]coreauth.QuotaSnapshot)
	}
	c.m[id] = snap
}

func (c *xaiBillingCache) get(id string) (coreauth.QuotaSnapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snap, ok := c.m[id]
	return snap, ok
}

// XAIBillingPoller periodically refreshes grok billing snapshots for all xai
// auths in the background and serves them from an in-memory cache. It is fully
// independent of the codex quota subsystem.
type XAIBillingPoller struct {
	fetcher     *XAIBillingFetcher
	lister      AuthLister
	interval    time.Duration
	concurrency int
	cache       xaiBillingCache

	mu      sync.Mutex
	cancel  context.CancelFunc
	started bool

	// observer, when set, receives every freshly fetched snapshot. Used to
	// mirror grok billing into the monitor's quota history alongside codex.
	observer func(authID string, snap coreauth.QuotaSnapshot)
}

// SetObserver installs a callback invoked with each freshly fetched snapshot.
// Observational only; it must not block. Call before Start.
func (p *XAIBillingPoller) SetObserver(fn func(authID string, snap coreauth.QuotaSnapshot)) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.observer = fn
	p.mu.Unlock()
}

// notifyObserver fans a snapshot out to the observer if one is installed.
func (p *XAIBillingPoller) notifyObserver(authID string, snap coreauth.QuotaSnapshot) {
	if p == nil {
		return
	}
	p.mu.Lock()
	fn := p.observer
	p.mu.Unlock()
	if fn != nil {
		fn(authID, snap)
	}
}

// NewXAIBillingPoller constructs a poller. interval<=0 uses the default.
func NewXAIBillingPoller(lister AuthLister, interval time.Duration) *XAIBillingPoller {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	return &XAIBillingPoller{
		fetcher:     NewXAIBillingFetcher(),
		lister:      lister,
		interval:    interval,
		concurrency: DefaultConcurrency,
	}
}

// Start launches the background loop. Idempotent: a second call is a no-op
// while already running.
func (p *XAIBillingPoller) Start(ctx context.Context) {
	if p == nil || p.lister == nil {
		return
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.started = true
	p.mu.Unlock()
	go p.loop(loopCtx)
}

// Stop halts the background loop. Idempotent.
func (p *XAIBillingPoller) Stop() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.started = false
}

// Snapshot returns the cached billing snapshot for an auth, if present.
func (p *XAIBillingPoller) Snapshot(authID string) (coreauth.QuotaSnapshot, bool) {
	if p == nil {
		return coreauth.QuotaSnapshot{}, false
	}
	return p.cache.get(strings.TrimSpace(authID))
}

// RefreshNow performs a synchronous fetch for a single auth (used by the
// management "refresh" button) and updates the cache on success.
func (p *XAIBillingPoller) RefreshNow(ctx context.Context, authID string) (coreauth.QuotaSnapshot, bool, error) {
	if p == nil {
		return coreauth.QuotaSnapshot{}, false, nil
	}
	authID = strings.TrimSpace(authID)
	for _, a := range p.lister() {
		if a == nil || a.ID != authID {
			continue
		}
		snap, ok, err := p.fetcher.Fetch(ctx, a)
		if err != nil || !ok {
			return coreauth.QuotaSnapshot{}, ok, err
		}
		p.cache.set(authID, snap)
		p.notifyObserver(authID, snap)
		return snap, true, nil
	}
	return coreauth.QuotaSnapshot{}, false, fmt.Errorf("xai billing: auth %q not found", authID)
}

func (p *XAIBillingPoller) loop(ctx context.Context) {
	// Small randomized initial delay so a fleet of accounts does not hit
	// grok in the same instant on startup.
	jitter := time.Duration(rand.Int64N(int64(time.Second)))
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
	}
	p.runOnce(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.runOnce(ctx)
		}
	}
}

func (p *XAIBillingPoller) runOnce(ctx context.Context) {
	auths := p.lister()
	if len(auths) == 0 {
		return
	}
	targets := make([]*coreauth.Auth, 0, len(auths))
	for _, a := range auths {
		if a == nil || a.Disabled || a.ID == "" {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "xai") {
			continue
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		return
	}
	concurrency := p.concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, target := range targets {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(a *coreauth.Auth) {
			defer wg.Done()
			defer func() { <-sem }()
			snap, ok, err := p.fetcher.Fetch(ctx, a)
			if err != nil {
				log.Debugf("xai-billing: fetch failed | auth=%s err=%v", a.ID, err)
				return
			}
			if !ok {
				return
			}
			p.cache.set(a.ID, snap)
			p.notifyObserver(a.ID, snap)
			log.Debugf("xai-billing: fetch ok | auth=%s weekly_used=%d%% monthly_used=%d%%", a.ID, snap.UsedPercentPrimary, snap.UsedPercentSecondary)
		}(target)
	}
	wg.Wait()
}
