// Package management provides the management API handlers and middleware
// for configuring the server and managing auth files.
package management

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"golang.org/x/crypto/bcrypt"
)

type attemptInfo struct {
	count        int
	blockedUntil time.Time
	lastActivity time.Time // track last activity for cleanup
}

// attemptCleanupInterval controls how often stale IP entries are purged
const attemptCleanupInterval = 1 * time.Hour

// attemptMaxIdleTime controls how long an IP can be idle before cleanup
const attemptMaxIdleTime = 2 * time.Hour

// Handler aggregates config reference, persistence path and helpers.
type Handler struct {
	cfg                 *config.Config
	configFilePath      string
	mu                  sync.Mutex
	attemptsMu          sync.Mutex
	failedAttempts      map[string]*attemptInfo // keyed by client IP
	authManager         *coreauth.Manager
	tokenStore          coreauth.Store
	localPassword       string
	allowRemoteOverride bool
	envSecret           string
	logDir              string
	postAuthHook        coreauth.PostAuthHook
	postAuthPersistHook coreauth.PostAuthHook
	pluginHost          *pluginhost.Host

	// Quota observation hooks injected by the cliproxy Service. quotaSnapshot
	// returns the latest cached wham/usage snapshot for an auth (or ok=false
	// when no fresh snapshot is available). quotaRefreshNow performs a
	// synchronous out-of-cycle fetch — wired to the background refresher's
	// RefreshNow so the management UI can drive an immediate re-check for one
	// account. Both fields are optional: setups without the codex quota
	// subsystem leave them nil and the corresponding endpoints respond 503.
	quotaSnapshot    QuotaSnapshotFunc
	quotaRefreshNow  QuotaRefreshNowFunc
	quotaProvidersMu sync.RWMutex
}

// QuotaSnapshotData mirrors the fields the management API exposes from the
// LeastRemainingQuotaSelector's cache. UsedPercentPrimary / Secondary are
// 0-100 ints; LimitReached mirrors upstream rate_limit.limit_reached; the
// reset times are absolute timestamps from upstream's `resets_at` /
// `resets_in_seconds`. FetchedAt records when the snapshot was last
// captured.
// Times use *time.Time so a zero value omits cleanly from JSON. Go's
// encoder does NOT honour omitempty for a non-pointer time.Time zero
// value — it serialises to "0001-01-01T00:00:00Z" which the UI then
// renders as the absurd "739768d ago" (delta from year 1 to now).
// Pointer-omit is the standard fix and the cooldowns endpoint applies
// it for the same reason.
type QuotaSnapshotData struct {
	UsedPercentPrimary   int        `json:"used_percent_primary"`
	UsedPercentSecondary int        `json:"used_percent_secondary"`
	LimitReached         bool       `json:"limit_reached"`
	ResetAtPrimary       *time.Time `json:"reset_at_primary,omitempty"`
	ResetAtSecondary     *time.Time `json:"reset_at_secondary,omitempty"`
	FetchedAt            *time.Time `json:"fetched_at,omitempty"`
}

// QuotaSnapshotFunc returns the cached snapshot for authID. ok=false when
// no fresh entry exists (cache miss or stale).
type QuotaSnapshotFunc func(authID string) (QuotaSnapshotData, bool)

// QuotaRefreshNowFunc performs a synchronous fetch via the refresher.
// ok=false means the auth is not eligible (disabled / non-codex / missing).
// err covers transient network/parse failures.
type QuotaRefreshNowFunc func(ctx context.Context, authID string) (QuotaSnapshotData, bool, error)

// NewHandler creates a new management handler instance.
func NewHandler(cfg *config.Config, configFilePath string, manager *coreauth.Manager) *Handler {
	envSecret, _ := os.LookupEnv("MANAGEMENT_PASSWORD")
	envSecret = strings.TrimSpace(envSecret)

	h := &Handler{
		cfg:                 cfg,
		configFilePath:      configFilePath,
		failedAttempts:      make(map[string]*attemptInfo),
		authManager:         manager,
		tokenStore:          sdkAuth.GetTokenStore(),
		allowRemoteOverride: envSecret != "",
		envSecret:           envSecret,
	}
	h.startAttemptCleanup()
	return h
}

// startAttemptCleanup launches a background goroutine that periodically
// removes stale IP entries from failedAttempts to prevent memory leaks.
func (h *Handler) startAttemptCleanup() {
	go func() {
		ticker := time.NewTicker(attemptCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			h.purgeStaleAttempts()
		}
	}()
}

// purgeStaleAttempts removes IP entries that have been idle beyond attemptMaxIdleTime
// and whose ban (if any) has expired.
func (h *Handler) purgeStaleAttempts() {
	now := time.Now()
	h.attemptsMu.Lock()
	defer h.attemptsMu.Unlock()
	for ip, ai := range h.failedAttempts {
		// Skip if still banned
		if !ai.blockedUntil.IsZero() && now.Before(ai.blockedUntil) {
			continue
		}
		// Remove if idle too long
		if now.Sub(ai.lastActivity) > attemptMaxIdleTime {
			delete(h.failedAttempts, ip)
		}
	}
}

// NewHandler creates a new management handler instance.
func NewHandlerWithoutConfigFilePath(cfg *config.Config, manager *coreauth.Manager) *Handler {
	return NewHandler(cfg, "", manager)
}

// SetConfig updates the in-memory config reference when the server hot-reloads.
func (h *Handler) SetConfig(cfg *config.Config) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.cfg = cfg
	h.mu.Unlock()
}

// SetAuthManager updates the auth manager reference used by management endpoints.
func (h *Handler) SetAuthManager(manager *coreauth.Manager) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.authManager = manager
	h.mu.Unlock()
}

// SetPluginHost updates the plugin host used by plugin-backed management endpoints.
func (h *Handler) SetPluginHost(host *pluginhost.Host) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.pluginHost = host
	h.mu.Unlock()
}

// SetLocalPassword configures the runtime-local password accepted for localhost requests.
func (h *Handler) SetLocalPassword(password string) { h.localPassword = password }

// SetLogDirectory updates the directory where main.log should be looked up.
func (h *Handler) SetLogDirectory(dir string) {
	if dir == "" {
		return
	}
	if !filepath.IsAbs(dir) {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	h.logDir = dir
}

// SetPostAuthHook registers a hook to be called after auth record creation but before persistence.
func (h *Handler) SetPostAuthHook(hook coreauth.PostAuthHook) {
	h.postAuthHook = hook
}

// SetPostAuthPersistHook registers a hook to be called after auth persistence.
func (h *Handler) SetPostAuthPersistHook(hook coreauth.PostAuthHook) {
	h.postAuthPersistHook = hook
}

// SetQuotaProviders wires the cached-snapshot reader and synchronous
// refresh trigger to the LeastRemainingQuotaSelector + Refresher pair
// that the cliproxy Service owns. Either argument can be nil to leave
// the corresponding endpoint disabled; callers that don't use the
// codex quota subsystem simply skip this call.
func (h *Handler) SetQuotaProviders(snapshot QuotaSnapshotFunc, refreshNow QuotaRefreshNowFunc) {
	if h == nil {
		return
	}
	h.quotaProvidersMu.Lock()
	h.quotaSnapshot = snapshot
	h.quotaRefreshNow = refreshNow
	h.quotaProvidersMu.Unlock()
}

func (h *Handler) getQuotaSnapshotFunc() QuotaSnapshotFunc {
	if h == nil {
		return nil
	}
	h.quotaProvidersMu.RLock()
	defer h.quotaProvidersMu.RUnlock()
	return h.quotaSnapshot
}

func (h *Handler) getQuotaRefreshFunc() QuotaRefreshNowFunc {
	if h == nil {
		return nil
	}
	h.quotaProvidersMu.RLock()
	defer h.quotaProvidersMu.RUnlock()
	return h.quotaRefreshNow
}

// Middleware enforces access control for management endpoints.
// All requests (local and remote) require a valid management key.
// Additionally, remote access requires allow-remote-management=true.
func (h *Handler) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-CPA-VERSION", buildinfo.Version)
		c.Header("X-CPA-COMMIT", buildinfo.Commit)
		c.Header("X-CPA-BUILD-DATE", buildinfo.BuildDate)

		clientIP := c.ClientIP()
		localClient := clientIP == "127.0.0.1" || clientIP == "::1"

		// Accept either Authorization: Bearer <key> or X-Management-Key
		var provided string
		if ah := c.GetHeader("Authorization"); ah != "" {
			parts := strings.SplitN(ah, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				provided = parts[1]
			} else {
				provided = ah
			}
		}
		if provided == "" {
			provided = c.GetHeader("X-Management-Key")
		}

		allowed, statusCode, errMsg := h.AuthenticateManagementKey(clientIP, localClient, provided)
		if !allowed {
			c.AbortWithStatusJSON(statusCode, gin.H{"error": errMsg})
			return
		}
		c.Next()
	}
}

// AuthenticateManagementKey verifies the provided management key for the given client.
// It mirrors the behaviour of Middleware() so non-HTTP callers can reuse the same logic.
func (h *Handler) AuthenticateManagementKey(clientIP string, localClient bool, provided string) (bool, int, string) {
	const maxFailures = 5
	const banDuration = 30 * time.Minute

	if h == nil {
		return false, http.StatusForbidden, "remote management disabled"
	}

	cfg := h.cfg
	var (
		allowRemote bool
		secretHash  string
	)
	if cfg != nil {
		allowRemote = cfg.RemoteManagement.AllowRemote
		secretHash = cfg.RemoteManagement.SecretKey
	}
	if h.allowRemoteOverride {
		allowRemote = true
	}
	envSecret := h.envSecret

	now := time.Now()
	h.attemptsMu.Lock()
	ai := h.failedAttempts[clientIP]
	if ai != nil && !ai.blockedUntil.IsZero() {
		if now.Before(ai.blockedUntil) {
			remaining := ai.blockedUntil.Sub(now).Round(time.Second)
			h.attemptsMu.Unlock()
			return false, http.StatusForbidden, fmt.Sprintf("IP banned due to too many failed attempts. Try again in %s", remaining)
		}
		// Ban expired, reset state
		ai.blockedUntil = time.Time{}
		ai.count = 0
	}
	h.attemptsMu.Unlock()

	if !localClient && !allowRemote {
		return false, http.StatusForbidden, "remote management disabled"
	}

	fail := func() {
		h.attemptsMu.Lock()
		aip := h.failedAttempts[clientIP]
		if aip == nil {
			aip = &attemptInfo{}
			h.failedAttempts[clientIP] = aip
		}
		aip.count++
		aip.lastActivity = time.Now()
		if aip.count >= maxFailures {
			aip.blockedUntil = time.Now().Add(banDuration)
			aip.count = 0
		}
		h.attemptsMu.Unlock()
	}

	reset := func() {
		h.attemptsMu.Lock()
		if ai := h.failedAttempts[clientIP]; ai != nil {
			ai.count = 0
			ai.blockedUntil = time.Time{}
		}
		h.attemptsMu.Unlock()
	}

	if secretHash == "" && envSecret == "" {
		return false, http.StatusForbidden, "remote management key not set"
	}

	if provided == "" {
		fail()
		return false, http.StatusUnauthorized, "missing management key"
	}

	if localClient {
		if lp := h.localPassword; lp != "" {
			if subtle.ConstantTimeCompare([]byte(provided), []byte(lp)) == 1 {
				reset()
				return true, 0, ""
			}
		}
	}

	if envSecret != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(envSecret)) == 1 {
		reset()
		return true, 0, ""
	}

	if secretHash == "" || bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(provided)) != nil {
		fail()
		return false, http.StatusUnauthorized, "invalid management key"
	}

	reset()

	return true, 0, ""
}

// persist saves the current in-memory config to disk.
func (h *Handler) persist(c *gin.Context) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.persistLocked(c)
}

// persistLocked saves the current in-memory config to disk.
// It expects the caller to hold h.mu.
func (h *Handler) persistLocked(c *gin.Context) bool {
	// Preserve comments when writing
	if err := config.SaveConfigPreserveComments(h.configFilePath, h.cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save config: %v", err)})
		return false
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
	return true
}

// Helper methods for simple types
func (h *Handler) updateBoolField(c *gin.Context, set func(bool)) {
	var body struct {
		Value *bool `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	set(*body.Value)
	h.persist(c)
}

func (h *Handler) updateIntField(c *gin.Context, set func(int)) {
	var body struct {
		Value *int `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	set(*body.Value)
	h.persist(c)
}

func (h *Handler) updateStringField(c *gin.Context, set func(string)) {
	var body struct {
		Value *string `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	set(*body.Value)
	h.persist(c)
}
