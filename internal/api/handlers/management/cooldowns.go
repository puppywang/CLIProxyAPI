package management

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// cooldownAccount is the per-auth JSON shape returned by the cooldown
// management endpoint. Lists everything an operator needs to decide
// whether a credential is in a transient blip or stuck on a stale
// marker — and the Clear button uses the same auth_id to drive the
// reset.
type cooldownAccount struct {
	AuthID        string          `json:"auth_id"`
	AuthLabel     string          `json:"auth_label,omitempty"`
	Provider      string          `json:"provider,omitempty"`
	Email         string          `json:"email,omitempty"`
	Disabled      bool            `json:"disabled"`
	Status        coreauth.Status `json:"status"`
	StatusMessage string          `json:"status_message,omitempty"`
	// Auth-level cooldown state. Empty when the auth itself is healthy
	// and only individual per-model entries carry cooldown markers.
	Auth cooldownAuthState `json:"auth"`
	// Per-model cooldown entries. Only models with a non-trivial state
	// are included — clean models clutter the panel.
	Models []cooldownModelState `json:"models,omitempty"`
	// model_registry's per-model quota-suspended flags. Set independently
	// of the per-ModelState quota fields above; the selector consults
	// the registry first when filtering candidates.
	RegistrySuspendedModels []string `json:"registry_suspended_models,omitempty"`
}

// Use pointer time.Time so a zero value omits cleanly from JSON. Go's
// json/encoding does NOT honour `omitempty` for a non-pointer time.Time
// zero value — it still serialises it as "0001-01-01T00:00:00Z", which
// the UI then treats as a real (very old) timestamp and shows nonsense
// like "retry 739768d ago" on accounts that have no retry timer at all.
// The pointer-omit pattern is the standard fix.
type cooldownAuthState struct {
	Unavailable    bool       `json:"unavailable"`
	NextRetryAfter *time.Time `json:"next_retry_after,omitempty"`
	QuotaExceeded  bool       `json:"quota_exceeded"`
	QuotaReason    string     `json:"quota_reason,omitempty"`
	QuotaRecoverAt *time.Time `json:"quota_recover_at,omitempty"`
	QuotaBackoff   int        `json:"quota_backoff_level,omitempty"`
}

type cooldownModelState struct {
	Model          string     `json:"model"`
	Status         string     `json:"status"`
	StatusMessage  string     `json:"status_message,omitempty"`
	Unavailable    bool       `json:"unavailable"`
	NextRetryAfter *time.Time `json:"next_retry_after,omitempty"`
	QuotaExceeded  bool       `json:"quota_exceeded"`
	QuotaReason    string     `json:"quota_reason,omitempty"`
	QuotaRecoverAt *time.Time `json:"quota_recover_at,omitempty"`
	QuotaBackoff   int        `json:"quota_backoff_level,omitempty"`
}

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ListAuthCooldowns returns every codex auth with non-trivial cooldown
// state. Healthy auths (no Unavailable / NextRetryAfter / Quota markers
// and no model-level entries) are omitted so the panel shows only
// what an operator might want to act on.
func (h *Handler) ListAuthCooldowns(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager not configured"})
		return
	}
	now := time.Now()
	reg := registry.GetGlobalRegistry()
	accounts := make([]cooldownAccount, 0)
	for _, a := range h.authManager.List() {
		if a == nil {
			continue
		}
		row, ok := buildCooldownAccount(a, reg, now)
		if !ok {
			continue
		}
		accounts = append(accounts, row)
	}
	// Most-stale first: auths with the latest NextRetryAfter or
	// QuotaRecoverAt rise to the top so the operator's eye lands on
	// the longest-blocked credentials first.
	sort.Slice(accounts, func(i, j int) bool {
		ti := latestCooldownTime(accounts[i])
		tj := latestCooldownTime(accounts[j])
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return accounts[i].AuthID < accounts[j].AuthID
	})
	c.JSON(http.StatusOK, gin.H{
		"now":      now,
		"accounts": accounts,
	})
}

// ClearAuthCooldown wipes the cooldown markers on the named auth. See
// coreauth.Manager.ClearCooldown for the exact field list. Returns the
// post-reset state in the same shape ListAuthCooldowns uses so the UI
// can replace the row in place. The row will typically be EMPTY after
// a successful clear (no models had cooldowns); responding with the
// row even when empty keeps the UI happy.
func (h *Handler) ClearAuthCooldown(c *gin.Context) {
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
	resolvedID := identifier
	for _, a := range h.authManager.List() {
		if a == nil {
			continue
		}
		if a.ID == identifier || a.FileName == identifier {
			resolvedID = a.ID
			break
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	updated, err := h.authManager.ClearCooldown(ctx, resolvedID)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": msg})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}
	now := time.Now()
	reg := registry.GetGlobalRegistry()
	row, _ := buildCooldownAccount(updated, reg, now)
	c.JSON(http.StatusOK, gin.H{
		"id":      resolvedID,
		"now":     now,
		"account": row,
	})
}

// ForceAuthCooldown manually marks an auth as quota-exceeded until a
// given deadline, used when upstream wham/usage returns wrong data
// (e.g. claims 100% available on an auth that has actually exhausted
// its quota). Request body accepts either an absolute `until`
// (RFC3339 / unix seconds) or a relative `duration_seconds`; one is
// required, both is rejected to keep the contract unambiguous.
//
// The refresher's auto-recovery refuses to clear a manual cooldown
// until its NextRecoverAt is in the past, so the operator's chosen
// deadline is honoured even if wham flickers back to "healthy" in the
// meantime.
func (h *Handler) ForceAuthCooldown(c *gin.Context) {
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
	var body struct {
		Until           string `json:"until"`
		UntilUnix       int64  `json:"until_unix"`
		DurationSeconds int64  `json:"duration_seconds"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid body: %v", err)})
		return
	}
	now := time.Now()
	var until time.Time
	provided := 0
	if strings.TrimSpace(body.Until) != "" {
		provided++
		parsed, errParse := time.Parse(time.RFC3339, strings.TrimSpace(body.Until))
		if errParse != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid `until` (expected RFC3339): %v", errParse)})
			return
		}
		until = parsed
	}
	if body.UntilUnix > 0 {
		provided++
		until = time.Unix(body.UntilUnix, 0)
	}
	if body.DurationSeconds > 0 {
		provided++
		until = now.Add(time.Duration(body.DurationSeconds) * time.Second)
	}
	if provided == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "supply one of `until` (RFC3339), `until_unix`, or `duration_seconds`"})
		return
	}
	if provided > 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "supply only one of `until`, `until_unix`, `duration_seconds`"})
		return
	}
	if !until.After(now) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cooldown deadline must be in the future"})
		return
	}
	resolvedID := identifier
	for _, a := range h.authManager.List() {
		if a == nil {
			continue
		}
		if a.ID == identifier || a.FileName == identifier {
			resolvedID = a.ID
			break
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	updated, err := h.authManager.ForceCooldown(ctx, resolvedID, until)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": msg})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	reg := registry.GetGlobalRegistry()
	row, _ := buildCooldownAccount(updated, reg, time.Now())
	c.JSON(http.StatusOK, gin.H{
		"id":      resolvedID,
		"now":     time.Now(),
		"until":   until,
		"account": row,
	})
}

func buildCooldownAccount(a *coreauth.Auth, reg *registry.ModelRegistry, now time.Time) (cooldownAccount, bool) {
	row := cooldownAccount{
		AuthID:        a.ID,
		AuthLabel:     a.Label,
		Provider:      strings.TrimSpace(a.Provider),
		Disabled:      a.Disabled,
		Status:        a.Status,
		StatusMessage: a.StatusMessage,
	}
	if a.Metadata != nil {
		if email, ok := a.Metadata["email"].(string); ok {
			row.Email = strings.TrimSpace(email)
		}
	}
	auth := cooldownAuthState{
		Unavailable:    a.Unavailable,
		NextRetryAfter: optionalTime(a.NextRetryAfter),
		QuotaExceeded:  a.Quota.Exceeded,
		QuotaReason:    a.Quota.Reason,
		QuotaRecoverAt: optionalTime(a.Quota.NextRecoverAt),
		QuotaBackoff:   a.Quota.BackoffLevel,
	}
	row.Auth = auth

	models := make([]cooldownModelState, 0, len(a.ModelStates))
	for name, state := range a.ModelStates {
		if state == nil {
			continue
		}
		if modelStateClean(state) {
			continue
		}
		entry := cooldownModelState{
			Model:          name,
			Status:         string(state.Status),
			StatusMessage:  state.StatusMessage,
			Unavailable:    state.Unavailable,
			NextRetryAfter: optionalTime(state.NextRetryAfter),
			QuotaExceeded:  state.Quota.Exceeded,
			QuotaReason:    state.Quota.Reason,
			QuotaRecoverAt: optionalTime(state.Quota.NextRecoverAt),
			QuotaBackoff:   state.Quota.BackoffLevel,
		}
		models = append(models, entry)
	}
	sort.Slice(models, func(i, j int) bool { return models[i].Model < models[j].Model })
	row.Models = models

	// model_registry's quota-suspended flags. Even when the per-ModelState
	// quota is clean (e.g. the conductor recovered the auth but the
	// registry never got the Resume signal), the selector still filters
	// the auth out — so surface this independently.
	if reg != nil {
		row.RegistrySuspendedModels = reg.SuspendedModelsForClient(a.ID)
		sort.Strings(row.RegistrySuspendedModels)
	}

	// Skip rows where everything is clean.
	if hasAnyCooldownMarker(row) {
		return row, true
	}
	return cooldownAccount{}, false
}

func modelStateClean(state *coreauth.ModelState) bool {
	if state == nil {
		return true
	}
	if state.Status != coreauth.StatusActive {
		return false
	}
	if state.Unavailable || state.StatusMessage != "" || !state.NextRetryAfter.IsZero() || state.LastError != nil {
		return false
	}
	if state.Quota.Exceeded || state.Quota.Reason != "" || !state.Quota.NextRecoverAt.IsZero() || state.Quota.BackoffLevel != 0 {
		return false
	}
	return true
}

func hasAnyCooldownMarker(row cooldownAccount) bool {
	// Admin-disabled accounts are NOT cooldowns. They have their own
	// lifecycle (operator un-disables them via /auth-files/status) and
	// the Clear button on this panel can't help them anyway. Excluding
	// them keeps the panel focused on what it's actually for: transient
	// recoverable cooldowns. The historical status_message that
	// triggered the disable (e.g. "unauthorized" from a 401 before the
	// admin took the account offline) stays in the auth-files panel for
	// operator reference but doesn't pollute this view.
	if row.Disabled {
		return false
	}
	if row.Auth.Unavailable || row.Auth.NextRetryAfter != nil || row.Auth.QuotaExceeded {
		return true
	}
	if len(row.Models) > 0 || len(row.RegistrySuspendedModels) > 0 {
		return true
	}
	if row.Status == coreauth.StatusError {
		// Non-disabled auths with Status=Error are stuck even when no
		// structured marker is set — surface them so the operator can
		// clear and re-admit them.
		return true
	}
	// Note: a non-empty StatusMessage on an otherwise-healthy
	// (Status=Active, no Unavailable / NextRetryAfter / QuotaExceeded /
	// per-model markers) auth is NOT a cooldown — it's a historical
	// note from a past failure that the auth has since recovered from
	// (per-model success path resets state.LastError but leaves auth-
	// level StatusMessage if hasModelError was true at the time). The
	// auth-files panel still surfaces it for context; the cooldowns
	// panel is for things the operator can / should act on.
	return false
}

func latestCooldownTime(row cooldownAccount) time.Time {
	var t time.Time
	consider := func(p *time.Time) {
		if p != nil && p.After(t) {
			t = *p
		}
	}
	consider(row.Auth.NextRetryAfter)
	consider(row.Auth.QuotaRecoverAt)
	for _, m := range row.Models {
		consider(m.NextRetryAfter)
		consider(m.QuotaRecoverAt)
	}
	return t
}
