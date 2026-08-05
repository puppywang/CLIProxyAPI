package management

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// RefreshAuthPlan fetches live ChatGPT subscription plan_type from
// wham/usage (via the same quota refresher path) and rewrites the auth's
// stored plan when it differs. This is the operator-facing "sync plan from
// server" action for agent-identity credentials whose plan was frozen at
// registration — free→plus upgrades no longer require re-importing the
// credential file.
//
// Status codes:
//
//   - 200: plan checked (and updated when different). Body includes
//     previous_plan, plan_type, changed, and the refreshed quota snapshot.
//   - 400: missing/invalid id.
//   - 404: auth not found.
//   - 409: auth disabled / non-codex.
//   - 502/503/504: upstream or subsystem failures (same as quota-refresh).
func (h *Handler) RefreshAuthPlan(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager not configured"})
		return
	}
	refreshNow := h.getQuotaRefreshFunc()
	if refreshNow == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "quota refresher not configured"})
		return
	}

	identifier := strings.TrimSpace(c.Param("id"))
	if identifier == "" {
		identifier = strings.TrimSpace(c.Query("id"))
	}
	if identifier == "" {
		identifier = strings.TrimSpace(c.Query("name"))
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
	if auth.Disabled {
		c.JSON(http.StatusConflict, gin.H{"error": "auth is disabled"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		c.JSON(http.StatusConflict, gin.H{"error": "plan refresh requires a codex auth"})
		return
	}

	previous := effectiveAuthPlanType(auth)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Drive a full wham/usage refresh. The Service-wired PlanUpdater hook
	// rewrites plan_type + re-registers the model catalog when the live
	// tier differs from the stored one — so this single call both
	// refreshes quota and syncs the subscription.
	snap, ok, err := refreshNow(ctx, auth.ID)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			c.JSON(http.StatusNotFound, gin.H{"error": msg})
		case strings.Contains(msg, "disabled"):
			c.JSON(http.StatusConflict, gin.H{"error": msg})
		case strings.Contains(msg, "not a codex"):
			c.JSON(http.StatusConflict, gin.H{"error": msg})
		default:
			if ctx.Err() != nil {
				c.JSON(http.StatusGatewayTimeout, gin.H{"error": "wham/usage plan refresh timed out"})
				return
			}
			c.JSON(http.StatusBadGateway, gin.H{"error": msg})
		}
		return
	}
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"id":            auth.ID,
			"previous_plan": previous,
			"plan_type":     previous,
			"changed":       false,
			"note":          "fetcher returned no data (missing credential or non-codex auth)",
		})
		return
	}

	// Re-read the auth after the PlanUpdater may have rewritten it.
	live, okLive := h.authManager.GetByID(auth.ID)
	if !okLive || live == nil {
		live = auth
	}
	current := effectiveAuthPlanType(live)
	// Prefer the live wham plan when the hook somehow didn't fire but the
	// snapshot carried one — apply it here as a safety net so the endpoint
	// still upgrades the account on a single click.
	if livePlan := strings.TrimSpace(snap.PlanType); livePlan != "" && !strings.EqualFold(current, livePlan) {
		if applyPlanTypeToAuth(live, livePlan) {
			live.UpdatedAt = time.Now()
			if _, errUpdate := h.authManager.Update(ctx, live); errUpdate == nil {
				reRegisterCodexModelsForPlan(live)
				h.authManager.RefreshSchedulerEntry(live.ID)
				current = livePlan
			}
		}
	}

	changed := !strings.EqualFold(previous, current)
	c.JSON(http.StatusOK, gin.H{
		"id":            auth.ID,
		"previous_plan": previous,
		"plan_type":     current,
		"changed":       changed,
		"quota":         snap,
		"models":        codexModelIDsForPlan(current),
	})
}

func effectiveAuthPlanType(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if p := strings.TrimSpace(auth.Attributes["plan_type"]); p != "" {
			return p
		}
	}
	if auth.Metadata != nil {
		if raw, ok := auth.Metadata["plan_type"].(string); ok {
			if p := strings.TrimSpace(raw); p != "" {
				return p
			}
		}
	}
	return ""
}

// applyPlanTypeToAuth writes plan into Metadata + Attributes. Returns true
// when the value actually changed.
func applyPlanTypeToAuth(auth *coreauth.Auth, plan string) bool {
	if auth == nil {
		return false
	}
	plan = strings.TrimSpace(plan)
	if plan == "" {
		return false
	}
	if strings.EqualFold(effectiveAuthPlanType(auth), plan) {
		return false
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Metadata["plan_type"] = plan
	auth.Attributes["plan_type"] = plan
	return true
}

func codexModelIDsForPlan(plan string) []string {
	var models []*registry.ModelInfo
	switch strings.ToLower(strings.TrimSpace(plan)) {
	case "pro":
		models = registry.GetCodexProModels()
	case "plus":
		models = registry.GetCodexPlusModels()
	case "team", "business", "go":
		models = registry.GetCodexTeamModels()
	case "free":
		models = registry.GetCodexFreeModels()
	default:
		if plan == "" {
			return nil
		}
		models = registry.GetCodexProModels()
	}
	out := make([]string, 0, len(models))
	for _, m := range models {
		if m == nil || strings.TrimSpace(m.ID) == "" {
			continue
		}
		out = append(out, m.ID)
	}
	return out
}
