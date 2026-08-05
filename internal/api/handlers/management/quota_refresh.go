package management

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// RefreshAuthQuota performs a synchronous wham/usage fetch for the auth
// identified by ?id= (or ?name=) and returns the resulting snapshot.
//
// The endpoint exists so the management UI can drive an immediate quota
// re-check from a per-account "refresh" button: the periodic refresher
// would otherwise leave operators waiting up to one full interval before
// the panel reflects a credential that just came back online. Re-uses
// the same fetcher + selector cache the periodic loop writes through,
// so the on-screen value matches what subsequent Pick calls will see.
//
// Status codes:
//
//   - 200: snapshot returned in the `quota` field.
//   - 400: missing/invalid id.
//   - 404: auth not found in pool.
//   - 409: auth disabled / non-codex (refresh inapplicable).
//   - 503: quota subsystem not configured.
//   - 502: upstream fetch failed (network, parse, non-2xx wham/usage).
//
// Identifier resolution mirrors GetAuthFileModels: prefer auth.ID via the
// authManager, fall back to filename match, finally use the raw query.
func (h *Handler) RefreshAuthQuota(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
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

	resolvedID := identifier
	if h.authManager != nil {
		for _, a := range h.authManager.List() {
			if a == nil {
				continue
			}
			if a.ID == identifier || a.FileName == identifier {
				resolvedID = a.ID
				break
			}
		}
	}

	// Bounded to the wham/usage fetch budget. RefreshNow itself enforces
	// the fetcher's per-call timeout, but a top-level cap keeps this
	// endpoint from holding a connection open if the refresher is wedged.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	snap, ok, err := refreshNow(ctx, resolvedID)
	if err != nil {
		// Refresher reports auth-eligibility failures via err. Bucket
		// them into the right HTTP class so the UI can render an
		// actionable message instead of a generic 500.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			c.JSON(http.StatusNotFound, gin.H{"error": msg})
		case strings.Contains(msg, "disabled"):
			c.JSON(http.StatusConflict, gin.H{"error": msg})
		case strings.Contains(msg, "not a codex"):
			c.JSON(http.StatusConflict, gin.H{"error": msg})
		default:
			if errors.Is(err, context.DeadlineExceeded) {
				c.JSON(http.StatusGatewayTimeout, gin.H{"error": "wham/usage refresh timed out"})
				return
			}
			c.JSON(http.StatusBadGateway, gin.H{"error": msg})
		}
		return
	}
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"id":    resolvedID,
			"quota": nil,
			"note":  "fetcher returned no data (missing access_token or non-codex auth)",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":    resolvedID,
		"quota": snap,
	})
}
