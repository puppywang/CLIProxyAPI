package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// AutoRelease429Status is the JSON shape returned by the auto-release-429
// management endpoints. Enabled mirrors the in-memory toggle; flipping
// it takes effect immediately for every in-flight and future request
// without a restart, and is persisted to config.yaml so the toggle
// survives restarts.
type AutoRelease429Status struct {
	Enabled bool `json:"enabled"`
}

// GetAutoRelease429 reports the current auto-release-on-429 toggle state.
// Reads the live in-memory atomic so it reflects the most recent PUT,
// even before the config file watcher has reloaded.
func (h *Handler) GetAutoRelease429(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	c.JSON(http.StatusOK, AutoRelease429Status{
		Enabled: coreauth.AutoReleaseOn429Enabled(),
	})
}

// SetAutoRelease429 flips the auto-release-on-429 toggle. When enabled,
// the conductor reacts to an upstream 429 by (a) immediately dropping
// every session-affinity binding on the exhausted auth so its stranded
// conversations re-pick a fresh account on their next turn, and (b)
// converting the 429 that would otherwise surface to the client into a
// 500 so the client retries — by the time the retry arrives the binding
// is gone and the selector routes to a different account. The net effect
// is transparent failover: the user sees at worst a single retried
// request, never a hard 429.
//
// The toggle is persisted to config.yaml (auto-release-on-429) so it
// survives restarts. Body: {"enabled": true|false}. Returns the
// post-update state.
func (h *Handler) SetAutoRelease429(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	var in AutoRelease429Status
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Flip the live in-memory toggle first so the next request sees the
	// new value immediately, then persist to config.yaml so a restart
	// restores it. The config-reload hook in server.go also calls
	// SetAutoReleaseOn429, so a manual config edit is honoured too.
	coreauth.SetAutoReleaseOn429(in.Enabled)
	h.mu.Lock()
	if h.cfg != nil {
		h.cfg.AutoReleaseOn429 = in.Enabled
	}
	h.mu.Unlock()
	// Best-effort persist: if configFilePath is empty (test harness),
	// skip — the in-memory toggle above is enough for the test.
	if h.configFilePath != "" {
		h.persist(c)
		return
	}
	c.JSON(http.StatusOK, AutoRelease429Status{
		Enabled: coreauth.AutoReleaseOn429Enabled(),
	})
}
