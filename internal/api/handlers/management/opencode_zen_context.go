package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

// OpencodeZenInjectContextStatus is the JSON shape returned by the
// opencode-zen-inject-context management endpoints. Enabled mirrors the
// in-memory toggle; flipping it takes effect immediately for every
// subsequent opencode-zen request without a restart, and is persisted to
// config.yaml so the toggle survives restarts.
type OpencodeZenInjectContextStatus struct {
	Enabled bool `json:"enabled"`
}

// GetOpencodeZenInjectContext reports the current opencode zen
// context-injection toggle state. Reads the live in-memory atomic so it
// reflects the most recent PUT, even before the config file watcher has
// reloaded.
func (h *Handler) GetOpencodeZenInjectContext(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	c.JSON(http.StatusOK, OpencodeZenInjectContextStatus{
		Enabled: helps.OpencodeZenInjectContextEnabled(),
	})
}

// SetOpencodeZenInjectContext flips the opencode zen context-injection
// toggle. When enabled, every opencode-zen request gets the canonical
// opencode system prompt and the canonical six tools injected (the shape
// the zen gateway's content check requires). When disabled, requests are
// forwarded with only the legal-shape fixes (reasoning_content backfill,
// developer->system, include_usage, payload budget) and the client's own
// prompt/tools pass through untouched. The toggle is persisted to
// config.yaml (opencode-zen-inject-context) so it survives restarts.
// Body: {"enabled": true|false}. Returns the post-update state.
func (h *Handler) SetOpencodeZenInjectContext(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	var in OpencodeZenInjectContextStatus
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Flip the live in-memory toggle first so the next request sees the new
	// value immediately, then persist to config.yaml so a restart restores
	// it. The config-reload hook in server.go also calls
	// SetOpencodeZenInjectContext, so a manual config edit is honoured too.
	helps.SetOpencodeZenInjectContext(in.Enabled)
	h.mu.Lock()
	if h.cfg != nil {
		h.cfg.OpencodeZenInjectContext = in.Enabled
	}
	h.mu.Unlock()
	// Best-effort persist: if configFilePath is empty (test harness),
	// skip — the in-memory toggle above is enough for the test.
	if h.configFilePath != "" {
		h.persist(c)
		return
	}
	c.JSON(http.StatusOK, OpencodeZenInjectContextStatus{
		Enabled: helps.OpencodeZenInjectContextEnabled(),
	})
}
