package monitor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CachedBinding describes one entry from the session-affinity cache,
// pulled across the package boundary so monitor can render the bindings
// reverse-index view without importing sdk/cliproxy/auth (which would
// create a cycle — auth already imports nothing from monitor).
//
// Closed / ClosedAt / ForkedTo carry the fork-detection marker: when a
// Codex /new turn arrives, the selector flags the prior thread's
// binding as closed and remembers which thread replaced it. The
// bindings endpoint surfaces these so operators see "this account has
// 2 active + 3 closed" rather than a misleading "5 active" load.
type CachedBinding struct {
	SessionKey string    // e.g. "mixed::codex-thread:<uuid>"
	AuthID     string    // e.g. "codex-tanaka.haru23@..."
	ExpiresAt  time.Time // when the cache TTL elapses
	Closed     bool
	ClosedAt   time.Time
	ForkedTo   string // thread_id of the replacement conversation
}

// BindingsByAuthFunc is the dependency the bindings reverse-index
// endpoint pulls from at request time. The wiring lives in
// internal/api/server.go which has access to both the monitor
// registry and the configured SessionAffinitySelector.
type BindingsByAuthFunc func() map[string][]CachedBinding

// AuthLabelLookup returns a friendly label / provider for an auth ID,
// matching the existing Registry.AuthLookup signature. Used to enrich
// the bindings panel with the same names operators see elsewhere in
// the UI. Returning ok=false leaves the row showing the raw ID.
type AuthLabelLookup func(authID string) (label, provider, proxy string, ok bool)

// RegisterRoutes attaches monitor endpoints to the given router group. The
// group is expected to already have any necessary auth middleware attached.
// bindingsFunc is optional — pass nil to skip the bindings reverse-index
// endpoint (e.g., setups that don't use SessionAffinitySelector).
func RegisterRoutes(group *gin.RouterGroup, reg *Registry, bindingsFunc BindingsByAuthFunc, authLookup AuthLabelLookup) {
	if group == nil || reg == nil {
		return
	}
	group.GET("/in-flight", listHandler(reg))
	group.GET("/in-flight/stream", streamHandler(reg))
	group.POST("/in-flight/:id/cancel", cancelHandler(reg))
	group.GET("/in-flight/settings", settingsGetHandler(reg))
	group.PUT("/in-flight/settings", settingsPutHandler(reg))
	group.GET("/in-flight/history", historyHandler(reg))
	group.GET("/in-flight/recent-errors", recentErrorsHandler(reg))
	group.GET("/quota-history", quotaHistoryHandler(reg))
	if bindingsFunc != nil {
		group.GET("/session-affinity/bindings", bindingsHandler(reg, bindingsFunc, authLookup))
	}
}

func settingsGetHandler(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, reg.Settings())
	}
}

func settingsPutHandler(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in Settings
		if err := c.ShouldBindJSON(&in); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updated, err := reg.UpdateSettings(in)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, updated)
	}
}

func recentErrorsHandler(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 50
		if v := strings.TrimSpace(c.Query("limit")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"records": reg.RecentErrors(limit),
			"now":     time.Now(),
		})
	}
}

// quotaHistoryHandler serves the retained per-auth quota series so the quota
// panel can draw a usage curve. `hours` limits the window (default 48, 0 = all
// retained history).
func quotaHistoryHandler(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		hours := 48
		if v := strings.TrimSpace(c.Query("hours")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				hours = n
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"accounts": reg.QuotaHistorySnapshot(hours),
			"now":      time.Now(),
		})
	}
}

// bindingsWindow is the per-window JSON returned by the bindings
// reverse-index endpoint. Each entry represents ONE Codex chat window
// — i.e. all cache rows that share the same UUID, with thread/window
// kinds folded together. Operators reading "ikedamiku04 holds 3
// windows" should see exactly 3 of these regardless of how many
// thread/window pairs the cache stores internally.
//
// Closed/ClosedAt/ForkedTo carry the fork-detection marker — when a
// Codex /new turn arrived carrying forked_from_thread_id pointing at
// this UUID, we recorded the close. ForkedTo holds the replacement
// thread_id so the panel can show "→ <new uuid>".
type bindingsWindow struct {
	UUID      string `json:"uuid"`
	Kind      string `json:"kind"` // "thread", "window", or "both"
	Workspace string `json:"workspace,omitempty"`
	ExpiresAt string `json:"expires_at"`
	Closed    bool   `json:"closed,omitempty"`
	ClosedAt  string `json:"closed_at,omitempty"`
	ForkedTo  string `json:"forked_to,omitempty"`
}

// bindingsAccount aggregates every window currently bound to one auth.
// WindowsCount is the total live entries; ActiveCount and ClosedCount
// split them so the UI can render "2 active + 3 closed" — observe-only
// view today (closed entries still count toward LeastBoundSelector's
// distribution decisions).
type bindingsAccount struct {
	AuthID       string           `json:"auth_id"`
	AuthLabel    string           `json:"auth_label,omitempty"`
	Provider     string           `json:"provider,omitempty"`
	WindowsCount int              `json:"windows_count"`
	ActiveCount  int              `json:"active_count"`
	ClosedCount  int              `json:"closed_count"`
	Windows      []bindingsWindow `json:"windows"`
}

// parseCacheSessionKey splits "mixed::codex-thread:<uuid>" into
// ("codex-thread", "<uuid>"). Returns ok=false for keys whose shape
// the bindings panel cannot meaningfully render (msg:<hash> content-
// hash fallbacks, malformed entries). Callers degrade gracefully when
// ok=false by falling back to the raw key for display.
func parseCacheSessionKey(key string) (kind, id string, ok bool) {
	// Strip the leading provider prefix ("mixed::", "codex::", etc.).
	if idx := strings.Index(key, "::"); idx >= 0 {
		key = key[idx+2:]
	}
	colon := strings.Index(key, ":")
	if colon <= 0 {
		return "", "", false
	}
	prefix := key[:colon]
	id = key[colon+1:]
	if id == "" {
		return "", "", false
	}
	switch {
	case strings.EqualFold(prefix, "codex-thread"):
		return "thread", id, true
	case strings.EqualFold(prefix, "codex-window"):
		return "window", id, true
	default:
		// e.g. "msg:<hash>" content-hash fallbacks — keep them visible
		// as their own "kind" so operators can still see what's bound.
		return prefix, id, true
	}
}

// bindingsHandler renders the bindings reverse-index — one row per
// VS Code Codex window, grouped by auth_id, with workspace path
// inlined when known. Folds thread+window cache pairs of the same
// UUID into a single row (kind="both") because they represent the
// same conversation from the operator's POV.
func bindingsHandler(reg *Registry, bindingsFunc BindingsByAuthFunc, authLookup AuthLabelLookup) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := bindingsFunc()
		workspaces := reg.SessionWorkspaceSnapshot()
		accounts := make([]bindingsAccount, 0, len(raw))
		for authID, entries := range raw {
			// Per-UUID accumulator: kinds set + latest expires_at.
			// A UUID is treated as closed only when EVERY underlying
			// cache row (thread + window of the same UUID) carries the
			// closed flag — that way a stale window mirror that wasn't
			// reached by the fork signal cannot mask the close.
			perUUID := make(map[string]*bindingsWindow, len(entries))
			perUUIDOpen := make(map[string]int, len(entries))
			for _, e := range entries {
				kind, id, okParse := parseCacheSessionKey(e.SessionKey)
				if !okParse {
					continue
				}
				w := perUUID[id]
				if w == nil {
					w = &bindingsWindow{UUID: id, Workspace: workspaces[id], Closed: true}
					perUUID[id] = w
				}
				if !e.Closed {
					perUUIDOpen[id]++
				} else if w.ForkedTo == "" && e.ForkedTo != "" {
					w.ForkedTo = e.ForkedTo
				}
				if e.Closed && !e.ClosedAt.IsZero() {
					closedAt := e.ClosedAt.UTC().Format(time.RFC3339Nano)
					if w.ClosedAt == "" || closedAt > w.ClosedAt {
						w.ClosedAt = closedAt
					}
				}
				switch {
				case w.Kind == "":
					w.Kind = kind
				case w.Kind == kind:
					// no change
				case (w.Kind == "thread" && kind == "window") || (w.Kind == "window" && kind == "thread"):
					w.Kind = "both"
				}
				expires := e.ExpiresAt.UTC().Format(time.RFC3339Nano)
				if w.ExpiresAt == "" || expires > w.ExpiresAt {
					w.ExpiresAt = expires
				}
			}
			if len(perUUID) == 0 {
				continue
			}
			windows := make([]bindingsWindow, 0, len(perUUID))
			activeCount := 0
			closedCount := 0
			for uuid, w := range perUUID {
				// A window stays "active" as long as ANY of its
				// underlying cache rows (thread or window key) is not
				// closed. Only when every row is closed do we report
				// the UUID itself as closed.
				if perUUIDOpen[uuid] > 0 {
					w.Closed = false
					w.ClosedAt = ""
					w.ForkedTo = ""
				}
				if w.Closed {
					closedCount++
				} else {
					activeCount++
				}
				windows = append(windows, *w)
			}
			// Stable ordering: active first, then closed; within each
			// group by expires_at desc, then by UUID.
			sort.Slice(windows, func(i, j int) bool {
				if windows[i].Closed != windows[j].Closed {
					return !windows[i].Closed // active first
				}
				if windows[i].ExpiresAt != windows[j].ExpiresAt {
					return windows[i].ExpiresAt > windows[j].ExpiresAt
				}
				return windows[i].UUID < windows[j].UUID
			})
			acc := bindingsAccount{
				AuthID:       authID,
				WindowsCount: len(windows),
				ActiveCount:  activeCount,
				ClosedCount:  closedCount,
				Windows:      windows,
			}
			if authLookup != nil {
				if label, provider, _, ok := authLookup(authID); ok {
					acc.AuthLabel = label
					acc.Provider = provider
				}
			}
			accounts = append(accounts, acc)
		}
		// Most ACTIVE accounts first; closed-heavy ones settle below.
		// Tie-break by total windows count, then by ID for stability.
		// Sorting by active first matches operator intent: "what's
		// holding live conversations" outranks "what has old history".
		sort.Slice(accounts, func(i, j int) bool {
			if accounts[i].ActiveCount != accounts[j].ActiveCount {
				return accounts[i].ActiveCount > accounts[j].ActiveCount
			}
			if accounts[i].WindowsCount != accounts[j].WindowsCount {
				return accounts[i].WindowsCount > accounts[j].WindowsCount
			}
			return accounts[i].AuthID < accounts[j].AuthID
		})
		c.JSON(http.StatusOK, gin.H{
			"accounts": accounts,
			"now":      time.Now(),
		})
	}
}

func historyHandler(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 50
		if v := strings.TrimSpace(c.Query("limit")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"records": reg.History(limit),
			"now":     time.Now(),
		})
	}
}

// QueryKeyToAuthHeader copies a ?key=... query parameter into the Authorization
// header so that SSE clients (which cannot set custom headers) can authenticate
// against the same middleware as regular API calls.
func QueryKeyToAuthHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" && c.GetHeader("X-Management-Key") == "" {
			if key := strings.TrimSpace(c.Query("key")); key != "" {
				c.Request.Header.Set("Authorization", "Bearer "+key)
			}
		}
		c.Next()
	}
}

func listHandler(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"entries": reg.Snapshot(),
			"now":     time.Now(),
		})
	}
}

func cancelHandler(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.Param("id"))
		if id == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing id"})
			return
		}
		by := strings.TrimSpace(c.GetHeader("X-Cancelled-By"))
		if by == "" {
			by = c.ClientIP()
		}
		if ok := reg.Cancel(id, by, ReasonManual); !ok {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "request not found or already finished"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "canceling", "id": id})
	}
}

func streamHandler(reg *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Header().Set("X-Accel-Buffering", "no")
		c.Writer.WriteHeader(http.StatusOK)

		flusher, ok := c.Writer.(http.Flusher)
		if !ok {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		events, unsubscribe := reg.Subscribe()
		defer unsubscribe()

		flushEvent := func(ev Event) bool {
			payload, err := json.Marshal(ev)
			if err != nil {
				return true
			}
			if _, err := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", ev.Type, payload); err != nil {
				return false
			}
			flusher.Flush()
			return true
		}

		// Initial heartbeat so clients know the stream is alive.
		fmt.Fprintf(c.Writer, ": connected\n\n")
		flusher.Flush()

		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		ctx := c.Request.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				if !flushEvent(ev) {
					return
				}
			case <-ticker.C:
				if _, err := fmt.Fprintf(c.Writer, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
