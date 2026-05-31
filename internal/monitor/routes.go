package monitor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes attaches monitor endpoints to the given router group. The
// group is expected to already have any necessary auth middleware attached.
func RegisterRoutes(group *gin.RouterGroup, reg *Registry) {
	if group == nil || reg == nil {
		return
	}
	group.GET("/in-flight", listHandler(reg))
	group.GET("/in-flight/stream", streamHandler(reg))
	group.POST("/in-flight/:id/cancel", cancelHandler(reg))
	group.GET("/in-flight/settings", settingsGetHandler(reg))
	group.PUT("/in-flight/settings", settingsPutHandler(reg))
	group.GET("/in-flight/history", historyHandler(reg))
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
