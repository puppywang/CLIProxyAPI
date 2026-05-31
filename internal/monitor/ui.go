package monitor

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed ui.html
var uiHTML []byte

// ServeUI returns a Gin handler that serves the bundled monitor HTML page.
// The page itself is unauthenticated; its JavaScript prompts for the
// management key and uses it as a Bearer token against the protected
// monitor API endpoints.
func ServeUI() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Cache-Control", "no-store")
		c.Status(http.StatusOK)
		_, _ = c.Writer.Write(uiHTML)
	}
}
