package management

import (
        "context"
        "testing"

        "github.com/gin-gonic/gin"
        "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
        coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestListAuthFiles_IncludesConfigSourcedOpenCode(t *testing.T) {
        t.Setenv("MANAGEMENT_PASSWORD", "")
        gin.SetMode(gin.TestMode)

        manager := coreauth.NewManager(nil, nil, nil)
        record := &coreauth.Auth{
                ID:       "openai-compatibility:opencode:abc123def456",
                Provider: "opencode",
                Label:    "opencode",
                Status:   coreauth.StatusActive,
                Attributes: map[string]string{
                        "source":       "config:opencode[abc123def456]",
                        "base_url":     "https://opencode.ai/zen/v1",
                        "compat_name":  "opencode",
                        "provider_key": "opencode",
                        "api_key":      "sk-test",
                },
        }
        if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
                t.Fatalf("failed to register auth record: %v", errRegister)
        }

        h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
        h.tokenStore = &memoryAuthStore{}

        entry := firstAuthFileEntry(t, h)
        if got := entry["id"]; got != record.ID {
                t.Fatalf("expected id %q, got %#v", record.ID, got)
        }
        if got := entry["provider"]; got != "opencode" {
                t.Fatalf("expected provider %q, got %#v", "opencode", got)
        }
        if got := entry["source"]; got != "config" {
                t.Fatalf("expected source %q, got %#v", "config", got)
        }
}