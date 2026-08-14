package management

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// TestRejectConfigKeyDrop_EmptyPath verifies the guard is a no-op when the
// handler has no config path (SDK/test harness mode).
func TestRejectConfigKeyDrop_EmptyPath(t *testing.T) {
	t.Parallel()
	h := &Handler{}
	if err := h.rejectConfigKeyDrop([]byte("port: 1\n")); err != nil {
		t.Fatalf("empty path should skip the guard, got err=%v", err)
	}
}

// TestRejectConfigKeyDrop_MissingDiskFile verifies the guard allows a write
// when there is no config on disk yet (fresh install / first write).
func TestRejectConfigKeyDrop_MissingDiskFile(t *testing.T) {
	t.Parallel()
	h := &Handler{configFilePath: filepath.Join(t.TempDir(), "nope.yaml")}
	if err := h.rejectConfigKeyDrop([]byte("port: 1\n")); err != nil {
		t.Fatalf("missing disk config should skip the guard, got err=%v", err)
	}
}

// TestRejectConfigKeyDrop_MissingKeys verifies the core protection: a
// submitted document that drops top-level keys present on disk is refused,
// and the error names the missing keys (the 2026-08-13 regression case).
func TestRejectConfigKeyDrop_MissingKeys(t *testing.T) {
	t.Parallel()
	disk := "port: 8317\nauto-release-on-429: true\ncodex:\n  identity-confuse: true\npayload:\n  filter: []\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(disk), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Handler{configFilePath: path}

	// Full copy: allowed.
	if err := h.rejectConfigKeyDrop([]byte(disk)); err != nil {
		t.Fatalf("complete config should pass, got err=%v", err)
	}

	// Template/legacy shape missing several live keys: refused, and the
	// message lists every dropped key so the caller knows what to restore.
	submitted := "port: 8317\n"
	err := h.rejectConfigKeyDrop([]byte(submitted))
	if err == nil {
		t.Fatal("expected refusal for config missing top-level keys, got nil")
	}
	for _, key := range []string{"auto-release-on-429", "codex", "payload"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error should mention dropped key %q, got: %v", key, err)
		}
	}
}

// TestPutConfigYAML_RejectsKeyDropEndToEnd verifies the guard wires into the
// HTTP handler: a PUT that drops a top-level key returns 422 and leaves the
// on-disk config untouched.
func TestPutConfigYAML_RejectsKeyDropEndToEnd(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	disk := "port: 8317\nauto-release-on-429: true\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(disk), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: &config.Config{}, configFilePath: path}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/v0/management/config.yaml", strings.NewReader("port: 8317\n"))

	h.PutConfigYAML(c)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != disk {
		t.Fatalf("disk config was modified on refused PUT:\n got: %q\nwant: %q", string(after), disk)
	}
}

// TestPutConfigYAML_AcceptsCompleteConfig verifies the normal management
// editor flow still works: submitting the full current config succeeds and
// the updated content lands on disk.
func TestPutConfigYAML_AcceptsCompleteConfig(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	disk := "port: 8317\nauto-release-on-429: true\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(disk), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: &config.Config{}, configFilePath: path}

	updated := "port: 8318\nauto-release-on-429: true\n"
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/v0/management/config.yaml", strings.NewReader(updated))

	h.PutConfigYAML(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "port: 8318") {
		t.Fatalf("disk config not updated, got: %q", string(after))
	}
}
