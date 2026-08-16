package auth

import (
        "context"
        "os"
        "path/filepath"
        "testing"
)

// TestFileTokenStoreListSkipsSystemFiles verifies that internal system files
// living in the auth dir (session-affinity cache, round-robin cursor) are not
// surfaced as credentials in List(). They have no "type" field, so without the
// skip they would appear as type=unknown "accounts" in the operator UI.
func TestFileTokenStoreListSkipsSystemFiles(t *testing.T) {
        dir := t.TempDir()

        // Real credential
        if err := os.WriteFile(filepath.Join(dir, "codex-user.json"), []byte(`{"type":"codex","email":"user@example.com"}`), 0o600); err != nil {
                t.Fatalf("write credential: %v", err)
        }
        // System files that must be ignored
        if err := os.WriteFile(filepath.Join(dir, "session-affinity-cache.json"), []byte(`{"version":1,"entries":{}}`), 0o600); err != nil {
                t.Fatalf("write session-affinity-cache: %v", err)
        }
        if err := os.WriteFile(filepath.Join(dir, "round-robin-cursor.json"), []byte(`{"version":1,"cursors":{}}`), 0o600); err != nil {
                t.Fatalf("write round-robin-cursor: %v", err)
        }

        store := NewFileTokenStore()
        store.SetBaseDir(dir)

        auths, err := store.List(context.Background())
        if err != nil {
                t.Fatalf("List: %v", err)
        }
        if len(auths) != 1 {
                t.Fatalf("expected 1 auth, got %d", len(auths))
        }
        if auths[0].ID != "codex-user.json" {
                t.Fatalf("expected codex-user.json, got %q", auths[0].ID)
        }
}