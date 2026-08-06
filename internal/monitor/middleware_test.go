package monitor

import (
	"bytes"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// chunkedRequest builds a gin context whose request body carries no declared
// length, mirroring a chunked-transfer POST (ContentLength -1). httptest.NewRequest
// derives a length from *bytes.Reader, so the body is wrapped to hide its size.
func chunkedRequest(body []byte) *gin.Context {
	req := httptest.NewRequest("POST", "/v1/chat/completions", io.NopCloser(bytes.NewReader(body)))
	req.ContentLength = -1
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	return c
}

// TestPeekModel_ChunkedOversizedBodyIsNotTruncated is the regression test for the
// 502 "unknown provider for model" storm on GitHub Copilot Chat requests
// (2026-08-06). Copilot posts chat completions with chunked encoding, so the
// declared-oversize branch never fires; the peek then buffered maxPeek+1 bytes and
// replaced the body with just that buffer, silently dropping everything past 1 MiB.
// The handler received JSON cut mid-array, found no "model", and 502'd.
func TestPeekModel_ChunkedOversizedBodyIsNotTruncated(t *testing.T) {
	// "model" deliberately sits AFTER the 1 MiB cut, which is how the real
	// failures presented: Copilot serializes messages before model.
	filler := strings.Repeat("x", (1<<20)+4096)
	body := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":%q}],"model":"deepseek-v4-flash-free"}`, filler))
	if len(body) <= (1<<20)+1 {
		t.Fatalf("test body must exceed the peek limit, got %d bytes", len(body))
	}

	c := chunkedRequest(body)
	peekModelAndWorkspaceFromRequest(c)

	got, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("restored body = %d bytes, want %d (%d bytes lost)", len(got), len(body), len(body)-len(got))
	}
	if !bytes.Equal(got, body) {
		t.Error("restored body differs from the original bytes")
	}
}

// TestPeekModel_ChunkedOversizedBodyStillReportsModel covers the monitor's own
// need: when the model appears within the peeked prefix it must still show up on
// the row even though the JSON is truncated and gjson cannot parse it.
func TestPeekModel_ChunkedOversizedBodyStillReportsModel(t *testing.T) {
	filler := strings.Repeat("x", (1<<20)+4096)
	body := []byte(fmt.Sprintf(`{"model":"deepseek-v4-flash-free","messages":[{"role":"user","content":%q}]}`, filler))

	c := chunkedRequest(body)
	model, _ := peekModelAndWorkspaceFromRequest(c)
	if model != "deepseek-v4-flash-free" {
		t.Errorf("model = %q, want deepseek-v4-flash-free", model)
	}
	got, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("restored body = %d bytes, want %d", len(got), len(body))
	}
}

// TestPeekModel_SmallBodyUnchanged pins the common path: a normal request still
// yields model + workspace and an intact body.
func TestPeekModel_SmallBodyUnchanged(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-luna","input":[{"content":[{"text":"<cwd>d:\\HomeProject\\x</cwd>"}]}]}`)
	c := chunkedRequest(body)

	model, workspace := peekModelAndWorkspaceFromRequest(c)
	if model != "gpt-5.6-luna" {
		t.Errorf("model = %q, want gpt-5.6-luna", model)
	}
	if workspace != `d:\HomeProject\x` {
		t.Errorf("workspace = %q, want d:\\HomeProject\\x", workspace)
	}
	got, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("restored body = %q, want the original", got)
	}
}

// TestPeekModel_DeclaredOversizeBodyIsNotTruncated covers the pre-existing
// large-body branch (Content-Length known and over the limit) for the same
// no-data-loss property.
func TestPeekModel_DeclaredOversizeBodyIsNotTruncated(t *testing.T) {
	filler := strings.Repeat("y", (1<<20)+1024)
	body := []byte(fmt.Sprintf(`{"model":"gpt-5.6-luna","messages":[{"role":"user","content":%q}]}`, filler))
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	req.ContentLength = int64(len(body)) // declared, and over maxPeek
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req

	model, _ := peekModelAndWorkspaceFromRequest(c)
	if model != "gpt-5.6-luna" {
		t.Errorf("model = %q, want gpt-5.6-luna", model)
	}
	got, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("restored body = %d bytes, want %d", len(got), len(body))
	}
}
