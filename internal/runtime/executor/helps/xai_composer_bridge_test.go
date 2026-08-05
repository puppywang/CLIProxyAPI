package helps

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func visionSSEHandler(delta string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\""+delta+"\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{}}\n\n")
	}
}

func TestIsGrokComposerModel(t *testing.T) {
	cases := map[string]bool{
		"grok-composer-2.5-fast": true,
		"grok-composer":          true,
		"GROK-COMPOSER":          true,
		"grok-4":                 false,
		"grok-build-0.1":         false,
		"":                       false,
	}
	for model, want := range cases {
		if got := IsGrokComposerModel(model); got != want {
			t.Errorf("IsGrokComposerModel(%q) = %v, want %v", model, got, want)
		}
	}
}

func TestBridgeComposerImages_ReplacesImageWithDescription(t *testing.T) {
	srv := httptest.NewServer(visionSSEHandler("A red cat on a mat."))
	defer srv.Close()

	body := []byte(`{"model":"grok-composer-2.5-fast","input":[{"role":"user","content":[` +
		`{"type":"input_text","text":"what is this"},` +
		`{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}]}`)

	out, n, err := BridgeComposerImages(context.Background(), srv.Client(), srv.URL, "tok", "grok-build-0.1", 512, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 image bridged, got %d", n)
	}
	part := gjson.GetBytes(out, "input.0.content.1")
	if part.Get("type").String() != "input_text" {
		t.Errorf("expected content.1 type input_text, got %q", part.Get("type").String())
	}
	if part.Get("image_url").Exists() {
		t.Errorf("expected image_url removed, still present")
	}
	if !strings.Contains(part.Get("text").String(), "A red cat on a mat.") {
		t.Errorf("expected description in text, got %q", part.Get("text").String())
	}
	// The sibling text part must be untouched.
	if gjson.GetBytes(out, "input.0.content.0.text").String() != "what is this" {
		t.Errorf("sibling text part was altered")
	}
}

func TestBridgeComposerImages_NoImagesUnchanged(t *testing.T) {
	// Server that would fail the test if called.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("vision endpoint should not be called for an image-free request")
	}))
	defer srv.Close()

	body := []byte(`{"model":"grok-composer","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}`)
	out, n, err := BridgeComposerImages(context.Background(), srv.Client(), srv.URL, "tok", "grok-build-0.1", 512, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 images, got %d", n)
	}
	if string(out) != string(body) {
		t.Errorf("body should be unchanged")
	}
}

func TestBridgeComposerImages_MultipleImages(t *testing.T) {
	srv := httptest.NewServer(visionSSEHandler("desc"))
	defer srv.Close()

	body := []byte(`{"input":[{"role":"user","content":[` +
		`{"type":"input_image","image_url":"data:1"},` +
		`{"type":"input_text","text":"mid"},` +
		`{"type":"input_image","image_url":"data:2"}]}]}`)
	out, n, err := BridgeComposerImages(context.Background(), srv.Client(), srv.URL, "tok", "grok-build-0.1", 512, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 images bridged, got %d", n)
	}
	if gjson.GetBytes(out, "input.0.content.0.type").String() != "input_text" ||
		gjson.GetBytes(out, "input.0.content.2.type").String() != "input_text" {
		t.Errorf("both image parts should now be input_text")
	}
	if gjson.GetBytes(out, "input.0.content.1.text").String() != "mid" {
		t.Errorf("middle text part must be preserved")
	}
}

func TestBridgeComposerImages_NonStreamingJSON(t *testing.T) {
	// stream:false path — the vision model returns a single Responses JSON
	// object rather than an SSE stream.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output":[{"type":"message","content":[{"type":"output_text","text":"A login screen."}]}]}`)
	}))
	defer srv.Close()

	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:1"}]}]}`)
	out, n, err := BridgeComposerImages(context.Background(), srv.Client(), srv.URL, "tok", "grok-build-0.1", 512, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 image bridged, got %d", n)
	}
	if !strings.Contains(gjson.GetBytes(out, "input.0.content.0.text").String(), "A login screen.") {
		t.Errorf("expected JSON output_text in description, got %q", gjson.GetBytes(out, "input.0.content.0.text").String())
	}
}

func TestBridgeComposerImages_VisionErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	defer srv.Close()

	body := []byte(`{"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:1"}]}]}`)
	_, _, err := BridgeComposerImages(context.Background(), srv.Client(), srv.URL, "tok", "grok-build-0.1", 512, body)
	if err == nil {
		t.Fatal("expected an error when the vision model fails")
	}
}
