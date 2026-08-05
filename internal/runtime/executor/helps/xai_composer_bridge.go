package helps

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// bridgeDescribeConcurrency bounds how many images are described in parallel
// so a request with many images cannot fan out unboundedly against a single
// account. Typical requests carry 1-2 images.
const bridgeDescribeConcurrency = 4

// composerBridgeDescribePrompt instructs the vision model to produce a
// CONCISE description a downstream text-only coding model can act on. Kept
// deliberately short (and paired with a max_output_tokens cap) because this
// describe call is a blocking pre-step in front of the composer request — a
// verbose "transcribe everything in thorough detail" prompt made the vision
// model emit a long, slow response. This mirrors the reference sub2api
// implementation's concise prompt.
const composerBridgeDescribePrompt = "Describe this image in concise, factual text for a downstream coding/composer model that cannot see it. " +
	"Include any visible text (transcribe code and error messages), UI elements, diagrams, and spatial relationships. " +
	"Output only the description; do not mention that you are describing an image."

// IsGrokComposerModel reports whether a model id is a Grok "composer" model.
// Composer models reject image input upstream ("this model does not support
// image input"), which is what the bridge works around.
func IsGrokComposerModel(model string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(model)), "composer")
}

// BridgeComposerImages rewrites a Responses-format request body so a composer
// model (which upstream rejects image input for) can carry image content:
// every input_image part is replaced with an input_text part holding a
// description produced by visionModel via the same /responses endpoint. It
// returns the possibly-modified body and the number of images bridged. A body
// with no image parts is returned unchanged with count 0.
//
// A vision-call failure is returned as an error so the caller can fail the
// request explicitly rather than silently forwarding an image the composer
// will reject anyway.
func BridgeComposerImages(ctx context.Context, client *http.Client, responsesURL, token, visionModel string, maxTokens int, body []byte) ([]byte, int, error) {
	input := gjson.GetBytes(body, "input")
	if !input.IsArray() {
		return body, 0, nil
	}

	// Collect targets first so we do not mutate the body while iterating the
	// gjson view of it. Replacement never changes array lengths, so the
	// (itemIdx, contentIdx) paths stay valid across substitutions.
	type target struct {
		itemIdx    int
		contentIdx int
		imageRaw   string
	}
	var targets []target
	input.ForEach(func(i, item gjson.Result) bool {
		content := item.Get("content")
		if !content.IsArray() {
			return true
		}
		content.ForEach(func(j, part gjson.Result) bool {
			if part.Get("type").String() == "input_image" {
				if iu := part.Get("image_url"); iu.Exists() {
					targets = append(targets, target{itemIdx: int(i.Int()), contentIdx: int(j.Int()), imageRaw: iu.Raw})
				}
			}
			return true
		})
		return true
	})
	if len(targets) == 0 {
		return body, 0, nil
	}

	// Describe every image concurrently. The calls are independent and this
	// whole bridge is a blocking pre-step in front of the composer request,
	// so describing serially would stack each image's (multi-second) latency.
	descriptions := make([]string, len(targets))
	describeErrs := make([]error, len(targets))
	sem := make(chan struct{}, bridgeDescribeConcurrency)
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			descriptions[i], describeErrs[i] = describeComposerImage(ctx, client, responsesURL, token, visionModel, maxTokens, targets[i].imageRaw)
		}(i)
	}
	wg.Wait()
	for i := range targets {
		if describeErrs[i] != nil {
			return body, 0, fmt.Errorf("composer image bridge: %w", describeErrs[i])
		}
	}
	for i, t := range targets {
		replacement, _ := sjson.SetBytes([]byte(`{"type":"input_text"}`), "text",
			fmt.Sprintf("[Image content, described by %s because this model cannot read images]:\n%s", visionModel, descriptions[i]))
		path := fmt.Sprintf("input.%d.content.%d", t.itemIdx, t.contentIdx)
		body, _ = sjson.SetRawBytes(body, path, replacement)
	}
	log.Debugf("xai composer bridge: replaced %d image part(s) with %s descriptions", len(targets), visionModel)
	return body, len(targets), nil
}

// describeComposerImage sends a single image to the vision model via the
// /responses endpoint and returns the concatenated output text. It preserves
// the caller's exact image_url representation (data URL string or object) by
// splicing its raw JSON into the vision request. The call is non-streaming
// with a bounded max_output_tokens so it stays fast (it blocks the composer
// request behind it); store=false avoids persisting the throwaway describe
// turn upstream. Matches the reference sub2api bridge.
func describeComposerImage(ctx context.Context, client *http.Client, responsesURL, token, visionModel string, maxTokens int, imageRaw string) (string, error) {
	reqBody := []byte(`{"stream":false,"store":false}`)
	reqBody, _ = sjson.SetBytes(reqBody, "model", visionModel)
	if maxTokens > 0 {
		reqBody, _ = sjson.SetBytes(reqBody, "max_output_tokens", maxTokens)
	}
	reqBody, _ = sjson.SetBytes(reqBody, "input.0.type", "message")
	reqBody, _ = sjson.SetBytes(reqBody, "input.0.role", "user")
	reqBody, _ = sjson.SetBytes(reqBody, "input.0.content.0.type", "input_text")
	reqBody, _ = sjson.SetBytes(reqBody, "input.0.content.0.text", composerBridgeDescribePrompt)
	reqBody, _ = sjson.SetBytes(reqBody, "input.0.content.1.type", "input_image")
	reqBody, _ = sjson.SetRawBytes(reqBody, "input.0.content.1.image_url", []byte(imageRaw))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, responsesURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("xai composer bridge: close response body error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("vision model %s returned status %d: %s", visionModel, resp.StatusCode, truncateBridge(data, 200))
	}
	return parseResponsesOutputText(data)
}

// parseResponsesOutputText extracts the assistant text from a Responses-format
// reply. It handles both shapes: a non-streaming JSON object (stream:false,
// the default path here) and an SSE stream (accumulating
// response.output_text.delta, falling back to the response.completed payload).
// This keeps it robust whether the backend honours stream:false or streams.
func parseResponsesOutputText(data []byte) (string, error) {
	var sb strings.Builder
	var completed gjson.Result
	sawSSE := false
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		sawSSE = true
		event := bytes.TrimSpace(line[len("data:"):])
		switch gjson.GetBytes(event, "type").String() {
		case "response.output_text.delta":
			sb.WriteString(gjson.GetBytes(event, "delta").String())
		case "response.completed":
			completed = gjson.GetBytes(event, "response")
		}
	}
	if sb.Len() == 0 {
		// Choose the output source: the SSE completed payload, or — for a
		// non-streaming reply — the whole JSON body.
		src := completed
		if !src.Exists() && !sawSSE {
			src = gjson.ParseBytes(data)
		}
		src.Get("output").ForEach(func(_, item gjson.Result) bool {
			item.Get("content").ForEach(func(_, part gjson.Result) bool {
				switch part.Get("type").String() {
				case "output_text", "text":
					sb.WriteString(part.Get("text").String())
				}
				return true
			})
			return true
		})
	}
	out := strings.TrimSpace(sb.String())
	if out == "" {
		return "", fmt.Errorf("vision model returned no description")
	}
	return out, nil
}

func truncateBridge(payload []byte, max int) string {
	if len(payload) <= max {
		return string(payload)
	}
	return string(payload[:max]) + "..."
}
