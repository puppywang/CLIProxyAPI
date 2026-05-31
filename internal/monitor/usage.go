package monitor

import (
	"bytes"
	"sync/atomic"

	"github.com/tidwall/gjson"
)

// usagePathSet groups gjson paths by token role. Each chunk is scanned and the
// largest non-zero value observed across all matching paths is kept — the
// final upstream chunk typically carries the most complete totals.
type usagePathSet struct {
	input  []string
	output []string
	total  []string
}

// usageMarkers are quick substring checks; if none match the chunk we skip the
// (relatively expensive) gjson scan entirely.
var usageMarkers = [][]byte{
	[]byte(`"usage"`),
	[]byte(`"usageMetadata"`),
}

// Multi-provider usage paths. gjson returns the first occurrence for each path
// scanned over the entire chunk, which is sufficient since providers normally
// embed usage in exactly one frame per response.
var usagePaths = usagePathSet{
	input: []string{
		"usage.input_tokens",                    // OpenAI Responses / Codex
		"usage.prompt_tokens",                   // OpenAI Chat Completions
		"response.usage.input_tokens",           // OpenAI Responses stream wrapper
		"message.usage.input_tokens",            // Anthropic message_start
		"usageMetadata.promptTokenCount",        // Gemini
		"usageMetadata.cachedContentTokenCount", // Gemini (informational; not added)
	},
	output: []string{
		"usage.output_tokens",                // OpenAI Responses / Codex / Anthropic delta
		"usage.completion_tokens",            // OpenAI Chat Completions
		"response.usage.output_tokens",       // OpenAI Responses stream wrapper
		"message.usage.output_tokens",        // Anthropic message_start
		"usageMetadata.candidatesTokenCount", // Gemini
	},
	total: []string{
		"usage.total_tokens",
		"response.usage.total_tokens",
		"usageMetadata.totalTokenCount",
	},
}

// ExtractUsage scans a response chunk for token usage information and updates
// the tracked entry monotonically: a value is only adopted if it strictly
// exceeds the currently stored count. Returns true if any field changed.
func (r *Registry) ExtractUsage(t *trackedRequest, chunk []byte) bool {
	if t == nil || len(chunk) == 0 {
		return false
	}
	// Fast path: skip chunks that clearly contain no usage payload.
	matched := false
	for _, marker := range usageMarkers {
		if bytes.Contains(chunk, marker) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	in := maxFromPaths(chunk, usagePaths.input)
	out := maxFromPaths(chunk, usagePaths.output)
	tot := maxFromPaths(chunk, usagePaths.total)

	changed := false
	if in > 0 && bumpAtomicTo(&t.inputTokens, in) {
		changed = true
	}
	if out > 0 && bumpAtomicTo(&t.outputTokens, out) {
		changed = true
	}
	if tot > 0 && bumpAtomicTo(&t.totalTokens, tot) {
		changed = true
	}
	if changed {
		r.broadcast(Event{Type: "updated", Entry: t.snapshot()})
	}
	return changed
}

func maxFromPaths(chunk []byte, paths []string) int64 {
	var best int64
	for _, p := range paths {
		v := gjson.GetBytes(chunk, p)
		if !v.Exists() {
			continue
		}
		n := v.Int()
		if n > best {
			best = n
		}
	}
	return best
}

// bumpAtomicTo updates the atomic counter only when the new value is larger.
func bumpAtomicTo(dst *atomic.Int64, v int64) bool {
	for {
		cur := dst.Load()
		if v <= cur {
			return false
		}
		if dst.CompareAndSwap(cur, v) {
			return true
		}
	}
}
