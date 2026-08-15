package config

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWeightZeroPointerSerialization(t *testing.T) {
	zero := 0
	five := 5
	entry := OpenAICompatibilityAPIKey{
		APIKey: "k1",
		Weight: &zero,
	}
	entry2 := OpenAICompatibilityAPIKey{
		APIKey: "k2",
		Weight: &five,
	}
	list := []OpenAICompatibilityAPIKey{entry, entry2}

	yamlData, err := yaml.Marshal(map[string]any{"api-key-entries": list})
	if err != nil {
		t.Fatalf("yaml.Marshal error: %v", err)
	}
	t.Logf("yaml output:\n%s", string(yamlData))

	jsonData, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	t.Logf("json output: %s", string(jsonData))

	if !contains(string(yamlData), "weight: 0") {
		t.Errorf("yaml output missing weight: 0\n%s", string(yamlData))
	}
	if !contains(string(jsonData), `"weight":0`) {
		t.Errorf("json output missing weight:0\n%s", string(jsonData))
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
