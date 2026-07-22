package registry

import "testing"

// TestIsClientModelUnsupported_ReasonScoped verifies the reason-scoped query:
// only a model_not_supported suspension makes IsClientModelUnsupported true,
// while a transient (e.g. "quota") suspension does not. This is what keeps the
// selector's soft isolation from over-excluding accounts that merely hit a 429.
func TestIsClientModelUnsupported_ReasonScoped(t *testing.T) {
	r := newTestModelRegistry()
	r.RegisterClient("c-nosol", "codex", []*ModelInfo{{ID: "m-sol"}})
	r.RegisterClient("c-quota", "codex", []*ModelInfo{{ID: "m-sol"}})
	r.SuspendClientModel("c-nosol", "m-sol", ModelNotSupportedReason)
	r.SuspendClientModel("c-quota", "m-sol", "quota")

	if !r.IsClientModelUnsupported("c-nosol", "m-sol") {
		t.Error("model_not_supported client should report unsupported=true")
	}
	if r.IsClientModelUnsupported("c-quota", "m-sol") {
		t.Error("quota-suspended client must report unsupported=false (reason-scoped)")
	}
	if r.IsClientModelUnsupported("c-unknown", "m-sol") {
		t.Error("unregistered client must report unsupported=false")
	}
	if r.IsClientModelUnsupported("c-nosol", "m-other") {
		t.Error("different model must report unsupported=false")
	}
	// IsClientModelSuspended stays reason-agnostic (both are suspended).
	if !r.IsClientModelSuspended("c-quota", "m-sol") || !r.IsClientModelSuspended("c-nosol", "m-sol") {
		t.Error("IsClientModelSuspended should be true for any suspension reason")
	}
	// Resuming clears both views.
	r.ResumeClientModel("c-nosol", "m-sol")
	if r.IsClientModelUnsupported("c-nosol", "m-sol") || r.IsClientModelSuspended("c-nosol", "m-sol") {
		t.Error("after ResumeClientModel the client must no longer be suspended/unsupported")
	}
}
