package registry

import "testing"

// TestClientModelUnsupported_DurableAcrossResume is the regression guard for
// the "flag reset on every downgraded success" bug: the learned
// model_not_supported flag lives in a separate store from SuspendedClients, so
// ResumeClientModel (which the conductor runs when a transparently-downgraded
// request looks like a success for the original model) must NOT clear it. It is
// also not confused with a transient quota suspension.
func TestClientModelUnsupported_DurableAcrossResume(t *testing.T) {
	r := newTestModelRegistry()
	r.RegisterClient("c-nosol", "codex", []*ModelInfo{{ID: "m-sol"}})
	r.RegisterClient("c-quota", "codex", []*ModelInfo{{ID: "m-sol"}})

	r.MarkClientModelUnsupported("c-nosol", "m-sol")
	if !r.IsClientModelUnsupported("c-nosol", "m-sol") {
		t.Fatal("marked client should report unsupported=true")
	}

	// A transient (quota) suspension must NOT count as unsupported.
	r.SuspendClientModel("c-quota", "m-sol", "quota")
	if r.IsClientModelUnsupported("c-quota", "m-sol") {
		t.Error("quota-suspended client must report unsupported=false (separate store)")
	}

	// The crux: a Suspend+Resume cycle on the marked client (what the conductor
	// does on a downgraded 'success') must leave the learned flag intact.
	r.SuspendClientModel("c-nosol", "m-sol", "quota")
	r.ResumeClientModel("c-nosol", "m-sol")
	if !r.IsClientModelUnsupported("c-nosol", "m-sol") {
		t.Error("ResumeClientModel must NOT clear the durable model_not_supported flag")
	}

	// Unknown client / other model are not flagged.
	if r.IsClientModelUnsupported("c-unknown", "m-sol") {
		t.Error("unmarked client must report unsupported=false")
	}
	if r.IsClientModelUnsupported("c-nosol", "m-other") {
		t.Error("different model must report unsupported=false")
	}
}
