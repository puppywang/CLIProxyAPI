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

// TestClientModelUnsupported_ClearedOnReRegister is the free→plus plan-upgrade
// path: an account that previously learned it cannot serve sol must become
// selectable again as soon as RegisterClient re-advertises sol in its catalog
// (the synthesizer re-registers after plan_type flips). Waiting out the 12h
// TTL is not acceptable for an operator-driven upgrade.
func TestClientModelUnsupported_ClearedOnReRegister(t *testing.T) {
	r := newTestModelRegistry()
	r.RegisterClient("c-upgrade", "codex", []*ModelInfo{{ID: "m-terra"}})
	r.MarkClientModelUnsupported("c-upgrade", "m-sol")
	if !r.IsClientModelUnsupported("c-upgrade", "m-sol") {
		t.Fatal("precondition: account should be marked unsupported for sol")
	}

	// Re-register with sol now in the catalog (plan upgraded to plus).
	r.RegisterClient("c-upgrade", "codex", []*ModelInfo{
		{ID: "m-terra"},
		{ID: "m-sol"},
	})
	if r.IsClientModelUnsupported("c-upgrade", "m-sol") {
		t.Fatal("re-registering sol in the catalog must clear the learned unsupported flag")
	}
	if !r.ClientSupportsModel("c-upgrade", "m-sol") {
		t.Fatal("re-registered client must support sol")
	}
}

// TestClearClientModelUnsupported verifies the explicit admin/operator clear
// path used when plan_type is patched without a full re-registration cycle.
func TestClearClientModelUnsupported(t *testing.T) {
	r := newTestModelRegistry()
	r.RegisterClient("c1", "codex", []*ModelInfo{{ID: "m-sol"}, {ID: "m-terra"}})
	r.MarkClientModelUnsupported("c1", "m-sol")
	r.MarkClientModelUnsupported("c1", "m-terra")

	r.ClearClientModelUnsupported("c1", "m-sol")
	if r.IsClientModelUnsupported("c1", "m-sol") {
		t.Error("ClearClientModelUnsupported must drop the sol flag")
	}
	if !r.IsClientModelUnsupported("c1", "m-terra") {
		t.Error("ClearClientModelUnsupported must not touch other models")
	}

	r.ClearAllClientModelUnsupported("c1")
	if r.IsClientModelUnsupported("c1", "m-terra") {
		t.Error("ClearAllClientModelUnsupported must drop every flag for the client")
	}
}
