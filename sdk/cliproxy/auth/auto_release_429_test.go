package auth

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// bindingCountingSelector is a minimal Selector that records
// InvalidateAuthBindings calls so the auto-release-on-429 path can be
// observed without spinning up a full SessionAffinitySelector + cache.
type bindingCountingSelector struct {
	released int32
}

func (s *bindingCountingSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	return auths[0], nil
}

func (s *bindingCountingSelector) InvalidateAuthBindings(authID string) int {
	return int(atomic.AddInt32(&s.released, 1))
}

// TestMaybeConvert429To500_ToggleOffLeaves429Unchanged verifies the
// converter is a no-op when the global toggle is off — the default
// state, so existing behaviour is preserved unless an operator opts in.
func TestMaybeConvert429To500_ToggleOffLeaves429Unchanged(t *testing.T) {
	SetAutoReleaseOn429(false)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	err := &Error{Code: "quota", Message: "rate limited", HTTPStatus: http.StatusTooManyRequests}
	got := maybeConvert429To500(err)
	authErr, ok := got.(*Error)
	if !ok || authErr == nil {
		t.Fatalf("expected *Error, got %T", got)
	}
	if authErr.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("expected 429 preserved when toggle off, got %d", authErr.HTTPStatus)
	}
}

// TestMaybeConvert429To500_ToggleOnConvertsTo500 verifies the converter
// rewrites a 429 to 500 when the toggle is on, so the API layer (which
// consults StatusCode()) reports a retryable 500 to the client instead
// of a hard 429.
func TestMaybeConvert429To500_ToggleOnConvertsTo500(t *testing.T) {
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	err := &Error{Code: "quota", Message: "rate limited", HTTPStatus: http.StatusTooManyRequests}
	got := maybeConvert429To500(err)
	authErr, ok := got.(*Error)
	if !ok || authErr == nil {
		t.Fatalf("expected *Error, got %T", got)
	}
	if authErr.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("expected 500 after conversion, got %d", authErr.HTTPStatus)
	}
}

// TestMaybeConvert429To500_ToggleOnConverts402To500 verifies the
// converter also rewrites a 402 (Payment Required — e.g.
// deactivated_workspace) to 500 when the toggle is on. A 402 is just
// as fatal to the account as a 429, so the same transparent-failover
// treatment applies.
func TestMaybeConvert429To500_ToggleOnConverts402To500(t *testing.T) {
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	err := &Error{Code: "payment_required", Message: "deactivated_workspace", HTTPStatus: http.StatusPaymentRequired}
	got := maybeConvert429To500(err)
	authErr, ok := got.(*Error)
	if !ok || authErr == nil {
		t.Fatalf("expected *Error, got %T", got)
	}
	if authErr.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("expected 500 after conversion, got %d", authErr.HTTPStatus)
	}
}

// TestMaybeConvert429To500_ToggleOnConverts401To500 verifies the converter
// also rewrites a 401 (Unauthorized — dead/expired credential) to 500 when
// the toggle is on. A 401 credential never serves the bound conversation
// again (CPA files without a refresh_token can't recover), so it gets the
// same transparent-failover treatment as 429/402: the client retries onto a
// fresh account instead of seeing a hard 401 loop.
func TestMaybeConvert429To500_ToggleOnConverts401To500(t *testing.T) {
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	err := &Error{Code: "unauthorized", Message: "token revoked", HTTPStatus: http.StatusUnauthorized}
	got := maybeConvert429To500(err)
	authErr, ok := got.(*Error)
	if !ok || authErr == nil {
		t.Fatalf("expected *Error, got %T", got)
	}
	if authErr.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("expected 500 after conversion, got %d", authErr.HTTPStatus)
	}
}

// TestMaybeConvert429To500_OtherStatusUnchanged verifies statuses OTHER than
// 429/402/401 pass through untouched even when the toggle is on — we mask
// only the "this credential is done, move on" failures, not transient
// 404/503 that the client must see.
func TestMaybeConvert429To500_OtherStatusUnchanged(t *testing.T) {
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable, http.StatusBadGateway} {
		err := &Error{Code: "other", Message: "boom", HTTPStatus: status}
		got := maybeConvert429To500(err)
		authErr, ok := got.(*Error)
		if !ok || authErr == nil {
			t.Fatalf("expected *Error for status %d, got %T", status, got)
		}
		if authErr.HTTPStatus != status {
			t.Fatalf("expected status %d preserved, got %d", status, authErr.HTTPStatus)
		}
	}
}

// TestMaybeConvert429To500_OverloadStays429 verifies an upstream engine-overload
// 429 (e.g. Kimi's engine_overloaded_error) is surfaced as a retryable 429 even
// when the toggle is on: failing over to another credential of the same
// overloaded engine can't help, so the client should back off and retry rather
// than see a masked 500. A normal quota 429 must still convert.
func TestMaybeConvert429To500_OverloadStays429(t *testing.T) {
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	overload := &Error{
		Message:    `{"error":{"message":"The engine is currently overloaded, please try again later","type":"engine_overloaded_error"}}`,
		HTTPStatus: http.StatusTooManyRequests,
	}
	if got := maybeConvert429To500(overload).(*Error); got.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("expected overload 429 preserved, got %d", got.HTTPStatus)
	}

	normal := &Error{Code: "quota", Message: "rate limited", HTTPStatus: http.StatusTooManyRequests}
	if got := maybeConvert429To500(normal).(*Error); got.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("expected normal 429 -> 500, got %d", got.HTTPStatus)
	}
}

// TestMaybeConvert429To500_ModelCooldownStays429 verifies that a model_cooldown
// error (every credential for the model is cooling down) keeps its native 429
// and reset hint rather than being masked as a 500 — there is nothing to fail
// over to, so the client should back off for the reset window, not tight-loop.
func TestMaybeConvert429To500_ModelCooldownStays429(t *testing.T) {
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	err := newModelCooldownError("gpt-5.6-sol", "codex", 143*time.Hour)
	got := maybeConvert429To500(err)
	if statusCodeFromError(got) != http.StatusTooManyRequests {
		t.Fatalf("model_cooldown must stay 429, got status=%d (%T)", statusCodeFromError(got), got)
	}
	if !strings.Contains(got.Error(), "model_cooldown") || !strings.Contains(got.Error(), "reset_seconds") {
		t.Errorf("model_cooldown body/reset hint lost: %q", got.Error())
	}
}

// TestMaybeConvert429To500_UsageLimitStays429 verifies an upstream
// usage/quota-limit 429 (codex usage_limit_reached) surfaces as a retryable
// 429 rather than a 500 — the failover loop already tried every credential, so
// the client should back off per the reset, not hammer 500s. A generic quota
// 429 (no usage-limit / overload signal) must still convert to 500 to preserve
// session-affinity failover.
func TestMaybeConvert429To500_UsageLimitStays429(t *testing.T) {
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	usage := &Error{
		Message:    `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","plan_type":"plus","resets_in_seconds":515481}}`,
		HTTPStatus: http.StatusTooManyRequests,
	}
	if got := maybeConvert429To500(usage).(*Error); got.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("usage_limit_reached must stay 429, got %d", got.HTTPStatus)
	}
	generic := &Error{Code: "quota", Message: "rate limited", HTTPStatus: http.StatusTooManyRequests}
	if got := maybeConvert429To500(generic).(*Error); got.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("generic 429 must still convert to 500, got %d", got.HTTPStatus)
	}
}

// TestMarkResult_429AutoReleasesBindingsWhenToggleOn verifies the
// central guarantee of the auto-release feature: when the toggle is on,
// a 429 result triggers invalidateSessionAffinityCount for the failing
// auth, so its stranded conversations re-pick on the next turn. When
// off, no invalidation happens.
func TestMarkResult_429AutoReleasesBindingsWhenToggleOn(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	t.Cleanup(func() { reg.UnregisterClient("auth-429") })

	sel := &bindingCountingSelector{}
	m := NewManager(nil, sel, nil)
	m.SetRetryConfig(0, 0, 0)
	// The 429 branch only schedules cooldowns when cooling is enabled;
	// keep the global default (cooling on) so the suspend path runs and
	// the auto-release hook fires.
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	auth := &Auth{
		ID:          "auth-429",
		Provider:    "claude",
		ModelStates: map[string]*ModelState{},
	}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}

	m.MarkResult(context.Background(), Result{
		AuthID:   "auth-429",
		Provider: "claude",
		Model:    "claude-3",
		Success:  false,
		Error: &Error{
			Code:       "quota",
			Message:    "rate limited",
			HTTPStatus: http.StatusTooManyRequests,
		},
	})

	if got := atomic.LoadInt32(&sel.released); got != 1 {
		t.Fatalf("expected 1 InvalidateAuthBindings call when toggle on, got %d", got)
	}
}

// TestMarkResult_402AutoReleasesBindingsWhenToggleOn mirrors the 429
// test for 402 (Payment Required — deactivated_workspace). A 402 is
// just as fatal to the account, so when the toggle is on the bindings
// must be dropped so stranded conversations re-pick a fresh account.
func TestMarkResult_402AutoReleasesBindingsWhenToggleOn(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	t.Cleanup(func() { reg.UnregisterClient("auth-402") })

	sel := &bindingCountingSelector{}
	m := NewManager(nil, sel, nil)
	m.SetRetryConfig(0, 0, 0)
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	auth := &Auth{
		ID:          "auth-402",
		Provider:    "claude",
		ModelStates: map[string]*ModelState{},
	}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}

	m.MarkResult(context.Background(), Result{
		AuthID:   "auth-402",
		Provider: "claude",
		Model:    "claude-3",
		Success:  false,
		Error: &Error{
			Code:       "payment_required",
			Message:    "deactivated_workspace",
			HTTPStatus: http.StatusPaymentRequired,
		},
	})

	if got := atomic.LoadInt32(&sel.released); got != 1 {
		t.Fatalf("expected 1 InvalidateAuthBindings call for 402 when toggle on, got %d", got)
	}
}

// TestMarkResult_429DoesNotReleaseWhenToggleOff verifies the inverse:
// with the toggle off, a 429 result must NOT trigger binding
// invalidation — the operator opted out, so the 429 surfaces and the
// manual ⏏ button is the only release path.
func TestMarkResult_429DoesNotReleaseWhenToggleOff(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	t.Cleanup(func() { reg.UnregisterClient("auth-429-off") })

	sel := &bindingCountingSelector{}
	m := NewManager(nil, sel, nil)
	m.SetRetryConfig(0, 0, 0)
	SetAutoReleaseOn429(false)

	auth := &Auth{
		ID:          "auth-429-off",
		Provider:    "claude",
		ModelStates: map[string]*ModelState{},
	}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}

	m.MarkResult(context.Background(), Result{
		AuthID:   "auth-429-off",
		Provider: "claude",
		Model:    "claude-3",
		Success:  false,
		Error: &Error{
			Code:       "quota",
			Message:    "rate limited",
			HTTPStatus: http.StatusTooManyRequests,
		},
	})

	if got := atomic.LoadInt32(&sel.released); got != 0 {
		t.Fatalf("expected 0 InvalidateAuthBindings calls when toggle off, got %d", got)
	}
}

// TestMarkResult_Non429DoesNotRelease verifies the auto-release hook
// only fires on 429 and 402, not on other failure statuses — a 401 or
// 503 must not drop bindings (those have their own cooldown paths and
// the conversations are not necessarily stranded on a dead account).
func TestMarkResult_Non429DoesNotRelease(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	t.Cleanup(func() { reg.UnregisterClient("auth-503") })

	sel := &bindingCountingSelector{}
	m := NewManager(nil, sel, nil)
	m.SetRetryConfig(0, 0, 0)
	SetAutoReleaseOn429(true)
	t.Cleanup(func() { SetAutoReleaseOn429(false) })

	auth := &Auth{
		ID:          "auth-503",
		Provider:    "claude",
		ModelStates: map[string]*ModelState{},
	}
	if _, err := m.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}

	m.MarkResult(context.Background(), Result{
		AuthID:   "auth-503",
		Provider: "claude",
		Model:    "claude-3",
		Success:  false,
		Error: &Error{
			Code:       "unavailable",
			Message:    "boom",
			HTTPStatus: http.StatusServiceUnavailable,
		},
	})

	if got := atomic.LoadInt32(&sel.released); got != 0 {
		t.Fatalf("expected 0 InvalidateAuthBindings calls for 503, got %d", got)
	}
}
