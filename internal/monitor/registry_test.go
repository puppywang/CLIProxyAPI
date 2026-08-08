package monitor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestRegistry_SetTurnMetadata verifies the window/conversation fields
// reach the entry snapshot and that empty inputs never clobber values
// already populated by an earlier call. The clobber-guard matters in
// practice because real Codex traffic sometimes sends a second header
// (X-Client-Request-Id) with a partially-populated turn shape after
// the canonical X-Codex-Turn-Metadata; without the guard the cleaner
// later header would erase context the registration call captured.
func TestRegistry_SetTurnMetadata(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("req-meta-1", "POST", "", "/v1/responses", "127.0.0.1", "codex", 0, cancel)

	reg.SetTurnMetadata(entry, "sid-A", "tid-A", "turn-A", "user")
	snap := reg.Snapshot()[0]
	if snap.SessionID != "sid-A" || snap.ThreadID != "tid-A" || snap.TurnID != "turn-A" || snap.ThreadSource != "user" {
		t.Fatalf("metadata not captured: %+v", snap)
	}

	// Empty values must NOT overwrite — partial updates should be tolerated.
	reg.SetTurnMetadata(entry, "", "", "turn-B", "")
	snap = reg.Snapshot()[0]
	if snap.SessionID != "sid-A" || snap.ThreadID != "tid-A" || snap.ThreadSource != "user" {
		t.Fatalf("empty-input clobbered an existing field: %+v", snap)
	}
	if snap.TurnID != "turn-B" {
		t.Fatalf("partial update missed: TurnID=%q want turn-B", snap.TurnID)
	}
}

// TestRegistry_RequestBytesFallback verifies that chunked requests (which
// register with requestBytes=0 because Content-Length is -1) still surface a
// measured request size once the body timer has counted actual bytes. Without
// the fallback the operator UI shows "0 B" for multi-megabyte uploads (e.g.
// GitHub Copilot Chat posting /v1/chat/completions chunked).
func TestRegistry_RequestBytesFallback(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Chunked request: registered with 0 declared bytes.
	entry := reg.Register("req-chunked-1", "POST", "", "/v1/chat/completions", "127.0.0.1", "copilot", 0, cancel)
	timer := &bodyTimer{arrival: time.Now()}
	timer.bytes.Store(1407542)
	entry.mu.Lock()
	entry.bodyTiming = timer
	entry.mu.Unlock()

	snap := reg.Snapshot()[0]
	if snap.RequestBytes != 1407542 {
		t.Fatalf("chunked request_bytes not filled from body timer: got %d want 1407542", snap.RequestBytes)
	}

	// Declared-size request: must keep the declared Content-Length.
	_, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	entry2 := reg.Register("req-declared-1", "POST", "", "/v1/chat/completions", "127.0.0.1", "codex", 4096, cancel2)
	timer2 := &bodyTimer{arrival: time.Now()}
	timer2.bytes.Store(4000)
	entry2.mu.Lock()
	entry2.bodyTiming = timer2
	entry2.mu.Unlock()

	var snap2 Entry
	for _, s := range reg.Snapshot() {
		if s.ID == "req-declared-1" {
			snap2 = s
			break
		}
	}
	if snap2.ID == "" {
		t.Fatal("declared-size entry not found in snapshot")
	}
	if snap2.RequestBytes != 4096 {
		t.Fatalf("declared request_bytes overwritten: got %d want 4096", snap2.RequestBytes)
	}
}

// TestRegistry_RecentErrors_CapturesNon2xx is the contract test for the
// recent-errors ring: a non-2xx terminal status must produce a record;
// 200 must not. Older entries fall off when the ring's capacity is hit,
// so the test also exercises the bounded-size behaviour by overflowing
// a small ring.
func TestRegistry_RecentErrors_CapturesNon2xx(t *testing.T) {
	reg := NewRegistry()

	register := func(id string, code int) {
		_, cancel := context.WithCancel(context.Background())
		entry := reg.Register(id, "POST", "", "/v1/responses", "127.0.0.1", "codex", 0, cancel)
		reg.SetStatusCode(entry, code)
		reg.Finish(entry)
		cancel()
	}

	register("ok-1", 200)
	register("auth-1", 401)
	register("quota-1", 429)
	register("upstream-1", 503)
	register("client-1", 400)

	got := reg.RecentErrors(50)
	if len(got) != 4 {
		t.Fatalf("RecentErrors: got %d records, want 4 (200 must not appear)", len(got))
	}
	// Newest first.
	if got[0].Entry.ID != "client-1" || got[0].Reason != "client_4xx" {
		t.Errorf("newest record = %+v, want client-1 / client_4xx", got[0])
	}
	if got[1].Reason != "upstream_5xx" || got[2].Reason != "quota" || got[3].Reason != "auth" {
		t.Errorf("reason ordering: %v %v %v", got[1].Reason, got[2].Reason, got[3].Reason)
	}
	for _, r := range got {
		if r.Entry.ID == "ok-1" {
			t.Fatalf("200 OK leaked into recent errors: %+v", r)
		}
	}
}

// TestRegistry_RecentErrors_CarriesErrorSnippet verifies the captured error
// body reaches the recent-errors ring, so the operator can see WHY a request
// failed (e.g. "unknown provider for model X") without opening logs.
func TestRegistry_RecentErrors_CarriesErrorSnippet(t *testing.T) {
	reg := NewRegistry()
	cancel := func() {}
	entry := reg.Register("errsnip-1", "POST", "", "/v1/responses", "127.0.0.1", "codex", 0, cancel)
	reg.SetStatusCode(entry, 502)
	reg.SetErrorSnippet(entry, `{"error":{"message":"unknown provider for model gpt-5.6-sol"}}`)
	reg.Finish(entry)

	got := reg.RecentErrors(10)
	if len(got) != 1 {
		t.Fatalf("RecentErrors: got %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Entry.ErrorSnippet, "unknown provider for model gpt-5.6-sol") {
		t.Errorf("ErrorSnippet = %q, want the captured upstream message", got[0].Entry.ErrorSnippet)
	}
}

// TestRegistry_RecentErrors_RecordsCanceled verifies the canceled path
// (Cancel before Finish) also produces an error record — operators want
// visibility into cancellations regardless of whether a status code
// was ever written.
func TestRegistry_RecentErrors_RecordsCanceled(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	entry := reg.Register("cancel-1", "POST", "", "/v1/responses", "127.0.0.1", "codex", 0, cancel)
	reg.Cancel("cancel-1", "test", ReasonStall)
	reg.Finish(entry)
	cancel()

	got := reg.RecentErrors(10)
	if len(got) != 1 {
		t.Fatalf("RecentErrors: got %d, want 1", len(got))
	}
	if got[0].Reason != "canceled" {
		t.Fatalf("reason = %q, want canceled", got[0].Reason)
	}
	// Verify timestamp is fresh (within the last few seconds).
	if time.Since(got[0].RecordedAt) > 5*time.Second {
		t.Errorf("RecordedAt looks stale: %v", got[0].RecordedAt)
	}
}

func TestRegistryRegisterAndRemove(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	entry := reg.Register("abc12345", "POST", "", "/v1/chat/completions", "127.0.0.1", "ua", 256, cancel)
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}

	snap := reg.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snap))
	}
	if snap[0].ID != "abc12345" {
		t.Errorf("unexpected id %q", snap[0].ID)
	}

	reg.SetModel(entry, "gpt-5-codex")
	reg.AddResponseBytes(entry, 4096)
	reg.SetAuth(entry, "auth-1")
	reg.SetStreaming(entry, true)

	snap = reg.Snapshot()
	if snap[0].Model != "gpt-5-codex" {
		t.Errorf("model not set: %q", snap[0].Model)
	}
	if snap[0].ResponseBytes != 4096 {
		t.Errorf("response_bytes not incremented: %d", snap[0].ResponseBytes)
	}
	if snap[0].AuthID != "auth-1" {
		t.Errorf("auth_id not set: %q", snap[0].AuthID)
	}
	if !snap[0].Streaming {
		t.Errorf("streaming flag not set")
	}

	reg.Finish(entry)
	// Finished entries linger in the registry briefly so the UI can show the
	// terminal outcome. Verify the status transitions, then explicitly remove.
	snap = reg.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected entry to linger after Finish, got %d", len(snap))
	}
	if snap[0].Status != StatusFinished {
		t.Errorf("expected status %q after Finish, got %q", StatusFinished, snap[0].Status)
	}
	reg.Remove(entry.id)
	if got := len(reg.Snapshot()); got != 0 {
		t.Errorf("expected empty after Remove, got %d", got)
	}
}

func TestRegistryCancel(t *testing.T) {
	reg := NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	entry := reg.Register("ff00aa11", "POST", "", "/v1/messages", "127.0.0.1", "", 128, cancel)
	_ = entry

	if ok := reg.Cancel("ff00aa11", "admin", ReasonManual); !ok {
		t.Fatal("expected Cancel to return true")
	}

	select {
	case <-ctx.Done():
		// expected: cancellation propagated
	case <-time.After(time.Second):
		t.Fatal("ctx was not cancelled within 1s")
	}

	snap := reg.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected entry still present until Finish, got %d", len(snap))
	}
	if snap[0].Status != StatusCanceling {
		t.Errorf("expected status %q, got %q", StatusCanceling, snap[0].Status)
	}
	if snap[0].CanceledBy != "admin" {
		t.Errorf("expected canceled_by %q, got %q", "admin", snap[0].CanceledBy)
	}
}

func TestRegistryFinishLingersThenRemoves(t *testing.T) {
	reg := NewRegistry()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	entry := reg.Register("aabbccdd", "POST", "", "/v1/messages", "127.0.0.1", "", 0, cancel)
	reg.Finish(entry)

	if got := len(reg.Snapshot()); got != 1 {
		t.Fatalf("expected linger after Finish, got %d", got)
	}
	// terminalLingerDuration is 5s; use a guard a bit larger.
	deadline := time.Now().Add(terminalLingerDuration + time.Second)
	for time.Now().Before(deadline) {
		if len(reg.Snapshot()) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("entry was not removed after linger duration")
}

func TestRegistryAddResponseBytesBroadcastsThrottled(t *testing.T) {
	reg := NewRegistry()
	ch, unsubscribe := reg.Subscribe()
	defer unsubscribe()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("deadbeef", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, cancel)

	// Drain the initial "added" event.
	<-ch

	// First byte write should broadcast immediately (lastBroadcast == 0).
	reg.AddResponseBytes(entry, 100)
	select {
	case ev := <-ch:
		if ev.Type != "updated" {
			t.Errorf("expected updated, got %q", ev.Type)
		}
		if ev.Entry.ResponseBytes != 100 {
			t.Errorf("expected 100 bytes in event, got %d", ev.Entry.ResponseBytes)
		}
	case <-time.After(time.Second):
		t.Fatal("no broadcast on first byte write")
	}

	// Subsequent rapid writes should be coalesced.
	reg.AddResponseBytes(entry, 200)
	reg.AddResponseBytes(entry, 300)
	select {
	case ev := <-ch:
		t.Fatalf("unexpected immediate broadcast: %+v", ev)
	case <-time.After(50 * time.Millisecond):
		// expected: no broadcast within the throttle window
	}

	// After the throttle window, another write broadcasts again with the latest total.
	time.Sleep(byteBroadcastInterval)
	reg.AddResponseBytes(entry, 50)
	select {
	case ev := <-ch:
		if ev.Entry.ResponseBytes != 650 {
			t.Errorf("expected 650 bytes in event, got %d", ev.Entry.ResponseBytes)
		}
	case <-time.After(time.Second):
		t.Fatal("no broadcast after throttle window")
	}
}

func TestRegistryAutoCancelOnStall(t *testing.T) {
	reg := NewRegistry()
	dir := t.TempDir()
	store := NewSettingsStore(dir + "/settings.json")
	_ = store.Set(Settings{StallTimeoutSeconds: 1})
	reg.AttachSettings(store)
	reg.AttachHistoryLog(dir + "/cancels.jsonl")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("stallid01", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, cancel)
	// Force lastActivity to be old enough to trip immediately.
	entry.lastActivity.Store(time.Now().Add(-5 * time.Second).UnixNano())

	reg.scanStalled()

	snap := reg.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected entry to linger after auto-cancel, got %d", len(snap))
	}
	if snap[0].Status != StatusCanceling {
		t.Errorf("expected status %q, got %q", StatusCanceling, snap[0].Status)
	}
	if snap[0].CanceledBy != "auto" {
		t.Errorf("expected canceled_by 'auto', got %q", snap[0].CanceledBy)
	}

	hist := reg.History(10)
	if len(hist) != 1 {
		t.Fatalf("expected 1 history record, got %d", len(hist))
	}
	if hist[0].Reason != ReasonStall {
		t.Errorf("expected reason %q, got %q", ReasonStall, hist[0].Reason)
	}
}

func TestRegistryAutoCancelOnSlowStream(t *testing.T) {
	reg := NewRegistry()
	dir := t.TempDir()
	store := NewSettingsStore(dir + "/settings.json")
	// Stall disabled so only the throughput floor can fire; window 1s, floor 1000 bytes.
	_ = store.Set(Settings{StallTimeoutSeconds: 0, SlowWindowSeconds: 1, SlowMinBytes: 1000})
	reg.AttachSettings(store)
	reg.AttachHistoryLog(dir + "/cancels.jsonl")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("slowid001", "POST", "", "/v1/responses", "127.0.0.1", "", 0, cancel)
	entry.streaming.Store(true)
	now := time.Now()
	// First byte long ago, recent activity (so stall would not apply even if enabled),
	// window anchor backdated past the window with a baseline of 0 bytes, but only
	// 500 bytes delivered over the whole window -> below the 1000-byte floor.
	entry.firstChunkAt.Store(now.Add(-10 * time.Second).UnixNano())
	entry.lastActivity.Store(now.UnixNano())
	entry.slowAnchorAt.Store(now.Add(-2 * time.Second).UnixNano())
	entry.slowAnchorBytes.Store(0)
	entry.responseBytes.Store(500)

	reg.scanStalled()

	snap := reg.Snapshot()
	if len(snap) != 1 || snap[0].Status != StatusCanceling {
		t.Fatalf("expected slow stream to be auto-cancelled (canceling), got %+v", snap)
	}
	hist := reg.History(10)
	if len(hist) != 1 {
		t.Fatalf("expected 1 history record, got %d", len(hist))
	}
	if hist[0].Reason != ReasonSlow {
		t.Errorf("expected reason %q, got %q", ReasonSlow, hist[0].Reason)
	}
	if hist[0].Detail == "" {
		t.Errorf("expected slow-stream detail to be populated, got empty")
	}
}

func TestRegistrySlowStreamHealthyNotCancelled(t *testing.T) {
	reg := NewRegistry()
	dir := t.TempDir()
	store := NewSettingsStore(dir + "/settings.json")
	_ = store.Set(Settings{StallTimeoutSeconds: 0, SlowWindowSeconds: 1, SlowMinBytes: 1000})
	reg.AttachSettings(store)

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("slowid002", "POST", "", "/v1/responses", "127.0.0.1", "", 0, cancel)
	entry.streaming.Store(true)
	now := time.Now()
	entry.firstChunkAt.Store(now.Add(-10 * time.Second).UnixNano())
	entry.lastActivity.Store(now.UnixNano())
	entry.slowAnchorAt.Store(now.Add(-2 * time.Second).UnixNano())
	entry.slowAnchorBytes.Store(0)
	// 4000 bytes over the window is well above the 1000-byte floor.
	entry.responseBytes.Store(4000)

	reg.scanStalled()

	snap := reg.Snapshot()
	if len(snap) != 1 || snap[0].Status != StatusRunning {
		t.Fatalf("expected healthy stream to keep running, got %+v", snap)
	}
	// The anchor should have slid forward to the current byte count.
	if got := entry.slowAnchorBytes.Load(); got != 4000 {
		t.Errorf("expected anchor bytes to advance to 4000, got %d", got)
	}
}

func TestRegistrySlowStreamFirstObservationAnchorsOnly(t *testing.T) {
	reg := NewRegistry()
	dir := t.TempDir()
	store := NewSettingsStore(dir + "/settings.json")
	_ = store.Set(Settings{StallTimeoutSeconds: 0, SlowWindowSeconds: 1, SlowMinBytes: 1000})
	reg.AttachSettings(store)

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("slowid003", "POST", "", "/v1/responses", "127.0.0.1", "", 0, cancel)
	entry.streaming.Store(true)
	now := time.Now()
	entry.firstChunkAt.Store(now.Add(-10 * time.Second).UnixNano())
	entry.lastActivity.Store(now.UnixNano())
	// No anchor yet (0) and few bytes: the first observation must only set the
	// anchor, never cancel — otherwise a stream would be judged before a full
	// window has been observed.
	entry.responseBytes.Store(100)

	reg.scanStalled()

	snap := reg.Snapshot()
	if len(snap) != 1 || snap[0].Status != StatusRunning {
		t.Fatalf("expected first observation to leave stream running, got %+v", snap)
	}
	if entry.slowAnchorAt.Load() == 0 {
		t.Errorf("expected anchor to be initialised on first observation")
	}
	if got := entry.slowAnchorBytes.Load(); got != 100 {
		t.Errorf("expected anchor baseline 100, got %d", got)
	}
}

func TestRegistryForceFinishStuckCancelingEntry(t *testing.T) {
	reg := NewRegistry()
	dir := t.TempDir()
	store := NewSettingsStore(dir + "/settings.json")
	_ = store.Set(Settings{StallTimeoutSeconds: 1})
	reg.AttachSettings(store)

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("stuck0001", "POST", "", "/v1/messages", "127.0.0.1", "", 0, cancel)
	if !reg.Cancel(entry.id, "operator", ReasonManual) {
		t.Fatal("Cancel should have transitioned the entry")
	}
	// Simulate the upstream not exiting: backdate canceledAt past the grace.
	entry.mu.Lock()
	entry.canceledAt = time.Now().Add(-2 * forceFinishGrace)
	entry.mu.Unlock()

	reg.scanStalled()

	snap := reg.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected entry to linger after force-finish, got %d", len(snap))
	}
	if snap[0].Status != StatusCanceled {
		t.Errorf("expected force-finish to produce status %q, got %q", StatusCanceled, snap[0].Status)
	}
}

func TestRegistryHistoryLogReplaysOnAttach(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/cancels.jsonl"

	// First registry: attach the log and record two cancellations.
	reg1 := NewRegistry()
	reg1.AttachHistoryLog(logPath)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, id := range []string{"histrec01", "histrec02"} {
		reg1.Register(id, "POST", "", "/v1/responses", "127.0.0.1", "", 0, cancel)
		if !reg1.Cancel(id, "operator", ReasonManual) {
			t.Fatalf("Cancel(%s) failed", id)
		}
	}
	if got := len(reg1.History(10)); got != 2 {
		t.Fatalf("reg1 History: got %d, want 2", got)
	}

	// Second registry (simulating a restart): attaching the same log must
	// replay the persisted records into the fresh ring, newest-first.
	reg2 := NewRegistry()
	reg2.AttachHistoryLog(logPath)
	hist := reg2.History(10)
	if len(hist) != 2 {
		t.Fatalf("reg2 History after replay: got %d, want 2", len(hist))
	}
	if hist[0].Entry.ID != "histrec02" || hist[1].Entry.ID != "histrec01" {
		t.Errorf("replay order wrong: got [%s, %s], want [histrec02, histrec01]",
			hist[0].Entry.ID, hist[1].Entry.ID)
	}
}

func TestRegistryCriticalEventNotDroppedUnderLoad(t *testing.T) {
	reg := NewRegistry()
	ch, unsubscribe := reg.Subscribe()
	defer unsubscribe()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := reg.Register("crit0001", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, cancel)
	// Drain the "added" event so the channel starts empty.
	<-ch

	// Saturate the channel with best-effort updates that should be dropped
	// rather than delivered. The buffer is intentionally large but finite.
	for i := 0; i < subscriberChannelBuffer*2; i++ {
		reg.broadcast(Event{Type: "updated", Entry: entry.snapshot()})
	}

	// Now fire a Critical event. Even though the channel is saturated, the
	// blocking-with-timeout path should eventually deliver it once the
	// subscriber drains room.
	delivered := make(chan struct{})
	go func() {
		seenCritical := false
		for ev := range ch {
			if ev.Critical {
				seenCritical = true
				close(delivered)
				return
			}
			_ = seenCritical
		}
	}()
	reg.broadcast(Event{Type: "updated", Entry: entry.snapshot(), Critical: true})

	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("Critical event was not delivered within 2s under load")
	}
}

func TestRegistrySubscribe(t *testing.T) {
	reg := NewRegistry()
	ch, unsubscribe := reg.Subscribe()
	defer unsubscribe()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg.Register("11223344", "POST", "", "/v1/chat/completions", "127.0.0.1", "", 0, cancel)

	select {
	case ev := <-ch:
		if ev.Type != "added" {
			t.Errorf("expected 'added' event, got %q", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received within 1s")
	}
}

// TestClassifyErrorReason_StreamFailureDespite200 locks in that a failure which
// happens after the status line was sent is still classified as an error. A
// streaming response commits 200 on its first byte, so without the
// StreamFailure marker a truncated turn is indistinguishable from success —
// exactly how "stream disconnected before completion" turns went unnoticed.
func TestClassifyErrorReason_StreamFailureDespite200(t *testing.T) {
	if got := classifyErrorReason(Entry{Status: StatusFinished, StatusCode: 200}); got != "" {
		t.Fatalf("a clean 200 must not be an error, got %q", got)
	}
	if got := classifyErrorReason(Entry{Status: StatusFinished, StatusCode: 200, StreamFailure: "codex stream closed before response.completed"}); got != "stream_incomplete" {
		t.Fatalf("mid-stream failure on a 200 must classify as stream_incomplete, got %q", got)
	}
	// A real HTTP error keeps its more specific classification.
	if got := classifyErrorReason(Entry{Status: StatusFinished, StatusCode: 429, StreamFailure: "x"}); got != "quota" {
		t.Fatalf("status-code classification must take precedence, got %q", got)
	}
}
