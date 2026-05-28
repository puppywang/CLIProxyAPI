package monitor

import (
	"context"
	"testing"
	"time"
)

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
