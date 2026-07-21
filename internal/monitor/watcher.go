package monitor

import (
	"time"

	log "github.com/sirupsen/logrus"
)

const watcherInterval = 2 * time.Second

// forceFinishGrace bounds how long an entry may sit in StatusCanceling. If
// the upstream executor never honours context cancellation (e.g. a Codex
// WebSocket whose read goroutine is blocked on a dead socket), the entry
// would otherwise linger in the registry forever. The watcher escalates by
// force-finishing it so the operator UI converges and the credential can be
// considered logically released.
const forceFinishGrace = 30 * time.Second

// StartWatcher launches the auto-cancel background loop. The goroutine
// terminates when the supplied stop channel is closed.
func (r *Registry) StartWatcher(stop <-chan struct{}) {
	go r.watcherLoop(stop)
}

func (r *Registry) watcherLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(watcherInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			r.scanStalled()
		}
	}
}

// scanStalled walks every tracked entry once per tick and takes one of two
// remediation actions:
//
//   - Running entries whose last response activity is older than the
//     configured stall threshold are auto-cancelled.
//   - Entries already in StatusCanceling for longer than forceFinishGrace are
//     force-finished so the registry never holds a permanently stuck slot.
func (r *Registry) scanStalled() {
	settings := r.Settings()
	stallThreshold := time.Duration(settings.StallTimeoutSeconds) * time.Second
	slowWindow := time.Duration(settings.SlowWindowSeconds) * time.Second
	slowMinBytes := int64(settings.SlowMinBytes)
	now := time.Now()

	r.mu.RLock()
	candidates := make([]*trackedRequest, 0, len(r.entries))
	for _, t := range r.entries {
		candidates = append(candidates, t)
	}
	r.mu.RUnlock()

	for _, t := range candidates {
		t.mu.RLock()
		status := t.status
		canceledAt := t.canceledAt
		t.mu.RUnlock()

		switch status {
		case StatusRunning:
			// 1) Stall watchdog: no response activity at all for the whole
			//    threshold. Covers the initial wait (no first byte yet) and
			//    any fully-silent mid-stream gap.
			if stallThreshold > 0 {
				last := time.Unix(0, t.lastActivity.Load())
				if last.IsZero() {
					last = t.startedAt
				}
				if now.Sub(last) >= stallThreshold {
					// Emit a structured line before cancelling so a stall is
					// visible in the service journal (the Cancel path itself
					// is silent for the auto case). The persisted CancelRecord
					// carries the same detail for the operator history view.
					log.WithField("request_id", t.id).
						WithField("gap", now.Sub(last).Round(time.Second).String()).
						WithField("threshold", stallThreshold.String()).
						WithField("response_bytes", t.responseBytes.Load()).
						Warn("monitor: auto-cancelling stalled request; no response activity within stall threshold")
					r.Cancel(t.id, "auto", ReasonStall)
					continue
				}
			}

			// 2) Slow-stream watchdog (throughput floor): a streaming response
			//    that never goes silent long enough to trip the stall timeout
			//    but delivers fewer than SlowMinBytes over a full
			//    SlowWindowSeconds window is a "trickle" and gets cancelled.
			r.scanSlow(t, now, slowWindow, slowMinBytes)

			// 3) Live upload progress: while the request body is still
			//    arriving, no other event fires (no response bytes yet), so
			//    push a snapshot each tick so the UI can render real-time
			//    upload speed/progress for slow client links.
			if t.isReceivingBody() {
				r.broadcast(Event{Type: "updated", Entry: t.snapshot()})
			}
		case StatusCanceling:
			if canceledAt.IsZero() || now.Sub(canceledAt) < forceFinishGrace {
				continue
			}
			log.WithField("request_id", t.id).
				WithField("canceled_at", canceledAt).
				Warn("monitor: force-finishing entry stuck in canceling state; upstream did not honor cancellation")
			r.Finish(t)
		}
	}
}

// scanSlow applies the throughput-floor watchdog to a single running entry.
// It maintains a rolling window anchored to the entry: once a full window has
// elapsed since the anchor, it measures how many response bytes arrived during
// that window. Below the floor -> cancel as a slow stream; at or above ->
// slide the anchor forward and keep watching. The watchdog only engages after
// the stream has produced its first byte, so the initial TTFB (handled by the
// stall watchdog) never counts against throughput. No-ops when either knob is
// unset or the entry is not a streaming response.
func (r *Registry) scanSlow(t *trackedRequest, now time.Time, window time.Duration, minBytes int64) {
	if window <= 0 || minBytes <= 0 {
		return
	}
	if !t.streaming.Load() {
		return
	}
	if t.firstChunkAt.Load() == 0 {
		// No bytes yet; the stall watchdog owns this phase.
		return
	}
	curBytes := t.responseBytes.Load()
	anchorAt := t.slowAnchorAt.Load()
	if anchorAt == 0 {
		// First observation after first byte: start the window here.
		t.slowAnchorAt.Store(now.UnixNano())
		t.slowAnchorBytes.Store(curBytes)
		return
	}
	if now.Sub(time.Unix(0, anchorAt)) < window {
		return
	}
	delta := curBytes - t.slowAnchorBytes.Load()
	if delta < minBytes {
		// Capture the triggering window delta before Cancel so the snapshot
		// (and thus the recorded detail) reports the number that actually
		// tripped the rule, not a whole-request average.
		t.slowWindowBytes.Store(delta)
		log.WithField("request_id", t.id).
			WithField("window", window.String()).
			WithField("bytes_in_window", delta).
			WithField("floor", minBytes).
			WithField("response_bytes", curBytes).
			Warn("monitor: auto-cancelling slow stream; response throughput below floor for a full window")
		r.Cancel(t.id, "auto", ReasonSlow)
		return
	}
	// Healthy window: slide the anchor forward.
	t.slowAnchorAt.Store(now.UnixNano())
	t.slowAnchorBytes.Store(curBytes)
}
