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
			if stallThreshold <= 0 {
				continue
			}
			last := time.Unix(0, t.lastActivity.Load())
			if last.IsZero() {
				last = t.startedAt
			}
			if now.Sub(last) < stallThreshold {
				continue
			}
			r.Cancel(t.id, "auto", ReasonStall)
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
