package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Cancel reasons surfaced to operators and persisted to history records.
const (
	ReasonManual = "manual"
	ReasonStall  = "auto-stall"
)

// CancelRecord captures a cancellation event for the operator history view.
type CancelRecord struct {
	Entry      Entry     `json:"entry"`
	Reason     string    `json:"reason"`
	CanceledBy string    `json:"canceled_by"`
	CanceledAt time.Time `json:"canceled_at"`
}

// historyRing is a bounded in-memory ring of recent cancellation records.
type historyRing struct {
	mu       sync.RWMutex
	records  []CancelRecord
	capacity int
}

func newHistoryRing(capacity int) *historyRing {
	if capacity <= 0 {
		capacity = 200
	}
	return &historyRing{capacity: capacity}
}

func (h *historyRing) add(rec CancelRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) >= h.capacity {
		drop := len(h.records) - h.capacity + 1
		h.records = append(h.records[:0:0], h.records[drop:]...)
	}
	h.records = append(h.records, rec)
}

// recent returns up to limit records, newest-first.
func (h *historyRing) recent(limit int) []CancelRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if limit <= 0 || limit > len(h.records) {
		limit = len(h.records)
	}
	out := make([]CancelRecord, limit)
	for i := 0; i < limit; i++ {
		out[i] = h.records[len(h.records)-1-i]
	}
	return out
}

// historyLog appends cancellation records to a JSONL file. Writes are
// best-effort: failures are logged but never block the cancel flow.
type historyLog struct {
	path string
	mu   sync.Mutex
}

func newHistoryLog(path string) *historyLog {
	return &historyLog{path: path}
}

func (h *historyLog) append(rec CancelRecord) {
	if h == nil || h.path == "" {
		return
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if dir := filepath.Dir(h.path); dir != "" {
		if errMk := os.MkdirAll(dir, 0o755); errMk != nil {
			log.WithError(errMk).WithField("dir", dir).Warn("monitor: failed to create history directory")
			return
		}
	}
	f, errOpen := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if errOpen != nil {
		log.WithError(errOpen).WithField("path", h.path).Warn("monitor: failed to open history log")
		return
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.WithError(errClose).WithField("path", h.path).Warn("monitor: failed to close history log")
		}
	}()
	if _, errWrite := f.Write(append(data, '\n')); errWrite != nil {
		log.WithError(errWrite).WithField("path", h.path).Warn("monitor: failed to write history record")
	}
}
