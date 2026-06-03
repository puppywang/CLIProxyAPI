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

// ErrorRecord captures a non-2xx outcome for the operator "recent
// errors" view. The full Entry snapshot is preserved so the UI can
// show the window/conversation context, chosen auth, model, and the
// observed status code without keeping the entry itself in memory.
type ErrorRecord struct {
	Entry      Entry     `json:"entry"`
	StatusCode int       `json:"status_code"`
	Reason     string    `json:"reason"`
	RecordedAt time.Time `json:"recorded_at"`
}

// errorsRing is a bounded in-memory ring of recent error outcomes.
// Implementation mirrors historyRing — keeping them separate (rather
// than refactoring) so a future divergence (different retention, an
// errors-only on-disk log, etc.) does not have to disentangle two
// callers from a shared abstraction.
type errorsRing struct {
	mu       sync.RWMutex
	records  []ErrorRecord
	capacity int
}

func newErrorsRing(capacity int) *errorsRing {
	if capacity <= 0 {
		capacity = 200
	}
	return &errorsRing{capacity: capacity}
}

func (e *errorsRing) add(rec ErrorRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.records) >= e.capacity {
		drop := len(e.records) - e.capacity + 1
		e.records = append(e.records[:0:0], e.records[drop:]...)
	}
	e.records = append(e.records, rec)
}

func (e *errorsRing) recent(limit int) []ErrorRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > len(e.records) {
		limit = len(e.records)
	}
	out := make([]ErrorRecord, limit)
	for i := 0; i < limit; i++ {
		out[i] = e.records[len(e.records)-1-i]
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

// errorsLog persists ErrorRecord entries to a JSONL file so the operator
// "Errors" panel survives CPA restarts. Append-only — operators who want
// to clear the panel truncate the file via the management API. Behaves
// identically to historyLog for writes; loadRecent additionally streams
// the file once at startup to repopulate the in-memory ring.
type errorsLog struct {
	path string
	mu   sync.Mutex
}

func newErrorsLog(path string) *errorsLog {
	return &errorsLog{path: path}
}

func (e *errorsLog) append(rec ErrorRecord) {
	if e == nil || e.path == "" {
		return
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if dir := filepath.Dir(e.path); dir != "" {
		if errMk := os.MkdirAll(dir, 0o755); errMk != nil {
			log.WithError(errMk).WithField("dir", dir).Warn("monitor: failed to create errors-log directory")
			return
		}
	}
	f, errOpen := os.OpenFile(e.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if errOpen != nil {
		log.WithError(errOpen).WithField("path", e.path).Warn("monitor: failed to open errors log")
		return
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.WithError(errClose).WithField("path", e.path).Warn("monitor: failed to close errors log")
		}
	}()
	if _, errWrite := f.Write(append(data, '\n')); errWrite != nil {
		log.WithError(errWrite).WithField("path", e.path).Warn("monitor: failed to write errors record")
	}
}

// loadRecent streams the JSONL file once and returns up to limit
// records in OLDEST-FIRST order so the caller can replay them into
// the ring buffer without inverting the sequence. Returns nil for
// missing files (first boot before any error has been written) or
// when the file cannot be opened. Malformed lines are skipped with
// a warning; one bad line never prevents loading the rest.
//
// Implementation note: we read the entire file rather than seeking
// from the tail. Operator JSONL is bounded by the ring capacity in
// practice (the historyLog has run for weeks at ~200 KB), and the
// streaming json.Decoder uses constant memory. The seek-from-tail
// approach is harder to get right (need to find a complete JSON
// document boundary in the middle of a file) and not worth the
// complexity for what is a startup-only path.
func (e *errorsLog) loadRecent(limit int) []ErrorRecord {
	if e == nil || e.path == "" || limit <= 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := os.Open(e.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).WithField("path", e.path).Warn("monitor: failed to open errors log for replay")
		}
		return nil
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.WithError(errClose).WithField("path", e.path).Warn("monitor: failed to close errors log after replay")
		}
	}()
	decoder := json.NewDecoder(f)
	// Ring of the most recent `limit` records. Decode every line
	// (cheaper than two-pass tail seek), keep only the last `limit`.
	buf := make([]ErrorRecord, 0, limit)
	for decoder.More() {
		var rec ErrorRecord
		if errDec := decoder.Decode(&rec); errDec != nil {
			log.WithError(errDec).WithField("path", e.path).Warn("monitor: skipped malformed errors-log line")
			continue
		}
		if len(buf) < limit {
			buf = append(buf, rec)
			continue
		}
		// Slide the window: drop oldest, append newest.
		buf = append(buf[:0:limit], append(buf[1:], rec)...)
	}
	return buf
}
