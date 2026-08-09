package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Quota history retention and sampling bounds. The codex refresher pushes a
// snapshot roughly every 10 minutes per auth, so 7 days is ~1k samples per
// account; the per-auth cap is a backstop against a pathological push rate
// (e.g. an operator hammering the manual refresh button).
const (
	quotaHistoryRetention   = 7 * 24 * time.Hour
	quotaHistoryPerAuthCap  = 3000
	quotaHistoryMinInterval = 60 * time.Second
	quotaHistorySaveEvery   = 60 * time.Second
	// quotaResetFloor: a sample whose primary-window usage is at or below
	// this percent is considered "reset to zero" (the 5h/weekly window
	// collapsed). 7% -> 0% must count as a reset even though the drop is
	// only 7 points — the old fixed >=25-point drop threshold missed it.
	quotaResetFloor = 5
	// quotaResetMinPrev: the previous sample must have been at or above
	// this percent for the drop to count as a reset. Guards against
	// refresh-interface jitter (3% -> 0% is noise, 7% -> 0% is a reset).
	quotaResetMinPrev = 5
	// quotaPassiveSlack: when a reset is observed, it is "passive" if the
	// quota API's declared reset time (reset_at) for the collapsed window
	// falls within this margin of the observation time. That means the
	// drop is a true CD-cooldown rollover the API was advertising. A
	// collapse that happens well before the declared reset time is
	// "active" (manual reset / account switch / interface anomaly).
	quotaPassiveSlack = 30 * time.Minute
)

// QuotaSample is one observation of an auth's quota windows. Field names are
// single letters because the whole series is shipped to the browser on every
// panel load and repeated over thousands of points.
type QuotaSample struct {
	T int64 `json:"t"`           // unix seconds
	P int   `json:"p"`           // primary window used percent (codex 5h / grok weekly)
	S int   `json:"s"`           // secondary window used percent (codex 7d / grok monthly)
	L bool  `json:"l,omitempty"` // limit_reached at this sample
	// RA is the primary-window reset time the quota API declared at this
	// sample (unix seconds; 0 when unknown). Used to classify a later
	// reset as passive (observed near the declared rollover) or active.
	RA int64 `json:"ra,omitempty"`
	// R marks a primary-window reset observed at this sample:
	//   "p" = passive — the API-declared reset time (previous sample's RA)
	//         fell within quotaPassiveSlack of this observation, so this is
	//         a true CD-cooldown rollover;
	//   "a" = active — the drop happened well before the declared reset
	//         time (manual reset / account switch / anomaly).
	R string `json:"r,omitempty"`
}

// quotaHistoryStore keeps a bounded, disk-backed time series per auth ID so the
// monitor can draw a usage curve across restarts. Writes are debounced: the
// file is rewritten at most once per quotaHistorySaveEvery, so a crash loses at
// most that much history — acceptable for an observability curve.
type quotaHistoryStore struct {
	mu       sync.Mutex
	data     map[string][]QuotaSample
	path     string
	lastSave time.Time
	dirty    bool
}

func newQuotaHistoryStore(path string) *quotaHistoryStore {
	s := &quotaHistoryStore{data: make(map[string][]QuotaSample), path: path}
	s.load()
	if path != "" {
		go s.flushLoop()
	}
	return s
}

// flushLoop persists pending samples on a timer. record() alone is not enough:
// its write is debounced, so the newest batch would sit unsaved until the NEXT
// sample arrives — a full refresh cycle (~10 min) later, and lost entirely if
// the process restarts first. The ticker bounds that exposure to the debounce
// interval. Runs for the process lifetime; the store is a startup singleton.
func (s *quotaHistoryStore) flushLoop() {
	ticker := time.NewTicker(quotaHistorySaveEvery)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		s.saveLocked(time.Now())
		s.mu.Unlock()
	}
}

func (s *quotaHistoryStore) load() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("monitor: read quota history %s: %v", s.path, err)
		}
		return
	}
	var stored map[string][]QuotaSample
	if errUnmarshal := json.Unmarshal(raw, &stored); errUnmarshal != nil {
		log.Warnf("monitor: parse quota history %s: %v", s.path, errUnmarshal)
		return
	}
	cutoff := time.Now().Add(-quotaHistoryRetention).Unix()
	for id, samples := range stored {
		kept := samples[:0]
		for _, sample := range samples {
			if sample.T >= cutoff {
				kept = append(kept, sample)
			}
		}
		if len(kept) > 0 {
			s.data[id] = kept
		}
	}
}

// record appends a sample for authID. Samples closer together than
// quotaHistoryMinInterval are dropped unless the values actually changed, so a
// burst of manual refreshes cannot flood the series while a real transition
// (e.g. a reset from 100% to 0%) is always captured.
//
// A primary-window reset (usage collapsing from a real value to near zero —
// 100%→0%, 7%→0%, …) is marked on the new sample: "p" (passive) when the
// quota API's declared reset time for the collapsed window (resetAtPrimary,
// captured on the previous sample) falls within quotaPassiveSlack of this
// observation — a true CD-cooldown rollover the API was advertising. Any
// collapse well before the declared reset time is "a" (active): manual reset,
// account switch, or an interface anomaly.
func (s *quotaHistoryStore) record(authID string, primary, secondary int, limitReached bool, resetAtPrimary time.Time, now time.Time) {
	if s == nil || authID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	series := s.data[authID]
	resetMark := ""
	if n := len(series); n > 0 {
		last := series[n-1]
		unchanged := last.P == primary && last.S == secondary && last.L == limitReached
		if unchanged && now.Sub(time.Unix(last.T, 0)) < quotaHistoryMinInterval {
			return
		}
		// Reset detection on the primary window: the previous sample was a
		// real usage level and the new one collapsed to (near) zero. No
		// fixed drop threshold — 7%→0% is a reset too.
		if last.P >= quotaResetMinPrev && primary <= quotaResetFloor && primary < last.P {
			if last.RA > 0 {
				// API-declared reset time known: passive iff this
				// observation lands at (about) the declared rollover —
				// a true CD-cooldown reset the API was advertising.
				ra := time.Unix(last.RA, 0)
				if !ra.IsZero() && now.Sub(ra) <= quotaPassiveSlack && ra.Sub(now) <= quotaPassiveSlack {
					resetMark = "p"
				} else {
					resetMark = "a"
				}
			}
			// Legacy sample without a recorded reset_at: the reset type
			// cannot be determined — leave the mark empty ("unknown").
		}
	}
	var ra int64
	if !resetAtPrimary.IsZero() {
		ra = resetAtPrimary.Unix()
	}
	series = append(series, QuotaSample{T: now.Unix(), P: primary, S: secondary, L: limitReached, RA: ra, R: resetMark})

	cutoff := now.Add(-quotaHistoryRetention).Unix()
	trimmed := 0
	for trimmed < len(series) && series[trimmed].T < cutoff {
		trimmed++
	}
	if trimmed > 0 {
		series = append(series[:0], series[trimmed:]...)
	}
	if over := len(series) - quotaHistoryPerAuthCap; over > 0 {
		series = append(series[:0], series[over:]...)
	}
	s.data[authID] = series
	s.dirty = true
	s.saveLocked(now)
}

// ResetAt returns the primary-window reset time the API declared at this
// sample as a time.Time; zero when unknown (pre-marker history or API gap).
func (q QuotaSample) ResetAt() time.Time {
	if q.RA == 0 {
		return time.Time{}
	}
	return time.Unix(q.RA, 0)
}

// snapshot returns a copy of every series, optionally limited to samples newer
// than `since`. Zero `since` returns everything retained.
func (s *quotaHistoryStore) snapshot(since time.Time) map[string][]QuotaSample {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := int64(0)
	if !since.IsZero() {
		cutoff = since.Unix()
	}
	out := make(map[string][]QuotaSample, len(s.data))
	for id, series := range s.data {
		start := 0
		if cutoff > 0 {
			start = sort.Search(len(series), func(i int) bool { return series[i].T >= cutoff })
		}
		if start >= len(series) {
			continue
		}
		clone := make([]QuotaSample, len(series)-start)
		copy(clone, series[start:])
		out[id] = clone
	}
	return out
}

// saveLocked persists the store, debounced. Caller must hold s.mu.
func (s *quotaHistoryStore) saveLocked(now time.Time) {
	if s.path == "" || !s.dirty || now.Sub(s.lastSave) < quotaHistorySaveEvery {
		return
	}
	raw, err := json.Marshal(s.data)
	if err != nil {
		log.Warnf("monitor: encode quota history: %v", err)
		return
	}
	if errMkdir := os.MkdirAll(filepath.Dir(s.path), 0o755); errMkdir != nil {
		log.Warnf("monitor: create quota history dir: %v", errMkdir)
		return
	}
	tmp := s.path + ".tmp"
	if errWrite := os.WriteFile(tmp, raw, 0o600); errWrite != nil {
		log.Warnf("monitor: write quota history: %v", errWrite)
		return
	}
	if errRename := os.Rename(tmp, s.path); errRename != nil {
		log.Warnf("monitor: replace quota history: %v", errRename)
		return
	}
	s.lastSave = now
	s.dirty = false
}

// AttachQuotaHistory enables disk-backed quota history at the given path.
// Safe to call once during startup; a nil/empty path keeps history in memory.
func (r *Registry) AttachQuotaHistory(path string) {
	if r == nil {
		return
	}
	store := newQuotaHistoryStore(path)
	r.mu.Lock()
	r.quotaHistory = store
	r.mu.Unlock()
}

// RecordQuotaSample records one quota observation for authID. No-op until
// AttachQuotaHistory has been called. resetAtPrimary is the primary-window
// reset time the quota API declared for this snapshot (used to classify a
// later reset as passive vs active); pass the zero time when unknown.
func (r *Registry) RecordQuotaSample(authID string, primary, secondary int, limitReached bool, resetAtPrimary time.Time) {
	if r == nil {
		return
	}
	r.mu.RLock()
	store := r.quotaHistory
	r.mu.RUnlock()
	store.record(authID, primary, secondary, limitReached, resetAtPrimary, time.Now())
}

// QuotaHistorySnapshot returns the retained series, limited to the last `hours`
// when hours > 0.
func (r *Registry) QuotaHistorySnapshot(hours int) map[string][]QuotaSample {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	store := r.quotaHistory
	r.mu.RUnlock()
	var since time.Time
	if hours > 0 {
		since = time.Now().Add(-time.Duration(hours) * time.Hour)
	}
	return store.snapshot(since)
}
