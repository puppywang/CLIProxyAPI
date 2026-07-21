package monitor

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"
)

// Settings carries operator-tunable knobs for the monitor subsystem. All
// fields are JSON-serialisable so the same struct can be exchanged with
// clients and persisted to disk.
type Settings struct {
	// StallTimeoutSeconds auto-cancels any non-terminal request that has had
	// no response activity (no new response bytes) for at least this many
	// seconds. Zero disables auto-cancel.
	StallTimeoutSeconds int `json:"stall_timeout_seconds"`

	// SlowWindowSeconds and SlowMinBytes form the throughput floor for the
	// slow-stream watchdog. Once a streaming response has begun producing
	// bytes, any rolling window of SlowWindowSeconds during which fewer than
	// SlowMinBytes new response bytes arrive causes the request to be
	// auto-cancelled (ReasonSlow). This catches "trickle" streams that never
	// go silent long enough to trip StallTimeoutSeconds but deliver almost
	// nothing over time. Both must be > 0 for the watchdog to run; either at
	// zero disables it.
	SlowWindowSeconds int `json:"slow_window_seconds"`
	SlowMinBytes      int `json:"slow_min_bytes"`
}

// SettingsStore loads and persists Settings to a JSON file.
type SettingsStore struct {
	path   string
	mu     sync.RWMutex
	values Settings
}

// NewSettingsStore creates a settings store backed by the given file. If the
// file is empty or missing, defaults are used and a save is attempted.
func NewSettingsStore(path string) *SettingsStore {
	s := &SettingsStore{path: path}
	s.load()
	return s
}

func (s *SettingsStore) load() {
	if s.path == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			// Best-effort: keep defaults, but surface the read failure for ops.
			log.WithError(err).WithField("path", s.path).Warn("monitor: failed to read settings")
		}
		return
	}
	var v Settings
	if errDecode := json.Unmarshal(data, &v); errDecode != nil {
		log.WithError(errDecode).WithField("path", s.path).Warn("monitor: failed to parse settings")
		return
	}
	s.mu.Lock()
	s.values = v
	s.mu.Unlock()
}

// Get returns the current settings snapshot.
func (s *SettingsStore) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.values
}

// Set replaces the current settings and persists them. Returns an error only
// if the on-disk save fails; the in-memory value is updated regardless.
func (s *SettingsStore) Set(v Settings) error {
	if v.StallTimeoutSeconds < 0 {
		v.StallTimeoutSeconds = 0
	}
	if v.SlowWindowSeconds < 0 {
		v.SlowWindowSeconds = 0
	}
	if v.SlowMinBytes < 0 {
		v.SlowMinBytes = 0
	}
	s.mu.Lock()
	s.values = v
	s.mu.Unlock()
	return s.persist()
}

func (s *SettingsStore) persist() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	payload, err := json.MarshalIndent(s.values, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if errMk := os.MkdirAll(dir, 0o755); errMk != nil {
			return errMk
		}
	}
	tmp := s.path + ".tmp"
	if errWrite := os.WriteFile(tmp, append(payload, '\n'), 0o600); errWrite != nil {
		return errWrite
	}
	return os.Rename(tmp, s.path)
}
