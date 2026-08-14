package executor

import (
	"strings"
	"sync"
	"time"
)

const (
	cursorAgentSessionTTL     = 10 * time.Minute
	cursorAgentSessionMaxIdle = 256
)

type cursorAgentSession struct {
	Key        string
	AuthID     string
	Model      string
	Transport  cursorAgentTransport
	Pending    []cursorPendingCall
	LastUsed   time.Time
	Generation int
}

type cursorAgentSessionStore struct {
	mu      sync.Mutex
	items   map[string]*cursorAgentSession
	cleanup sync.Once
}

func newCursorAgentSessionStore() *cursorAgentSessionStore {
	return &cursorAgentSessionStore{items: make(map[string]*cursorAgentSession)}
}

var cursorAgentSessions = newCursorAgentSessionStore()

func cursorAgentSessionKey(authID, anchor string) string {
	if authID == "" {
		authID = "_"
	}
	if anchor == "" {
		anchor = "_"
	}
	return authID + "\x1e" + anchor
}

func (s *cursorAgentSessionStore) get(key string) *cursorAgentSession {
	if s == nil || key == "" {
		return nil
	}
	s.startCleanup()
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.items[key]
	if sess == nil {
		return nil
	}
	if now.Sub(sess.LastUsed) > cursorAgentSessionTTL {
		s.removeLocked(key)
		return nil
	}
	sess.LastUsed = now
	return sess
}

func (s *cursorAgentSessionStore) put(sess *cursorAgentSession) {
	if s == nil || sess == nil || sess.Key == "" {
		return
	}
	s.startCleanup()
	now := time.Now()
	sess.LastUsed = now
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.items[sess.Key]; existing != nil && existing != sess {
		if existing.Transport != nil {
			_ = existing.Transport.Close()
		}
	}
	if len(s.items) >= cursorAgentSessionMaxIdle {
		s.evictLocked(now)
	}
	s.items[sess.Key] = sess
}

func (s *cursorAgentSessionStore) drop(key string) {
	if s == nil || key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(key)
}

func (s *cursorAgentSessionStore) dropAnchor(anchor string) {
	anchor = strings.TrimSpace(anchor)
	if s == nil || anchor == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	suffix := "\x1e" + anchor
	for key := range s.items {
		if strings.HasSuffix(key, suffix) {
			s.removeLocked(key)
		}
	}
}

func (s *cursorAgentSessionStore) closeAll() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.items {
		s.removeLocked(key)
	}
}

func (s *cursorAgentSessionStore) removeLocked(key string) {
	sess := s.items[key]
	if sess == nil {
		return
	}
	delete(s.items, key)
	if sess.Transport != nil {
		_ = sess.Transport.Close()
	}
}

func (s *cursorAgentSessionStore) evictLocked(now time.Time) {
	for key, sess := range s.items {
		if now.Sub(sess.LastUsed) > cursorAgentSessionTTL {
			s.removeLocked(key)
		}
	}
	for len(s.items) >= cursorAgentSessionMaxIdle {
		var oldestKey string
		var oldest time.Time
		for key, sess := range s.items {
			if oldestKey == "" || sess.LastUsed.Before(oldest) {
				oldestKey = key
				oldest = sess.LastUsed
			}
		}
		if oldestKey == "" {
			return
		}
		s.removeLocked(oldestKey)
	}
}

func (s *cursorAgentSessionStore) startCleanup() {
	s.cleanup.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				s.mu.Lock()
				for key, sess := range s.items {
					if now.Sub(sess.LastUsed) > cursorAgentSessionTTL {
						s.removeLocked(key)
					}
				}
				s.mu.Unlock()
			}
		}()
	})
}
