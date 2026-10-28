// Package auth implements CowSec's login: a local account (or an LDAP directory)
// for the password step, then TOTP or Duo Push as the second factor,
// cookie sessions, and an audit log of mutating API calls.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LocalAdmin is an account stored on this host (bcrypt). It works without any
// directory, and keeps working as a break-glass login if LDAP is unreachable.
type LocalAdmin struct {
	PasswordHash string    `json:"passwordHash"` // bcrypt
	CreatedAt    time.Time `json:"createdAt"`
}

// TOTPEnrollment is a confirmed authenticator-app secret for one user.
type TOTPEnrollment struct {
	Secret      string    `json:"secret"` // base32
	EnrolledAt  time.Time `json:"enrolledAt"`
	LastCounter int64     `json:"lastCounter"` // replay protection
}

type storedSession struct {
	User        string    `json:"user"`
	DisplayName string    `json:"displayName,omitempty"`
	Email       string    `json:"email,omitempty"`
	Source      string    `json:"source"` // ldap | local
	Method      string    `json:"method"` // totp | duo
	CreatedAt   time.Time `json:"createdAt"`
	IP          string    `json:"ip"`
}

type state struct {
	LocalAdmins map[string]*LocalAdmin     `json:"localAdmins"`
	TOTP        map[string]*TOTPEnrollment `json:"totp"`
	Sessions    map[string]*storedSession  `json:"sessions"` // keyed by sha256(token)
}

// Store persists auth state to a 0600 JSON file next to the server's .env.
type Store struct {
	mu      sync.Mutex
	path    string
	st      state
	modTime time.Time // of the file as last loaded/saved
}

func newState() state {
	return state{LocalAdmins: map[string]*LocalAdmin{}, TOTP: map[string]*TOTPEnrollment{}, Sessions: map[string]*storedSession{}}
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, st: newState()}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads the file; caller holds s.mu (or owns s exclusively).
func (s *Store) load() error {
	fi, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	st := newState()
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if st.LocalAdmins == nil {
		st.LocalAdmins = map[string]*LocalAdmin{}
	}
	if st.TOTP == nil {
		st.TOTP = map[string]*TOTPEnrollment{}
	}
	if st.Sessions == nil {
		st.Sessions = map[string]*storedSession{}
	}
	s.st, s.modTime = st, fi.ModTime()
	return nil
}

// refresh picks up changes made by the CLI while the server is running; caller holds s.mu.
func (s *Store) refresh() {
	if fi, err := os.Stat(s.path); err == nil && fi.ModTime().After(s.modTime) {
		_ = s.load()
	}
}

// save writes atomically; caller holds s.mu.
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.modTime = fi.ModTime()
	}
	return nil
}

func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) LocalAdmin(user string) (*LocalAdmin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	a, ok := s.st.LocalAdmins[user]
	return a, ok
}

func (s *Store) SetLocalAdmin(user, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	s.st.LocalAdmins[user] = &LocalAdmin{PasswordHash: hash, CreatedAt: time.Now()}
	return s.save()
}

func (s *Store) DeleteLocalAdmin(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	delete(s.st.LocalAdmins, user)
	return s.save()
}

func (s *Store) LocalAdminNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	out := []string{}
	for k := range s.st.LocalAdmins {
		out = append(out, k)
	}
	return out
}

func (s *Store) TOTP(user string) (*TOTPEnrollment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	t, ok := s.st.TOTP[user]
	if !ok {
		return nil, false
	}
	cp := *t
	return &cp, true
}

func (s *Store) SetTOTP(user, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	s.st.TOTP[user] = &TOTPEnrollment{Secret: secret, EnrolledAt: time.Now()}
	return s.save()
}

func (s *Store) DeleteTOTP(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	delete(s.st.TOTP, user)
	return s.save()
}

// UseTOTPCounter records an accepted TOTP time step; it refuses a step that
// was already used so a code cannot be replayed.
func (s *Store) UseTOTPCounter(user string, counter int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	t, ok := s.st.TOTP[user]
	if !ok || counter <= t.LastCounter {
		return false
	}
	t.LastCounter = counter
	_ = s.save()
	return true
}

func (s *Store) putSession(token string, sess *storedSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	s.st.Sessions[tokenKey(token)] = sess
	return s.save()
}

func (s *Store) session(token string) (*storedSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	sess, ok := s.st.Sessions[tokenKey(token)]
	return sess, ok
}

func (s *Store) deleteSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	delete(s.st.Sessions, tokenKey(token))
	_ = s.save()
}

// deleteUserSessions removes every session for a user (e.g. after a TOTP reset).
func (s *Store) deleteUserSessions(user string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	n := 0
	for k, v := range s.st.Sessions {
		if v.User == user {
			delete(s.st.Sessions, k)
			n++
		}
	}
	if n > 0 {
		_ = s.save()
	}
	return n
}

// deleteOtherSessions removes a user's sessions except the one for keepToken.
func (s *Store) deleteOtherSessions(user, keepToken string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	keep, n := tokenKey(keepToken), 0
	for k, v := range s.st.Sessions {
		if v.User == user && k != keep {
			delete(s.st.Sessions, k)
			n++
		}
	}
	if n > 0 {
		_ = s.save()
	}
	return n
}

// countUserSessions counts a user's sessions (including expired ones not yet pruned).
func (s *Store) countUserSessions(user string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	n := 0
	for _, v := range s.st.Sessions {
		if v.User == user {
			n++
		}
	}
	return n
}

// pruneSessions drops sessions older than maxAge.
func (s *Store) pruneSessions(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	changed := false
	for k, v := range s.st.Sessions {
		if time.Since(v.CreatedAt) > maxAge {
			delete(s.st.Sessions, k)
			changed = true
		}
	}
	if changed {
		_ = s.save()
	}
}
