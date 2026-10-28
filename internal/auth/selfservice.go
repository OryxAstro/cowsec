package auth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Self-service for the signed-in user: change their password (local accounts, or the
// directory's own password for LDAP accounts), set up a new authenticator without
// signing out first, and sign out their other sessions.

const reenrolTTL = 10 * time.Minute

type reenrol struct {
	token, secret string
	created       time.Time
}

// checkPassword verifies the signed-in user's current password against their account.
func (s *Service) checkPassword(id Identity, password string) error {
	if id.Source == "local" {
		admin, ok := s.store.LocalAdmin(id.User)
		if !ok || bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)) != nil {
			return errBadCredentials
		}
		return nil
	}
	_, err := authenticateLDAP(s.cfg.LDAP, id.User, password)
	return err
}

// guard applies the sign-in rate limit to a self-service check and records a failure.
func (s *Service) guard(w http.ResponseWriter, r *http.Request, id Identity, event string, check func() error) bool {
	ip := s.clientIP(r)
	if blocked, wait := s.limited(ip, id.User); blocked {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", int(wait.Minutes())+1)})
		return false
	}
	err := check()
	switch {
	case err == nil:
		return true
	case errors.Is(err, errBadCredentials):
		s.recordFailure(ip, id.User)
		s.audit(AuditEntry{Event: event, User: id.User, IP: ip, Detail: "wrong current password or code"})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "That isn't right. Check it and try again."})
	default:
		s.audit(AuditEntry{Event: event, User: id.User, IP: ip, Detail: err.Error()})
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
	}
	return false
}

func (s *Service) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	id, _ := FromContext(r.Context())
	var req struct{ Current, Next string }
	if decode(r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if len(req.Next) < 12 || len(req.Next) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The new password must be 12 to 128 characters."})
		return
	}
	if req.Next == req.Current {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The new password is the same as the current one."})
		return
	}
	if id.Source == "ldap" {
		if !s.guard(w, r, id, "password_change_failed", func() error { return changeLDAPPassword(s.cfg.LDAP, id.User, req.Current, req.Next) }) {
			return
		}
	} else {
		if !s.guard(w, r, id, "password_change_failed", func() error { return s.checkPassword(id, req.Current) }) {
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Next), 12)
		if err != nil || s.store.SetLocalAdmin(id.User, string(hash)) != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save the new password"})
			return
		}
	}
	token, _, _ := s.sessionFor(r)
	n := s.store.deleteOtherSessions(id.User, token)
	s.audit(AuditEntry{Event: "password_changed", User: id.User, IP: s.clientIP(r), Detail: fmt.Sprintf("%s · %d other session(s) ended", id.Source, n)})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "changed", "endedSessions": n})
}

// HandleTOTPBegin starts setting up a new authenticator. The user proves who they are
// with a code from the current one, or with their password when none is enrolled.
func (s *Service) HandleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	id, _ := FromContext(r.Context())
	var req struct{ Code, Password string }
	if decode(r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if !s.guard(w, r, id, "totp_reenrol_failed", func() error {
		if t, ok := s.store.TOTP(id.User); ok {
			if c := verifyTOTP(t.Secret, req.Code, time.Now()); c < 0 || !s.store.UseTOTPCounter(id.User, c) {
				return errBadCredentials
			}
			return nil
		}
		return s.checkPassword(id, req.Password)
	}) {
		return
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create secret"})
		return
	}
	p := &reenrol{token: randomToken(24), secret: secret, created: time.Now()}
	s.mu.Lock()
	s.reenrols[id.User] = p
	s.mu.Unlock()
	otp := otpauthURL(issuer, id.User, secret)
	writeJSON(w, http.StatusOK, map[string]string{"token": p.token, "secret": secret, "otpauthUrl": otp, "qr": qrDataURI(otp)})
}

// HandleTOTPConfirm swaps in the new authenticator once it has produced a valid code,
// then signs out the user's other sessions.
func (s *Service) HandleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	id, _ := FromContext(r.Context())
	var req struct{ Token, Code string }
	if decode(r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	s.mu.Lock()
	p, ok := s.reenrols[id.User]
	if ok && (p.token != req.Token || time.Since(p.created) > reenrolTTL) {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "This setup has expired. Start again.", "restart": true})
		return
	}
	counter := verifyTOTP(p.secret, req.Code, time.Now())
	if counter < 0 {
		s.recordFailure(s.clientIP(r), id.User)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "That code didn't match. Check your authenticator app's clock and try again."})
		return
	}
	if err := s.store.SetTOTP(id.User, p.secret); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save the authenticator"})
		return
	}
	s.store.UseTOTPCounter(id.User, counter)
	s.mu.Lock()
	delete(s.reenrols, id.User)
	s.mu.Unlock()
	token, _, _ := s.sessionFor(r)
	n := s.store.deleteOtherSessions(id.User, token)
	s.audit(AuditEntry{Event: "totp_enrolled", User: id.User, IP: s.clientIP(r), Detail: fmt.Sprintf("new authenticator · %d other session(s) ended", n)})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "enrolled", "endedSessions": n})
}

func (s *Service) HandleEndOtherSessions(w http.ResponseWriter, r *http.Request) {
	id, _ := FromContext(r.Context())
	token, _, _ := s.sessionFor(r)
	n := s.store.deleteOtherSessions(id.User, token)
	s.audit(AuditEntry{Event: "sessions_ended", User: id.User, IP: s.clientIP(r), Detail: fmt.Sprintf("%d other session(s)", n)})
	writeJSON(w, http.StatusOK, map[string]int{"endedSessions": n})
}
