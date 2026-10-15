package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName     = "cowsec_session"
	pendingTTL     = 5 * time.Minute
	maxMFAAttempts = 5
	failWindow     = 15 * time.Minute
	maxIPFailures  = 20
	maxUserFails   = 6
	csrfHeader     = "X-CowSec-Request"
	issuer         = "CowSec"
)

type ctxKey struct{}

// Identity is the signed-in user attached to each authenticated request.
type Identity struct {
	User        string    `json:"user"`
	DisplayName string    `json:"displayName"`
	Email       string    `json:"email"`
	Source      string    `json:"source"` // ldap | local
	Method      string    `json:"method"` // totp | duo
	CreatedAt   time.Time `json:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// FromContext returns the identity for an authenticated request.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

type pendingLogin struct {
	user, display, email, source string
	created                      time.Time
	attempts                     int
	enrollSecret                 string // set when the user must enrol TOTP first
	methods                      []string
}

type Config struct {
	StatePath      string
	AuditPath      string
	LDAP           LDAPConfig
	Duo            DuoConfig
	TrustedProxies []*net.IPNet
	IdleTimeout    time.Duration
	MaxAge         time.Duration
}

// ConfigFromEnv reads COWSEC_* settings (systemd loads /etc/cowsec/cowsec.env).
func ConfigFromEnv(baseDir string) Config {
	env := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	dur := func(k string, def time.Duration) time.Duration {
		if d, err := time.ParseDuration(env(k, "")); err == nil && d > 0 {
			return d
		}
		return def
	}
	cfg := Config{
		StatePath: env("COWSEC_AUTH_STATE", baseDir+"/auth-state.json"),
		AuditPath: env("COWSEC_AUDIT_LOG", baseDir+"/audit.log"),
		LDAP: LDAPConfig{
			URL:      env("COWSEC_LDAP_URL", ""),
			BaseDN:   env("COWSEC_LDAP_BASE_DN", ""),
			BindUser: env("COWSEC_LDAP_BIND_USER", ""),
			BindPwd:  env("COWSEC_LDAP_BIND_PWD", ""),
			Group:    env("COWSEC_LDAP_GROUP", "cowsec_admins"),

			TLSServerName: env("COWSEC_LDAP_TLS_SERVER_NAME", ""),
		},
		Duo:         DuoConfig{Host: env("COWSEC_DUO_HOST", ""), IKey: env("COWSEC_DUO_IKEY", ""), SKey: env("COWSEC_DUO_SKEY", "")},
		IdleTimeout: dur("COWSEC_SESSION_IDLE", 12*time.Hour),
		MaxAge:      dur("COWSEC_SESSION_MAX_AGE", 7*24*time.Hour),
	}
	for _, c := range strings.Split(env("COWSEC_TRUSTED_PROXIES", ""), ",") {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			cfg.TrustedProxies = append(cfg.TrustedProxies, n)
		}
	}
	return cfg
}

type Service struct {
	cfg   Config
	store *Store

	mu       sync.Mutex
	pending  map[string]*pendingLogin
	lastSeen map[string]time.Time // sha256(token) -> last request
	ipFails  map[string][]time.Time
	userFail map[string][]time.Time

	auditMu sync.Mutex
}

func New(cfg Config) (*Service, error) {
	st, err := OpenStore(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("auth state %s: %w", cfg.StatePath, err)
	}
	s := &Service{cfg: cfg, store: st, pending: map[string]*pendingLogin{}, lastSeen: map[string]time.Time{},
		ipFails: map[string][]time.Time{}, userFail: map[string][]time.Time{}}
	st.pruneSessions(cfg.MaxAge)
	if !cfg.LDAP.Enabled() && len(st.LocalAdminNames()) == 0 {
		log.Printf("⚠️  auth: no LDAP configured (COWSEC_LDAP_URL/COWSEC_LDAP_BASE_DN) and no local admin; run `cowsec auth local-admin set <name>`")
	}
	return s, nil
}

// ---------- request helpers ----------

func (s *Service) trusted(ip net.IP) bool {
	for _, n := range s.cfg.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Service) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && s.trusted(ip) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	return host
}

func (s *Service) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	return ip != nil && s.trusted(ip) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---------- rate limiting ----------

func prune(ts []time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if time.Since(t) < failWindow {
			out = append(out, t)
		}
	}
	return out
}

func (s *Service) limited(ip, user string) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipFails[ip] = prune(s.ipFails[ip])
	s.userFail[user] = prune(s.userFail[user])
	check := func(ts []time.Time, max int) (bool, time.Duration) {
		if len(ts) >= max {
			return true, failWindow - time.Since(ts[0])
		}
		return false, 0
	}
	if b, d := check(s.ipFails[ip], maxIPFailures); b {
		return b, d
	}
	return check(s.userFail[user], maxUserFails)
}

func (s *Service) recordFailure(ip, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipFails[ip] = append(s.ipFails[ip], time.Now())
	s.userFail[user] = append(s.userFail[user], time.Now())
}

func (s *Service) clearFailures(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.userFail, user)
}

// ---------- audit ----------

type AuditEntry struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`
	User   string    `json:"user,omitempty"`
	IP     string    `json:"ip,omitempty"`
	Method string    `json:"method,omitempty"`
	Path   string    `json:"path,omitempty"`
	Status int       `json:"status,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

func (s *Service) audit(e AuditEntry) {
	e.Time = time.Now()
	line, _ := json.Marshal(e)
	log.Printf("audit: %s", line)
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	f, err := os.OpenFile(s.cfg.AuditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// RecentAudit returns up to limit entries, newest first.
func (s *Service) RecentAudit(limit int) []AuditEntry {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	f, err := os.Open(s.cfg.AuditPath)
	if err != nil {
		return []AuditEntry{}
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > 512*1024 {
		_, _ = f.Seek(fi.Size()-512*1024, 0)
	}
	var all []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Event != "" {
			all = append(all, e)
		}
	}
	out := []AuditEntry{}
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out
}

// ---------- sessions ----------

func (s *Service) createSession(w http.ResponseWriter, r *http.Request, p *pendingLogin, method string) Identity {
	token := randomToken(32)
	sess := &storedSession{User: p.user, DisplayName: p.display, Email: p.email, Source: p.source, Method: method, CreatedAt: time.Now(), IP: s.clientIP(r)}
	_ = s.store.putSession(token, sess)
	s.mu.Lock()
	s.lastSeen[tokenKey(token)] = time.Now()
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: s.isHTTPS(r), MaxAge: int(s.cfg.MaxAge.Seconds()),
	})
	s.clearFailures(p.user)
	s.audit(AuditEntry{Event: "login_success", User: p.user, IP: sess.IP, Detail: p.source + "+" + method})
	return s.identity(sess)
}

func (s *Service) identity(sess *storedSession) Identity {
	id := Identity{User: sess.User, DisplayName: sess.DisplayName, Email: sess.Email, Source: sess.Source,
		Method: sess.Method, CreatedAt: sess.CreatedAt, ExpiresAt: sess.CreatedAt.Add(s.cfg.MaxAge)}
	if id.DisplayName == "" {
		id.DisplayName = sess.User
	}
	return id
}

// sessionFor validates the cookie (exists, not past max age or idle timeout).
func (s *Service) sessionFor(r *http.Request) (string, *storedSession, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return "", nil, false
	}
	sess, ok := s.store.session(c.Value)
	if !ok {
		return "", nil, false
	}
	key := tokenKey(c.Value)
	s.mu.Lock()
	last, seen := s.lastSeen[key]
	if !seen {
		last = time.Now() // first request after a server restart
	}
	expired := time.Since(sess.CreatedAt) > s.cfg.MaxAge || time.Since(last) > s.cfg.IdleTimeout
	if !expired {
		s.lastSeen[key] = time.Now()
	} else {
		delete(s.lastSeen, key)
	}
	s.mu.Unlock()
	if expired {
		s.store.deleteSession(c.Value)
		return "", nil, false
	}
	return c.Value, sess, true
}

// ---------- middleware ----------

var publicPaths = map[string]bool{
	"/api/auth/config": true, "/api/auth/login": true, "/api/auth/verify": true,
	"/api/auth/enroll": true, "/api/auth/me": true, "/api/auth/logout": true,
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

// Flush keeps streaming responses working through the recorder.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware requires a session for every /api route except the login flow,
// enforces the CSRF header on state-changing requests, and audits them.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		// A custom header cannot be sent cross-origin without a CORS preflight we never allow,
		// so this blocks CSRF from other sites, including sibling apps on the same parent domain.
		if mutating && r.Header.Get(csrfHeader) != "1" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing " + csrfHeader + " header"})
			return
		}
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		_, sess, ok := s.sessionFor(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		id := s.identity(sess)
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, id))
		if !mutating {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.audit(AuditEntry{Event: "api", User: id.User, IP: s.clientIP(r), Method: r.Method, Path: r.URL.RequestURI(), Status: rec.status})
	})
}

// ---------- login flow handlers ----------

func decode(r *http.Request, v interface{}) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 16*1024)).Decode(v)
}

func (s *Service) HandleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"service": "cowsec", "ldap": s.cfg.LDAP.Enabled(), "duo": s.cfg.Duo.Enabled(),
		"localAdmin": len(s.store.LocalAdminNames()) > 0, "group": s.cfg.LDAP.Group,
	})
}

func (s *Service) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if decode(r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	login := strings.TrimSpace(req.Username)
	ip := s.clientIP(r)
	if blocked, wait := s.limited(ip, strings.ToLower(login)); blocked {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", int(wait.Minutes())+1)})
		return
	}
	fail := func(status int, msg, reason string) {
		s.recordFailure(ip, strings.ToLower(login))
		s.audit(AuditEntry{Event: "login_failed", User: login, IP: ip, Detail: reason})
		writeJSON(w, status, map[string]string{"error": msg})
	}

	p := &pendingLogin{created: time.Now()}
	if admin, ok := s.store.LocalAdmin(login); ok {
		if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)) != nil {
			fail(http.StatusUnauthorized, "Invalid username or password.", "local: bad password")
			return
		}
		p.user, p.display, p.source = login, login, "local"
	} else if s.cfg.LDAP.Enabled() {
		u, err := authenticateLDAP(s.cfg.LDAP, login, req.Password)
		switch {
		case errors.Is(err, errBadCredentials):
			fail(http.StatusUnauthorized, "Invalid username or password.", "ldap: bad credentials")
			return
		case errors.Is(err, errNotInGroup):
			fail(http.StatusForbidden, "Your account is not allowed to use CowSec (not in the "+s.cfg.LDAP.Group+" group).", "ldap: not in group")
			return
		case err != nil:
			s.audit(AuditEntry{Event: "login_failed", User: login, IP: ip, Detail: err.Error()})
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "The directory (LDAP) is unavailable. Use a local account."})
			return
		}
		p.user, p.display, p.email, p.source = u.UID, u.DisplayName, u.Email, "ldap"
	} else {
		fail(http.StatusUnauthorized, "Invalid username or password.", "no matching account")
		return
	}

	// Second factor: enrolled TOTP and/or Duo (directory users only).
	if _, ok := s.store.TOTP(p.user); ok {
		p.methods = append(p.methods, "totp")
	}
	if p.source == "ldap" && s.cfg.Duo.Enabled() {
		if res, _, err := s.cfg.Duo.duoPreauth(p.user); err == nil && res == "auth" {
			p.methods = append(p.methods, "duo")
		}
	}
	token := randomToken(24)
	resp := map[string]interface{}{"pendingToken": token, "user": p.user, "displayName": p.display}
	if len(p.methods) == 0 {
		secret, err := NewTOTPSecret()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create secret"})
			return
		}
		p.enrollSecret = secret
		otp := otpauthURL(issuer, p.user, secret)
		resp["stage"], resp["secret"], resp["otpauthUrl"], resp["qr"] = "enroll", secret, otp, qrDataURI(otp)
	} else {
		resp["stage"], resp["methods"] = "mfa", p.methods
	}
	s.mu.Lock()
	for k, v := range s.pending {
		if time.Since(v.created) > pendingTTL {
			delete(s.pending, k)
		}
	}
	s.pending[token] = p
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) takePending(token string) (*pendingLogin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[token]
	if !ok || time.Since(p.created) > pendingTTL {
		delete(s.pending, token)
		return nil, false
	}
	return p, true
}

func (s *Service) mfaFailed(w http.ResponseWriter, r *http.Request, token string, p *pendingLogin, msg string) {
	s.mu.Lock()
	p.attempts++
	gone := p.attempts >= maxMFAAttempts
	if gone {
		delete(s.pending, token)
	}
	s.mu.Unlock()
	s.recordFailure(s.clientIP(r), strings.ToLower(p.user))
	s.audit(AuditEntry{Event: "mfa_failed", User: p.user, IP: s.clientIP(r), Detail: msg})
	if gone {
		msg = "Too many incorrect codes. Please sign in again."
	}
	writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": msg, "restart": gone})
}

func (s *Service) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct{ PendingToken, Code string }
	if decode(r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	p, ok := s.takePending(req.PendingToken)
	if !ok || p.enrollSecret == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "Sign-in expired. Please start again.", "restart": true})
		return
	}
	counter := verifyTOTP(p.enrollSecret, req.Code, time.Now())
	if counter < 0 {
		s.mfaFailed(w, r, req.PendingToken, p, "That code didn't match. Check your authenticator app's clock and try again.")
		return
	}
	if err := s.store.SetTOTP(p.user, p.enrollSecret); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save enrolment"})
		return
	}
	s.store.UseTOTPCounter(p.user, counter)
	s.mu.Lock()
	delete(s.pending, req.PendingToken)
	s.mu.Unlock()
	s.audit(AuditEntry{Event: "totp_enrolled", User: p.user, IP: s.clientIP(r)})
	writeJSON(w, http.StatusOK, s.createSession(w, r, p, "totp"))
}

func (s *Service) HandleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct{ PendingToken, Method, Code string }
	if decode(r, &req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	p, ok := s.takePending(req.PendingToken)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "Sign-in expired. Please start again.", "restart": true})
		return
	}
	allowed := false
	for _, m := range p.methods {
		allowed = allowed || m == req.Method
	}
	if !allowed {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "method not available"})
		return
	}
	switch req.Method {
	case "totp":
		t, ok := s.store.TOTP(p.user)
		counter := int64(-1)
		if ok {
			counter = verifyTOTP(t.Secret, req.Code, time.Now())
		}
		if counter < 0 || !s.store.UseTOTPCounter(p.user, counter) {
			s.mfaFailed(w, r, req.PendingToken, p, "Invalid or already-used code.")
			return
		}
	case "duo":
		approved, msg, err := s.cfg.Duo.duoPush(p.user, s.clientIP(r))
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Duo is unavailable: " + err.Error()})
			return
		}
		if !approved {
			if msg == "" {
				msg = "Duo push was denied or timed out."
			}
			s.mfaFailed(w, r, req.PendingToken, p, msg)
			return
		}
	}
	s.mu.Lock()
	delete(s.pending, req.PendingToken)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.createSession(w, r, p, req.Method))
}

func (s *Service) HandleMe(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := s.sessionFor(r)
	if !ok {
		// Not signed in is a normal answer here (the UI asks on every load), not an error.
		writeJSON(w, http.StatusOK, map[string]interface{}{"identity": nil})
		return
	}
	_, enrolled := s.store.TOTP(sess.User)
	writeJSON(w, http.StatusOK, map[string]interface{}{"identity": s.identity(sess), "totpEnrolled": enrolled,
		"idleTimeoutSec": int(s.cfg.IdleTimeout.Seconds())})
}

func (s *Service) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if token, sess, ok := s.sessionFor(r); ok {
		s.store.deleteSession(token)
		s.audit(AuditEntry{Event: "logout", User: sess.User, IP: s.clientIP(r)})
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

// HandleResetTOTP removes the caller's authenticator (after proving the current
// code) and signs out all their sessions; the next login re-enrols.
func (s *Service) HandleResetTOTP(w http.ResponseWriter, r *http.Request) {
	id, _ := FromContext(r.Context())
	var req struct{ Code string }
	_ = decode(r, &req)
	t, ok := s.store.TOTP(id.User)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No authenticator is enrolled."})
		return
	}
	if verifyTOTP(t.Secret, req.Code, time.Now()) < 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid code."})
		return
	}
	_ = s.store.DeleteTOTP(id.User)
	n := s.store.deleteUserSessions(id.User)
	s.audit(AuditEntry{Event: "totp_reset", User: id.User, IP: s.clientIP(r), Detail: fmt.Sprintf("%d session(s) ended", n)})
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

func (s *Service) HandleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.RecentAudit(200))
}
