package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// selfServiceRig is a signed-in local account "alice" with two sessions and an
// authenticator, behind the real middleware and routes.
func selfServiceRig(t *testing.T) (*Service, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{StatePath: filepath.Join(dir, "auth.json"), AuditPath: filepath.Join(dir, "audit.log"), IdleTimeout: time.Hour, MaxAge: 24 * time.Hour}
	if err := CreateLocalAccount(cfg.StatePath, "alice", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.store.SetTOTP("alice", rfcSecret)
	for _, tok := range []string{"this-session", "other-session"} {
		_ = s.store.putSession(tok, &storedSession{User: "alice", Source: "local", Method: "totp", CreatedAt: time.Now()})
	}
	r := chi.NewRouter()
	r.Use(s.Middleware)
	r.Route("/api/auth", s.Routes)
	return s, r
}

func call(t *testing.T, h http.Handler, path string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
	req.Header.Set("X-CowSec-Request", "1")
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "this-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func nowCode(secret string) string {
	c, _ := totpCode(secret, time.Now().Unix()/totpPeriod)
	return c
}

func TestChangePasswordLocal(t *testing.T) {
	s, h := selfServiceRig(t)
	if code, _ := call(t, h, "/api/auth/password", map[string]string{"current": "wrong password!!", "next": "a brand new passphrase"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong current password: got %d, want 401", code)
	}
	if code, _ := call(t, h, "/api/auth/password", map[string]string{"current": "correct horse battery", "next": "too short"}); code != http.StatusBadRequest {
		t.Fatalf("short new password: got %d, want 400", code)
	}
	code, out := call(t, h, "/api/auth/password", map[string]string{"current": "correct horse battery", "next": "a brand new passphrase"})
	if code != http.StatusOK || out["endedSessions"] != float64(1) {
		t.Fatalf("change: got %d %v", code, out)
	}
	if s.checkPassword(Identity{User: "alice", Source: "local"}, "a brand new passphrase") != nil {
		t.Fatal("new password should work")
	}
	if _, ok := s.store.session("other-session"); ok {
		t.Fatal("other sessions should be signed out")
	}
	if _, ok := s.store.session("this-session"); !ok {
		t.Fatal("the current session should stay signed in")
	}
}

func TestReenrolAuthenticator(t *testing.T) {
	s, h := selfServiceRig(t)
	if code, _ := call(t, h, "/api/auth/totp/begin", map[string]string{"code": "000000"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong current code: got %d, want 401", code)
	}
	code, begun := call(t, h, "/api/auth/totp/begin", map[string]string{"code": nowCode(rfcSecret)})
	if code != http.StatusOK {
		t.Fatalf("begin: got %d %v", code, begun)
	}
	secret, _ := begun["secret"].(string)
	token, _ := begun["token"].(string)
	if secret == "" || secret == rfcSecret || !strings.HasPrefix(begun["qr"].(string), "data:image/png") {
		t.Fatalf("begin should return a fresh secret and QR: %v", begun)
	}
	if code, _ := call(t, h, "/api/auth/totp/confirm", map[string]string{"token": "not-it", "code": nowCode(secret)}); code != http.StatusBadRequest {
		t.Fatalf("wrong token: got %d, want 400", code)
	}
	if code, _ := call(t, h, "/api/auth/totp/confirm", map[string]string{"token": token, "code": nowCode(secret)}); code != http.StatusOK {
		t.Fatalf("confirm: got %d", code)
	}
	if t2, _ := s.store.TOTP("alice"); t2.Secret != secret {
		t.Fatal("the new authenticator should replace the old one")
	}
	if _, ok := s.store.session("other-session"); ok {
		t.Fatal("other sessions should be signed out")
	}
}

func TestSelfServiceNeedsSessionAndHeader(t *testing.T) {
	_, h := selfServiceRig(t)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "this-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("without the CSRF header: got %d, want 403", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/auth/sessions/end-others", nil)
	req.Header.Set("X-CowSec-Request", "1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without a session: got %d, want 401", rec.Code)
	}
}
