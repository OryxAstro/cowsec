// Package setup serves the first-run wizard: a one-time HTTPS listener (self-signed,
// unlocked with a token printed on the server) that checks the host, collects the
// choices, creates the first account and runs the installer through cowsec-hostctl.
// Once setup is finished the listener is never started again.
package setup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OryxAstro/cowsec/internal/auth"
	"github.com/go-chi/chi/v5"
)

// Server is the setup wizard backend.
type Server struct {
	StateDir  string
	AuthState string // auth-state.json (accounts)
	Helper    string // cowsec-hostctl

	mu       sync.Mutex
	sessions map[string]time.Time
	fails    []time.Time
}

func (s *Server) path(name string) string { return filepath.Join(s.StateDir, name) }

// Complete reports whether setup has finished.
func Complete(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, "setup-complete"))
	return err == nil
}

// Token returns the one-time setup token, creating it on first use.
func Token(stateDir string) (string, error) {
	p := filepath.Join(stateDir, "setup-token")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	return tok, os.WriteFile(p, []byte(tok+"\n"), 0o600)
}

// SelfSignedTLS makes a throwaway certificate for the wizard and returns its SHA-256
// fingerprint so the admin can check it in the browser.
func SelfSignedTLS() (*tls.Config, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "CowSec setup (" + host + ")"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{host, "localhost"},
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				tmpl.IPAddresses = append(tmpl.IPAddresses, n.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, fmt.Sprintf("%X", sum), nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) gate(verb string, args ...string) ([]byte, error) {
	cmd := exec.Command(s.Helper)
	cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+strings.Join(append([]string{verb}, args...), " "), "SSH_CLIENT=setup 0 0",
		"COWSEC_STATE_DIR="+s.StateDir)
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if ee, ok := err.(*exec.ExitError); ok {
			msg = strings.TrimSpace(msg + " " + string(ee.Stderr))
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return out, nil
}

func (s *Server) passthrough(w http.ResponseWriter, verb string, args ...string) {
	out, err := s.gate(verb, args...)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out)
}

const cookie = "cowsec_setup"

func (s *Server) unlocked(r *http.Request) bool {
	c, err := r.Cookie(cookie)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	return ok && time.Now().Before(exp)
}

func (s *Server) requireUnlocked(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if Complete(s.StateDir) {
			writeJSON(w, http.StatusGone, map[string]string{"error": "Setup is already complete."})
			return
		}
		if !s.unlocked(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Enter the setup token first."})
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-CowSec-Request") != "1" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing request header"})
			return
		}
		next(w, r)
	}
}

// directorySignIn reports whether sign-in through LDAP is already configured (for example,
// carried over from an earlier install), in which case a local account is optional.
func directorySignIn() bool { return os.Getenv("COWSEC_LDAP_URL") != "" }

// Routes mounts /api/setup on the wizard listener.
func (s *Server) Routes(r chi.Router) {
	s.sessions = map[string]time.Time{}
	r.Get("/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"setupMode": true, "wizardOnThisListener": true, "complete": Complete(s.StateDir), "unlocked": s.unlocked(r),
			"accounts": len(auth.LocalAccounts(s.AuthState)) > 0, "directory": directorySignIn()})
	})
	r.Post("/unlock", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		cut := time.Now().Add(-15 * time.Minute)
		recent := s.fails[:0]
		for _, t := range s.fails {
			if t.After(cut) {
				recent = append(recent, t)
			}
		}
		s.fails = recent
		blocked := len(s.fails) >= 10
		s.mu.Unlock()
		if blocked {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Too many wrong tokens. Wait 15 minutes."})
			return
		}
		var req struct{ Token string }
		json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
		tok, err := Token(s.StateDir)
		if err != nil || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.Token)), []byte(tok)) != 1 {
			s.mu.Lock()
			s.fails = append(s.fails, time.Now())
			s.mu.Unlock()
			log.Printf("setup: wrong token from %s", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "That token is not right. Run `sudo cowsec-setup` on the server to see it."})
			return
		}
		buf := make([]byte, 24)
		rand.Read(buf)
		id := hex.EncodeToString(buf)
		s.mu.Lock()
		s.sessions[id] = time.Now().Add(4 * time.Hour)
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: cookie, Value: id, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	r.Get("/check", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) { s.passthrough(w, "setup-check") }))
	r.Get("/dns/providers", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) { s.passthrough(w, "dns-providers") }))
	r.Get("/dns/help", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		for _, ch := range code {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				writeJSON(w, 400, map[string]string{"error": "bad provider"})
				return
			}
		}
		s.passthrough(w, "dns-help", code)
	}))
	r.Post("/account", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Username, Password string }
		if json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req) != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if err := auth.CreateLocalAccount(s.AuthState, req.Username, req.Password); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("setup: local account %q created", req.Username)
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	r.Post("/install", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil || !json.Valid(body) {
			writeJSON(w, 400, map[string]string{"error": "invalid configuration"})
			return
		}
		if err := os.WriteFile(s.path("setup.pending.json"), body, 0o600); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if _, err := s.gate("job", "setup-install"); err != nil {
			os.Remove(s.path("setup.pending.json"))
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "started"})
	}))
	r.Get("/job", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) { s.passthrough(w, "job-state", "setup-install") }))
	// The mailcow admin password CowSec set when it installed mailcow; shown until Finish, then deleted.
	r.Get("/mailcow-admin", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(s.path("mailcow-admin.json"))
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"admin": nil})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		var v map[string]string
		if json.Unmarshal(b, &v) != nil {
			writeJSON(w, 200, map[string]interface{}{"admin": nil})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"admin": v})
	}))
	r.Post("/finish", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) {
		if len(auth.LocalAccounts(s.AuthState)) == 0 && !directorySignIn() {
			writeJSON(w, 400, map[string]string{"error": "Create an account first."})
			return
		}
		out, err := s.gate("job-state", "setup-install")
		var st struct{ State string }
		if err != nil || json.Unmarshal(out, &st) != nil || st.State != "ok" {
			writeJSON(w, 400, map[string]string{"error": "The installation has not finished successfully."})
			return
		}
		if err := os.WriteFile(s.path("setup-complete"), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		os.Remove(s.path("setup-token"))
		os.Remove(s.path("mailcow-admin.json"))
		log.Printf("setup: complete; restarting without the setup listener")
		writeJSON(w, 200, map[string]bool{"ok": true})
		go func() {
			time.Sleep(2 * time.Second)
			s.gate("action", "restart-cowsec")
		}()
	}))
}
