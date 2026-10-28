// CowSec: a web console for CrowdSec on a mailcow host. It manages the local CrowdSec
// with cscli, uses the cowsec-hostctl helper for system-level work, and has its own
// sign-in (local accounts or LDAP, plus TOTP or Duo).
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OryxAstro/cowsec/internal/auth"
	"github.com/OryxAstro/cowsec/internal/crowdsec"
	"github.com/OryxAstro/cowsec/internal/geo"
	"github.com/OryxAstro/cowsec/internal/mailcow"
	"github.com/OryxAstro/cowsec/internal/setup"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var version = "dev"

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	stateDir := env("COWSEC_STATE_DIR", "/var/lib/cowsec")
	cfg := auth.ConfigFromEnv(stateDir)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "auth": // `cowsec auth ...` manages local accounts and authenticators
			os.Exit(auth.RunCLI(os.Args[2:], cfg.StatePath))
		case "version", "--version":
			fmt.Println("cowsec", version)
			return
		}
	}

	authSvc, err := auth.New(cfg)
	if err != nil {
		log.Fatalf("auth: %v", err) // fail closed
	}
	geoDB := geo.New(env("COWSEC_GEOIP_DIR", "/var/lib/crowdsec/data"))
	host := crowdsec.New(
		env("COWSEC_TARGET_ID", "local"),
		env("COWSEC_TARGET_NAME", "Mail server"),
		env("COWSEC_TARGET_DESCRIPTION", "mailcow · CrowdSec"),
		env("COWSEC_HELPER", "/usr/lib/cowsec/cowsec-hostctl"),
		stateDir,
		geoDB,
	)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(authSvc.Middleware)
	r.Route("/api", func(r chi.Router) {
		r.Route("/auth", authSvc.Routes)
		r.Route("/crowdsec", func(cr chi.Router) { crowdsec.Routes(cr, host) })
		mc := mailcow.FromEnv()
		if mc != nil {
			host.OnUnban = func(v string) {
				if err := mc.Unban(v); err != nil {
					log.Printf("mailcow netfilter unban %s: %v", v, err)
				}
			}
		}
		opts := mailcow.Options{Gate: host.Gate, StateDir: stateDir,
			Geo: func(ip string) *mailcow.GeoInfo {
				i := geoDB.One(ip)
				if i.Status != "success" {
					return nil
				}
				return &mailcow.GeoInfo{CountryCode: i.CountryCode, Country: i.Country, Org: i.Org, LAN: i.IsLAN}
			},
			BanStatus: func(ip string) *mailcow.Ban {
				ds, _, err := host.GetDecisions("", ip, 5, 0)
				if err != nil {
					return nil
				}
				for _, d := range ds {
					if d.Type == "ban" && !d.Simulated {
						return &mailcow.Ban{Banned: true, Duration: d.Duration, Origin: d.Origin}
					}
				}
				return &mailcow.Ban{}
			},
			Ban: func(ip, duration, reason string) error {
				_, err := host.AddDecision(ip, duration, reason, "ban")
				return err
			},
			Unban: func(ip string) error {
				_, err := host.DeleteDecision(ip, "")
				if host.OnUnban != nil {
					host.OnUnban(ip)
				}
				return err
			},
		}
		r.Route("/mailcow", func(mr chi.Router) { mailcow.Routes(mr, mc, opts) })
		r.Get("/about", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"version":%q}`, version)
		})
	})

	uiDir := env("COWSEC_UI_DIR", "/usr/share/cowsec/ui")
	files := http.FileServer(http.Dir(uiDir))
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		p := filepath.Join(uiDir, filepath.Clean("/"+req.URL.Path))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			http.ServeFile(w, req, filepath.Join(uiDir, "index.html"))
			return
		}
		files.ServeHTTP(w, req)
	})

	// The setup state is public on the console too, so the UI can point at the wizard.
	top := http.NewServeMux()
	top.HandleFunc("/api/setup/state", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"setupMode":%t,"wizardOnThisListener":false}`, !setup.Complete(stateDir))
	})
	top.Handle("/", r)

	if !setup.Complete(stateDir) {
		go serveSetup(stateDir, cfg.StatePath, uiDir)
	}
	listen := env("COWSEC_LISTEN", "127.0.0.1:8090")
	log.Printf("CowSec %s listening on http://%s (UI %s)", version, listen, uiDir)
	log.Fatal(http.ListenAndServe(listen, top))
}

// serveSetup runs the one-time setup wizard on its own HTTPS listener.
func serveSetup(stateDir, authState, uiDir string) {
	tok, err := setup.Token(stateDir)
	if err != nil {
		log.Printf("setup: cannot create token: %v", err)
		return
	}
	tlsCfg, fp, err := setup.SelfSignedTLS()
	if err != nil {
		log.Printf("setup: cannot create certificate: %v", err)
		return
	}
	s := &setup.Server{StateDir: stateDir, AuthState: authState, Helper: env("COWSEC_HELPER", "/usr/lib/cowsec/cowsec-hostctl")}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Route("/api/setup", s.Routes)
	files := http.FileServer(http.Dir(uiDir))
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		p := filepath.Join(uiDir, filepath.Clean("/"+req.URL.Path))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			w.Header().Set("Cache-Control", "no-store")
			http.ServeFile(w, req, filepath.Join(uiDir, "index.html"))
			return
		}
		files.ServeHTTP(w, req)
	})
	addr := env("COWSEC_SETUP_LISTEN", ":9443")
	srv := &http.Server{Addr: addr, Handler: r, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("setup wizard: https://<this-server>%s  token %s…  (run `sudo cowsec-setup` to see it in full)", addr, tok[:6])
	log.Printf("setup wizard certificate SHA-256: %s", fp)
	os.WriteFile(filepath.Join(stateDir, "setup-fingerprint"), []byte(fp+"\n"), 0o600)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Printf("setup wizard stopped: %v", err)
	}
}

// securityHeaders keeps the console out of frames and stops content sniffing.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		// Behind the edge, which always serves the console over HTTPS. Not includeSubDomains:
		// other sites on the same parent domain aren't ours to pin.
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && net.ParseIP(host).IsLoopback() && r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
