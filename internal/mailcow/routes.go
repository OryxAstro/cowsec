package mailcow

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

var (
	reDomain    = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	reLocalPart = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	reEmail     = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}@(?i)[a-z0-9.-]+\.[a-z]{2,}$`)
	reQueueID   = regexp.MustCompile(`^[A-Za-z0-9]{6,32}$`)
	logTypes    = map[string]bool{"postfix": true, "dovecot": true, "rspamd-history": true, "sogo": true, "netfilter": true,
		"autodiscover": true, "acme": true, "watchdog": true, "ratelimited": true, "api": true}
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeRaw(w http.ResponseWriter, data json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

func fail(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func decode(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// flag turns an optional bool into mailcow's "1"/"0".
func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// num validates an optional non-negative integer (MiB quotas, counts).
func num(name string, v *int, max int, attr map[string]interface{}, key string) error {
	if v == nil {
		return nil
	}
	if *v < 0 || *v > max {
		return fmt.Errorf("%s must be between 0 and %d", name, max)
	}
	attr[key] = strconv.Itoa(*v)
	return nil
}

// Routes mounts /api/mailcow. c may be nil (API not configured yet).
func Routes(r chi.Router, c *Client) {
	r.Get("/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"configured": c != nil})
	})
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if c == nil {
					writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"configured": false,
						"error": "mailcow management is not set up. On the server run: sudo cowsec-setup mailcow-api"})
					return
				}
				next.ServeHTTP(w, req)
			})
		})
		mount(r, c)
	})
}

func mount(r chi.Router, c *Client) {
	get := func(path string, list bool) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			var data json.RawMessage
			var err error
			if list {
				data, err = c.List(path)
			} else {
				data, err = c.Get(path)
			}
			if err != nil {
				fail(w, http.StatusBadGateway, err)
				return
			}
			writeRaw(w, data)
		}
	}
	change := func(w http.ResponseWriter, path string, body interface{}) {
		msgs, err := c.Change(path, body)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, 200, map[string]interface{}{"status": "ok", "messages": msgs})
	}

	// ---- overview
	r.Get("/status", func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]json.RawMessage{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for key, path := range map[string]string{"containers": "get/status/containers", "version": "get/status/version",
			"vmail": "get/status/vmail", "domains": "get/domain/all", "mailboxes": "get/mailbox/all", "queue": "get/mailq/all",
			"quarantine": "get/quarantine/all"} {
			wg.Add(1)
			go func(key, path string) {
				defer wg.Done()
				data, err := c.Get(path)
				if err != nil {
					b, _ := json.Marshal(map[string]string{"error": err.Error()})
					data = b
				}
				mu.Lock()
				out[key] = data
				mu.Unlock()
			}(key, path)
		}
		wg.Wait()
		writeJSON(w, 200, out)
	})

	// ---- domains
	r.Get("/domains", get("get/domain/all", true))
	r.Post("/domains", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Domain      string `json:"domain"`
			Description string `json:"description"`
			Mailboxes   *int   `json:"mailboxes"`
			Aliases     *int   `json:"aliases"`
			DefQuota    *int   `json:"defquota"`
			MaxQuota    *int   `json:"maxquota"`
			Quota       *int   `json:"quota"`
			Active      bool   `json:"active"`
		}
		if err := decode(req, &in); err != nil || !reDomain.MatchString(in.Domain) {
			fail(w, 400, fmt.Errorf("enter a valid domain name"))
			return
		}
		body := map[string]interface{}{"domain": strings.ToLower(in.Domain), "description": trim(in.Description, 255), "active": flag(in.Active),
			"restart_sogo": "1", "rl_value": "", "rl_frame": "s"}
		for _, f := range []struct {
			n   string
			v   *int
			max int
			k   string
		}{{"mailboxes", in.Mailboxes, 100000, "mailboxes"}, {"aliases", in.Aliases, 100000, "aliases"},
			{"default mailbox quota", in.DefQuota, 10485760, "defquota"}, {"maximum mailbox quota", in.MaxQuota, 10485760, "maxquota"},
			{"domain quota", in.Quota, 104857600, "quota"}} {
			if err := num(f.n, f.v, f.max, body, f.k); err != nil {
				fail(w, 400, err)
				return
			}
		}
		change(w, "add/domain", body)
	})
	r.Patch("/domains/{domain}", func(w http.ResponseWriter, req *http.Request) {
		d := param(req, "domain")
		var in struct {
			Description *string `json:"description"`
			Active      *bool   `json:"active"`
			Mailboxes   *int    `json:"mailboxes"`
			Aliases     *int    `json:"aliases"`
			DefQuota    *int    `json:"defquota"`
			MaxQuota    *int    `json:"maxquota"`
			Quota       *int    `json:"quota"`
		}
		if err := decode(req, &in); err != nil || !reDomain.MatchString(d) {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		attr := map[string]interface{}{}
		if in.Description != nil {
			attr["description"] = trim(*in.Description, 255)
		}
		if in.Active != nil {
			attr["active"] = flag(*in.Active)
		}
		for _, f := range []struct {
			n   string
			v   *int
			max int
			k   string
		}{{"mailboxes", in.Mailboxes, 100000, "mailboxes"}, {"aliases", in.Aliases, 100000, "aliases"},
			{"default mailbox quota", in.DefQuota, 10485760, "defquota"}, {"maximum mailbox quota", in.MaxQuota, 10485760, "maxquota"},
			{"domain quota", in.Quota, 104857600, "quota"}} {
			if err := num(f.n, f.v, f.max, attr, f.k); err != nil {
				fail(w, 400, err)
				return
			}
		}
		change(w, "edit/domain", map[string]interface{}{"items": []string{d}, "attr": attr})
	})
	r.Delete("/domains/{domain}", func(w http.ResponseWriter, req *http.Request) {
		d := param(req, "domain")
		if !reDomain.MatchString(d) {
			fail(w, 400, fmt.Errorf("invalid domain"))
			return
		}
		change(w, "delete/domain", []string{d})
	})

	// ---- mailboxes
	r.Get("/mailboxes", func(w http.ResponseWriter, req *http.Request) {
		d := req.URL.Query().Get("domain")
		if d != "" && !reDomain.MatchString(d) {
			fail(w, 400, fmt.Errorf("invalid domain"))
			return
		}
		path := "get/mailbox/all"
		if d != "" {
			path += "/" + d
		}
		get(path, true)(w, req)
	})
	r.Post("/mailboxes", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			LocalPart string `json:"local_part"`
			Domain    string `json:"domain"`
			Name      string `json:"name"`
			Quota     *int   `json:"quota"`
			Password  string `json:"password"`
			Active    bool   `json:"active"`
		}
		if err := decode(req, &in); err != nil || !reLocalPart.MatchString(in.LocalPart) || !reDomain.MatchString(in.Domain) {
			fail(w, 400, fmt.Errorf("enter a valid address"))
			return
		}
		if len(in.Password) < 10 || len(in.Password) > 256 {
			fail(w, 400, fmt.Errorf("password must be 10-256 characters"))
			return
		}
		body := map[string]interface{}{"local_part": in.LocalPart, "domain": strings.ToLower(in.Domain), "name": trim(in.Name, 255),
			"password": in.Password, "password2": in.Password, "active": flag(in.Active), "force_pw_update": "0", "tls_enforce_in": "1", "tls_enforce_out": "1"}
		if err := num("quota", in.Quota, 10485760, body, "quota"); err != nil {
			fail(w, 400, err)
			return
		}
		change(w, "add/mailbox", body)
	})
	r.Patch("/mailboxes/{username}", func(w http.ResponseWriter, req *http.Request) {
		u := param(req, "username")
		var in struct {
			Name     *string `json:"name"`
			Active   *bool   `json:"active"`
			Quota    *int    `json:"quota"`
			Password *string `json:"password"`
		}
		if err := decode(req, &in); err != nil || !reEmail.MatchString(u) {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		attr := map[string]interface{}{}
		if in.Name != nil {
			attr["name"] = trim(*in.Name, 255)
		}
		if in.Active != nil {
			attr["active"] = flag(*in.Active)
		}
		if in.Password != nil {
			if len(*in.Password) < 10 || len(*in.Password) > 256 {
				fail(w, 400, fmt.Errorf("password must be 10-256 characters"))
				return
			}
			attr["password"], attr["password2"] = *in.Password, *in.Password
		}
		if err := num("quota", in.Quota, 10485760, attr, "quota"); err != nil {
			fail(w, 400, err)
			return
		}
		change(w, "edit/mailbox", map[string]interface{}{"items": []string{u}, "attr": attr})
	})
	r.Delete("/mailboxes/{username}", func(w http.ResponseWriter, req *http.Request) {
		u := param(req, "username")
		if !reEmail.MatchString(u) {
			fail(w, 400, fmt.Errorf("invalid mailbox"))
			return
		}
		change(w, "delete/mailbox", []string{u})
	})

	// ---- aliases
	r.Get("/aliases", get("get/alias/all", true))
	r.Post("/aliases", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Address string `json:"address"`
			Goto    string `json:"goto"`
			Active  bool   `json:"active"`
		}
		if err := decode(req, &in); err != nil || !(reEmail.MatchString(in.Address) || strings.HasPrefix(in.Address, "@") && reDomain.MatchString(in.Address[1:])) {
			fail(w, 400, fmt.Errorf("enter an alias address (or @domain for a catch-all)"))
			return
		}
		targets, err := gotoList(in.Goto)
		if err != nil {
			fail(w, 400, err)
			return
		}
		change(w, "add/alias", map[string]interface{}{"address": strings.ToLower(in.Address), "goto": targets, "active": flag(in.Active)})
	})
	r.Patch("/aliases/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := param(req, "id")
		var in struct {
			Goto   *string `json:"goto"`
			Active *bool   `json:"active"`
		}
		if _, err := strconv.Atoi(id); err != nil || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		attr := map[string]interface{}{}
		if in.Active != nil {
			attr["active"] = flag(*in.Active)
		}
		if in.Goto != nil {
			t, err := gotoList(*in.Goto)
			if err != nil {
				fail(w, 400, err)
				return
			}
			attr["goto"] = t
		}
		change(w, "edit/alias", map[string]interface{}{"items": []string{id}, "attr": attr})
	})
	r.Delete("/aliases/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := param(req, "id")
		if _, err := strconv.Atoi(id); err != nil {
			fail(w, 400, fmt.Errorf("invalid alias"))
			return
		}
		change(w, "delete/alias", []string{id})
	})

	// ---- DKIM
	r.Get("/dkim/{domain}", func(w http.ResponseWriter, req *http.Request) {
		d := param(req, "domain")
		if !reDomain.MatchString(d) {
			fail(w, 400, fmt.Errorf("invalid domain"))
			return
		}
		get("get/dkim/"+d, false)(w, req)
	})
	r.Post("/dkim", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Domain  string `json:"domain"`
			KeySize int    `json:"key_size"`
		}
		if err := decode(req, &in); err != nil || !reDomain.MatchString(in.Domain) || (in.KeySize != 2048 && in.KeySize != 3072 && in.KeySize != 4096) {
			fail(w, 400, fmt.Errorf("choose a domain and a key size of 2048, 3072 or 4096"))
			return
		}
		change(w, "add/dkim", map[string]interface{}{"domains": in.Domain, "dkim_selector": "dkim", "key_size": strconv.Itoa(in.KeySize)})
	})

	// ---- quarantine
	r.Get("/quarantine", get("get/quarantine/all", true))
	r.Post("/quarantine/{id}/{action}", func(w http.ResponseWriter, req *http.Request) {
		id, action := param(req, "id"), param(req, "action")
		if _, err := strconv.Atoi(id); err != nil || (action != "release" && action != "learnham") {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		change(w, "edit/qitem", map[string]interface{}{"items": []string{id}, "attr": map[string]string{"action": action}})
	})
	r.Delete("/quarantine/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := param(req, "id")
		if _, err := strconv.Atoi(id); err != nil {
			fail(w, 400, fmt.Errorf("invalid item"))
			return
		}
		change(w, "delete/qitem", []string{id})
	})

	// ---- mail queue
	r.Get("/queue", get("get/mailq/all", true))
	r.Post("/queue/flush", func(w http.ResponseWriter, _ *http.Request) {
		change(w, "edit/mailq", map[string]string{"action": "flush"})
	})
	r.Post("/queue/{qid}/{action}", func(w http.ResponseWriter, req *http.Request) {
		qid, action := param(req, "qid"), param(req, "action")
		if !reQueueID.MatchString(qid) || (action != "deliver" && action != "hold" && action != "unhold") {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		change(w, "edit/mailq", map[string]interface{}{"items": []string{qid}, "action": action})
	})
	r.Delete("/queue/{qid}", func(w http.ResponseWriter, req *http.Request) {
		qid := param(req, "qid")
		if !reQueueID.MatchString(qid) {
			fail(w, 400, fmt.Errorf("invalid queue id"))
			return
		}
		change(w, "delete/mailq", map[string]interface{}{"items": []string{qid}})
	})

	// ---- logs
	r.Get("/logs/{type}", func(w http.ResponseWriter, req *http.Request) {
		t := param(req, "type")
		n, _ := strconv.Atoi(req.URL.Query().Get("count"))
		if !logTypes[t] {
			fail(w, 400, fmt.Errorf("unknown log"))
			return
		}
		if n <= 0 || n > 1000 {
			n = 200
		}
		get(fmt.Sprintf("get/logs/%s/%d", t, n), true)(w, req)
	})
}

// param returns a decoded URL path parameter (mailbox addresses arrive as alice%40example.org).
func param(r *http.Request, name string) string {
	v := chi.URLParam(r, name)
	if d, err := url.PathUnescape(v); err == nil {
		return d
	}
	return v
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// gotoList validates comma/space separated alias targets.
func gotoList(s string) (string, error) {
	var out []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		t = strings.ToLower(strings.TrimSpace(t))
		if !reEmail.MatchString(t) {
			return "", fmt.Errorf("%q is not an e-mail address", t)
		}
		out = append(out, t)
	}
	if len(out) == 0 || len(out) > 100 {
		return "", fmt.Errorf("enter 1-100 destination addresses")
	}
	return strings.Join(out, ","), nil
}
