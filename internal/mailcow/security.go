package mailcow

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Mailbox security: sign-ins and failed attempts from mailcow's own logs, enriched with
// GeoIP and CrowdSec, the "lock down this mailbox" playbook with its undo, and the
// Lookout page (outbound volume, admins and 2FA, password policy, forwarding hosts).

// GeoInfo is what the security views need to know about an address.
type GeoInfo struct {
	CountryCode string `json:"cc"`
	Country     string `json:"country"`
	Org         string `json:"org"`
	LAN         bool   `json:"lan"`
}

// Ban describes a CrowdSec decision that currently covers an address.
type Ban struct {
	Banned   bool   `json:"banned"`
	Duration string `json:"duration,omitempty"`
	Origin   string `json:"origin,omitempty"`
}

var (
	reIP        = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)`)
	rePostfixIP = regexp.MustCompile(`\[([0-9a-fA-F.:]+)\]`)
	reSASLUser  = regexp.MustCompile(`sasl_username=([^\s,]+)`)
	reDoveUser  = regexp.MustCompile(`user=<([^>]*)>`)
	reDoveRIP   = regexp.MustCompile(`rip=([0-9a-fA-F.:]+)`)
	reSQLUser   = regexp.MustCompile(`\(([^,()]+),([0-9a-fA-F.:]+)(?:,[^)]*)?\): (?:Password mismatch|unknown user|password mismatch)`)
	lockMu      sync.Mutex
)

type signIn struct {
	Time       int64    `json:"time"`
	Service    string   `json:"service"`
	IP         string   `json:"ip"`
	AppPass    string   `json:"app_password,omitempty"`
	Geo        *GeoInfo `json:"geo,omitempty"`
	NewCountry bool     `json:"new_country"`
	Ban        *Ban     `json:"ban,omitempty"`
}

type failure struct {
	Time   int64    `json:"time"`
	Source string   `json:"source"` // smtp | imap
	IP     string   `json:"ip"`
	Tried  string   `json:"tried"`
	Geo    *GeoInfo `json:"geo,omitempty"`
	Ban    *Ban     `json:"ban,omitempty"`
}

// lockdown is what the playbook changed, so it can be put back.
type lockdown struct {
	User          string            `json:"user"`
	Since         time.Time         `json:"since"`
	By            string            `json:"by,omitempty"`
	PrevActive    string            `json:"prev_active,omitempty"`
	PrevForcePw   string            `json:"prev_force_pw,omitempty"`
	PrevRate      *json.RawMessage  `json:"prev_rate,omitempty"`
	Throttled     bool              `json:"throttled"`
	PausedApps    []string          `json:"paused_apps"`
	ClearedDevice bool              `json:"cleared_devices"`
	Banned        []string          `json:"banned"`
	Steps         []map[string]any  `json:"steps"`
	Extra         map[string]string `json:"extra,omitempty"`
}

func (o Options) lockFile() string {
	if o.StateDir == "" {
		return ""
	}
	return filepath.Join(o.StateDir, "mailbox-lockdowns.json")
}

func (o Options) loadLocks() map[string]*lockdown {
	out := map[string]*lockdown{}
	if f := o.lockFile(); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			json.Unmarshal(b, &out)
		}
	}
	return out
}

func (o Options) saveLocks(m map[string]*lockdown) error {
	f := o.lockFile()
	if f == "" {
		return fmt.Errorf("no state directory")
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := f + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f)
}

func ipOf(s string) string {
	if m := reIP.FindString(s); m != "" && net.ParseIP(m) != nil {
		return m
	}
	return ""
}

func publicIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && !p.IsPrivate() && !p.IsLoopback() && !p.IsLinkLocalUnicast() && !p.IsUnspecified()
}

// enrich adds GeoIP and ban status to a set of addresses, in parallel and with a cap.
func (o Options) enrich(ips []string) (map[string]*GeoInfo, map[string]*Ban) {
	geo, bans := map[string]*GeoInfo{}, map[string]*Ban{}
	uniq := map[string]bool{}
	for _, ip := range ips {
		if ip != "" {
			uniq[ip] = true
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	n := 0
	for ip := range uniq {
		if o.Geo != nil {
			geo[ip] = o.Geo(ip)
		}
		if o.BanStatus == nil || !publicIP(ip) || n >= 40 {
			continue
		}
		n++
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			b := o.BanStatus(ip)
			<-sem
			mu.Lock()
			bans[ip] = b
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return geo, bans
}

func mountSecurity(r chi.Router, c *Client, o Options) {
	change := func(w http.ResponseWriter, path string, body interface{}) {
		msgs, err := c.Change(path, body)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, 200, map[string]interface{}{"status": "ok", "messages": msgs})
	}

	r.Get("/mailboxes/{username}/security", func(w http.ResponseWriter, req *http.Request) {
		u := strings.ToLower(param(req, "username"))
		if !reEmail.MatchString(u) {
			fail(w, 400, fmt.Errorf("invalid mailbox"))
			return
		}
		days := 30
		var (
			logins   []signIn
			failures []failure
			mbox     map[string]interface{}
			wg       sync.WaitGroup
			mu       sync.Mutex
		)
		wg.Add(4)
		go func() {
			defer wg.Done()
			data, err := c.Get(fmt.Sprintf("get/last-login/%s/%d", u, days))
			if err != nil {
				return
			}
			var ll struct {
				SASL []struct {
					Service string      `json:"service"`
					RealRIP string      `json:"real_rip"`
					Date    string      `json:"datetime"`
					AppName *string     `json:"app_password_name"`
					App     interface{} `json:"app_password"`
				} `json:"sasl"`
			}
			if json.Unmarshal(data, &ll) != nil {
				return
			}
			for _, s := range ll.SASL {
				t, _ := time.ParseInLocation("2006-01-02 15:04:05", s.Date, time.UTC)
				in := signIn{Time: t.Unix(), Service: s.Service, IP: ipOf(s.RealRIP)}
				if s.AppName != nil {
					in.AppPass = *s.AppName
				}
				mu.Lock()
				logins = append(logins, in)
				mu.Unlock()
			}
		}()
		matches := mailboxMatcher(u)
		go func() { // failed SMTP AUTH (Postfix)
			defer wg.Done()
			if lines, err := c.logLines("postfix"); err == nil {
				f := postfixFailures(lines, matches)
				mu.Lock()
				failures = append(failures, f...)
				mu.Unlock()
			}
		}()
		go func() { // failed IMAP/POP3 logins (Dovecot)
			defer wg.Done()
			if lines, err := c.logLines("dovecot"); err == nil {
				f := dovecotFailures(lines, matches)
				mu.Lock()
				failures = append(failures, f...)
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			if data, err := c.Get("get/mailbox/" + u); err == nil {
				json.Unmarshal(data, &mbox)
			}
		}()
		wg.Wait()

		ips := []string{}
		for _, l := range logins {
			ips = append(ips, l.IP)
		}
		for _, f := range failures {
			ips = append(ips, f.IP)
		}
		geo, bans := o.enrich(ips)

		// a sign-in from a country this mailbox rarely uses is worth a second look
		countries := map[string]int{}
		for i := range logins {
			logins[i].Geo, logins[i].Ban = geo[logins[i].IP], bans[logins[i].IP]
			if g := logins[i].Geo; g != nil && !g.LAN && g.CountryCode != "" {
				countries[g.CountryCode]++
			}
		}
		home, top := "", 0
		for cc, n := range countries {
			if n > top {
				home, top = cc, n
			}
		}
		for i := range logins {
			if g := logins[i].Geo; g != nil && !g.LAN && g.CountryCode != "" && g.CountryCode != home && countries[g.CountryCode] <= 2 && len(logins) >= 3 {
				logins[i].NewCountry = true
			}
		}
		for i := range failures {
			failures[i].Geo, failures[i].Ban = geo[failures[i].IP], bans[failures[i].IP]
		}
		sort.Slice(logins, func(i, j int) bool { return logins[i].Time > logins[j].Time })
		sort.Slice(failures, func(i, j int) bool { return failures[i].Time > failures[j].Time })
		if len(failures) > 300 {
			failures = failures[:300]
		}

		lockMu.Lock()
		ld := o.loadLocks()[u]
		lockMu.Unlock()
		writeJSON(w, 200, map[string]interface{}{"user": u, "days": days, "logins": nz(logins), "failures": nzf(failures),
			"countries": countries, "home": home, "mailbox": mbox, "lockdown": ld, "can_ban": o.Ban != nil})
	})

	// ---- the lock-down playbook
	r.Post("/mailboxes/{username}/lockdown", func(w http.ResponseWriter, req *http.Request) {
		u := strings.ToLower(param(req, "username"))
		var in struct {
			DisableLogin  bool     `json:"disable_login"`
			ForcePassword bool     `json:"force_password"`
			PauseApps     bool     `json:"pause_app_passwords"`
			ClearDevices  bool     `json:"clear_devices"`
			Throttle      bool     `json:"throttle"`
			BanIPs        []string `json:"ban_ips"`
			BanDuration   string   `json:"ban_duration"`
		}
		if !reEmail.MatchString(u) || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		if in.BanDuration == "" {
			in.BanDuration = "7d"
		}
		if !regexp.MustCompile(`^[0-9]{1,4}[hd]$`).MatchString(in.BanDuration) {
			fail(w, 400, fmt.Errorf("ban length must look like 24h or 7d"))
			return
		}
		for _, ip := range in.BanIPs {
			if !publicIP(ip) {
				fail(w, 400, fmt.Errorf("%q is not a public IP address", ip))
				return
			}
		}
		var mb struct {
			Active     json.Number       `json:"active"`
			Attributes map[string]string `json:"attributes"`
			RL         json.RawMessage   `json:"rl"`
		}
		data, err := c.Get("get/mailbox/" + u)
		if err != nil || json.Unmarshal(data, &mb) != nil || mb.Attributes == nil {
			fail(w, 404, fmt.Errorf("mailbox not found"))
			return
		}
		lockMu.Lock()
		defer lockMu.Unlock()
		locks := o.loadLocks()
		ld := locks[u]
		if ld == nil {
			ld = &lockdown{User: u, Since: time.Now().UTC(), PrevActive: mb.Active.String(), PrevForcePw: mb.Attributes["force_pw_update"], PausedApps: []string{}, Banned: []string{}}
			if len(mb.RL) > 0 && string(mb.RL) != "false" {
				raw := json.RawMessage(mb.RL)
				ld.PrevRate = &raw
			}
		}
		ld.Steps = nil
		step := func(name string, err error, msg string) {
			s := map[string]any{"step": name, "ok": err == nil, "message": msg}
			if err != nil {
				s["message"] = err.Error()
			}
			ld.Steps = append(ld.Steps, s)
		}
		edit := func(attr map[string]interface{}) error {
			_, err := c.Change("edit/mailbox", map[string]interface{}{"items": []string{u}, "attr": attr})
			return err
		}
		if in.DisableLogin {
			// mailcow's "2": mail keeps arriving, but nobody can sign in
			step("disable_login", edit(map[string]interface{}{"active": "2"}), "Sign-in disabled. Mail still arrives.")
		}
		if in.ForcePassword {
			step("force_password", edit(map[string]interface{}{"force_pw_update": "1"}), "A new password is required at the next sign-in.")
		}
		if in.PauseApps {
			apps, _ := c.List("get/app-passwd/all/" + u)
			var rows []struct {
				ID     json.Number `json:"id"`
				Active json.Number `json:"active"`
			}
			json.Unmarshal(apps, &rows)
			n := 0
			var firstErr error
			for _, a := range rows {
				if a.Active.String() != "1" {
					continue
				}
				_, err := c.Change("edit/app-passwd", map[string]interface{}{"items": []string{a.ID.String()}, "attr": map[string]interface{}{"active": "0", "username": u}})
				if err != nil && firstErr == nil {
					firstErr = err
				}
				if err == nil {
					ld.PausedApps = appendUniq(ld.PausedApps, a.ID.String())
					n++
				}
			}
			step("pause_app_passwords", firstErr, fmt.Sprintf("%d app password%s paused.", n, plural(n)))
		}
		if in.ClearDevices {
			_, err := c.Change("delete/eas_cache", []string{u})
			if err == nil {
				ld.ClearedDevice = true
			}
			step("clear_devices", err, "Phones and tablets using ActiveSync must set up the account again.")
		}
		if in.Throttle {
			_, err := c.Change("edit/rl-mbox", map[string]interface{}{"items": []string{u}, "attr": map[string]interface{}{"rl_value": "1", "rl_frame": "h"}})
			if err == nil {
				ld.Throttled = true
			}
			step("throttle", err, "Sending limited to 1 message an hour.")
		}
		if len(in.BanIPs) > 0 {
			if o.Ban == nil {
				step("ban", fmt.Errorf("CrowdSec isn't available to ban addresses"), "")
			} else {
				n := 0
				var firstErr error
				for _, ip := range in.BanIPs {
					if err := o.Ban(ip, in.BanDuration, "cowsec lockdown "+u); err != nil {
						if firstErr == nil {
							firstErr = err
						}
						continue
					}
					ld.Banned = appendUniq(ld.Banned, ip)
					n++
				}
				step("ban", firstErr, fmt.Sprintf("%d address%s banned for %s.", n, map[bool]string{true: "", false: "es"}[n == 1], in.BanDuration))
			}
		}
		locks[u] = ld
		if err := o.saveLocks(locks); err != nil {
			step("record", err, "")
		}
		writeJSON(w, 200, ld)
	})

	r.Post("/mailboxes/{username}/lockdown/undo", func(w http.ResponseWriter, req *http.Request) {
		u := strings.ToLower(param(req, "username"))
		var in struct {
			RestoreLogin bool `json:"restore_login"`
			ResumeApps   bool `json:"resume_app_passwords"`
			RemoveLimit  bool `json:"remove_throttle"`
			Unban        bool `json:"unban"`
		}
		if !reEmail.MatchString(u) || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		lockMu.Lock()
		defer lockMu.Unlock()
		locks := o.loadLocks()
		ld := locks[u]
		if ld == nil {
			fail(w, 404, fmt.Errorf("%s isn't locked down", u))
			return
		}
		steps := []map[string]any{}
		step := func(name string, err error, msg string) {
			s := map[string]any{"step": name, "ok": err == nil, "message": msg}
			if err != nil {
				s["message"] = err.Error()
			}
			steps = append(steps, s)
		}
		if in.RestoreLogin {
			prev := ld.PrevActive
			if prev == "" || prev == "2" {
				prev = "1"
			}
			attr := map[string]interface{}{"active": prev}
			if ld.PrevForcePw != "" {
				attr["force_pw_update"] = ld.PrevForcePw
			}
			_, err := c.Change("edit/mailbox", map[string]interface{}{"items": []string{u}, "attr": attr})
			step("restore_login", err, "Sign-in allowed again.")
		}
		if in.ResumeApps && len(ld.PausedApps) > 0 {
			var firstErr error
			for _, id := range ld.PausedApps {
				if _, err := c.Change("edit/app-passwd", map[string]interface{}{"items": []string{id}, "attr": map[string]interface{}{"active": "1", "username": u}}); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			step("resume_app_passwords", firstErr, fmt.Sprintf("%d app password%s resumed.", len(ld.PausedApps), plural(len(ld.PausedApps))))
			if firstErr == nil {
				ld.PausedApps = []string{}
			}
		}
		if in.RemoveLimit && ld.Throttled {
			val, frame := "0", "h"
			if ld.PrevRate != nil {
				var prev struct {
					Value json.Number `json:"value"`
					Frame string      `json:"frame"`
				}
				if json.Unmarshal(*ld.PrevRate, &prev) == nil && prev.Value != "" {
					val, frame = prev.Value.String(), prev.Frame
				}
			}
			_, err := c.Change("edit/rl-mbox", map[string]interface{}{"items": []string{u}, "attr": map[string]interface{}{"rl_value": val, "rl_frame": frame}})
			step("remove_throttle", err, "Sending limit put back as it was.")
			if err == nil {
				ld.Throttled = false
			}
		}
		if in.Unban && len(ld.Banned) > 0 && o.Unban != nil {
			var firstErr error
			for _, ip := range ld.Banned {
				if err := o.Unban(ip); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			step("unban", firstErr, fmt.Sprintf("%d address%s unbanned.", len(ld.Banned), map[bool]string{true: "", false: "es"}[len(ld.Banned) == 1]))
			if firstErr == nil {
				ld.Banned = []string{}
			}
		}
		if in.RestoreLogin && len(ld.PausedApps) == 0 && !ld.Throttled && len(ld.Banned) == 0 {
			delete(locks, u)
		} else {
			locks[u] = ld
		}
		o.saveLocks(locks)
		writeJSON(w, 200, map[string]interface{}{"steps": steps, "remaining": locks[u]})
	})

	// ---- ban or unban one address seen in a mailbox's security view
	r.Post("/security/ban", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			IP       string `json:"ip"`
			Duration string `json:"duration"`
			Reason   string `json:"reason"`
		}
		if decode(req, &in) != nil || !publicIP(in.IP) {
			fail(w, 400, fmt.Errorf("choose a public IP address"))
			return
		}
		if o.Ban == nil {
			fail(w, 503, fmt.Errorf("CrowdSec isn't available"))
			return
		}
		if in.Duration == "" {
			in.Duration = "7d"
		}
		if err := o.Ban(in.IP, in.Duration, trim("cowsec mailbox security "+in.Reason, 180)); err != nil {
			fail(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]interface{}{"status": "ok", "messages": []string{in.IP + " banned for " + in.Duration}})
	})

	// ---- Lookout: outbound volume per sender, rate-limit hits, the queue by sender, lockdowns
	r.Get("/lookout", func(w http.ResponseWriter, _ *http.Request) {
		var (
			wg                   sync.WaitGroup
			postfix, rl, queue   json.RawMessage
			admins, dadmins, pol json.RawMessage
			fwd                  json.RawMessage
		)
		for _, j := range []struct {
			dst  *json.RawMessage
			path string
			list bool
		}{{&postfix, "get/logs/postfix/5000", true}, {&rl, "get/logs/ratelimited/500", true}, {&queue, "get/mailq/all", true},
			{&admins, "get/admin/all", true}, {&dadmins, "get/domain-admin/all", true}, {&pol, "get/passwordpolicy", false}, {&fwd, "get/fwdhost/all", true}} {
			wg.Add(1)
			go func(dst *json.RawMessage, path string, list bool) {
				defer wg.Done()
				var data json.RawMessage
				var err error
				if list {
					data, err = c.List(path)
				} else {
					data, err = c.Get(path)
				}
				if err != nil {
					data, _ = json.Marshal(map[string]string{"error": err.Error()})
				}
				*dst = data
			}(j.dst, j.path, j.list)
		}
		wg.Wait()

		// authenticated submissions per sender, from Postfix's log window
		var lines []logLine
		json.Unmarshal(postfix, &lines)
		senders, lo, hi := outboundSenders(lines)
		if len(senders) > 25 {
			senders = senders[:25]
		}

		var q []struct {
			Sender string `json:"sender"`
			Queue  string `json:"queue_name"`
		}
		json.Unmarshal(queue, &q)
		qby := map[string]int{}
		for _, m := range q {
			qby[strings.ToLower(m.Sender)]++
		}
		type qs struct {
			Sender string `json:"sender"`
			Count  int    `json:"count"`
		}
		queued := []qs{}
		for s, n := range qby {
			queued = append(queued, qs{s, n})
		}
		sort.Slice(queued, func(i, j int) bool { return queued[i].Count > queued[j].Count })

		lockMu.Lock()
		locks := o.loadLocks()
		lockMu.Unlock()
		ll := []*lockdown{}
		for _, l := range locks {
			ll = append(ll, l)
		}
		sort.Slice(ll, func(i, j int) bool { return ll[i].Since.After(ll[j].Since) })

		writeJSON(w, 200, map[string]interface{}{"window": map[string]int64{"from": lo, "to": hi}, "senders": senders, "queued": queued, "queue_total": len(q),
			"ratelimited": rl, "admins": admins, "domain_admins": dadmins, "password_policy": pol, "fwdhosts": fwd, "lockdowns": ll})
	})

	r.Put("/password-policy", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Length       int  `json:"length"`
			Chars        bool `json:"chars"`
			SpecialChars bool `json:"special_chars"`
			LowerUpper   bool `json:"lowerupper"`
			Numbers      bool `json:"numbers"`
		}
		if decode(req, &in) != nil || in.Length < 6 || in.Length > 64 {
			fail(w, 400, fmt.Errorf("a minimum length is between 6 and 64 characters"))
			return
		}
		change(w, "edit/passwordpolicy", map[string]interface{}{"length": strconv.Itoa(in.Length), "chars": flag(in.Chars),
			"special_chars": flag(in.SpecialChars), "lowerupper": flag(in.LowerUpper), "numbers": flag(in.Numbers)})
	})

	// ---- forwarding hosts: servers allowed to relay mail in (skipping greylisting and some checks)
	r.Post("/fwdhosts", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Host       string `json:"hostname"`
			FilterSpam bool   `json:"filter_spam"`
		}
		if decode(req, &in) != nil || !(reDomain.MatchString(in.Host) || net.ParseIP(in.Host) != nil || isCIDR(in.Host)) {
			fail(w, 400, fmt.Errorf("enter a host name, IP address or network"))
			return
		}
		change(w, "add/fwdhost", map[string]interface{}{"hostname": in.Host, "filter_spam": flag(in.FilterSpam)})
	})
	r.Delete("/fwdhosts/{host}", func(w http.ResponseWriter, req *http.Request) {
		h := param(req, "host")
		if !(net.ParseIP(h) != nil || isCIDR(h)) {
			fail(w, 400, fmt.Errorf("invalid forwarding host"))
			return
		}
		change(w, "delete/fwdhost", []string{h})
	})
}

type logLine struct {
	Time    json.Number `json:"time"`
	Message string      `json:"message"`
}

func (c *Client) logLines(kind string) ([]logLine, error) {
	data, err := c.List("get/logs/" + kind + "/5000")
	if err != nil {
		return nil, err
	}
	var lines []logLine
	err = json.Unmarshal(data, &lines)
	return lines, err
}

// mailboxMatcher matches the names a client might sign in with: the full address or its local part.
func mailboxMatcher(u string) func(string) bool {
	u = strings.ToLower(u)
	local := strings.SplitN(u, "@", 2)[0]
	return func(name string) bool {
		name = strings.ToLower(strings.Trim(name, "<>\" "))
		return name == u || name == local
	}
}

// postfixFailures finds failed SMTP AUTH attempts for one mailbox in Postfix's log.
func postfixFailures(lines []logLine, matches func(string) bool) []failure {
	out := []failure{}
	for _, l := range lines {
		if !strings.Contains(l.Message, "authentication failed") {
			continue
		}
		m := reSASLUser.FindStringSubmatch(l.Message)
		if m == nil || !matches(m[1]) {
			continue
		}
		ip := ""
		if p := rePostfixIP.FindStringSubmatch(l.Message); p != nil {
			ip = p[1]
		}
		t, _ := l.Time.Int64()
		out = append(out, failure{Time: t, Source: "smtp", IP: ip, Tried: m[1]})
	}
	return out
}

// dovecotFailures finds failed IMAP/POP3 logins for one mailbox in Dovecot's log.
func dovecotFailures(lines []logLine, matches func(string) bool) []failure {
	out := []failure{}
	for _, l := range lines {
		var name, ip string
		if strings.Contains(l.Message, "auth failed") {
			if m := reDoveUser.FindStringSubmatch(l.Message); m != nil {
				name = m[1]
			}
			if m := reDoveRIP.FindStringSubmatch(l.Message); m != nil {
				ip = m[1]
			}
		} else if m := reSQLUser.FindStringSubmatch(l.Message); m != nil && strings.Contains(strings.ToLower(l.Message), "mismatch") {
			name, ip = m[1], m[2]
		}
		if name == "" || !matches(name) {
			continue
		}
		t, _ := l.Time.Int64()
		out = append(out, failure{Time: t, Source: "imap", IP: ip, Tried: name})
	}
	return out
}

// outSender is one account's authenticated submissions in the log window.
type outSender struct {
	User    string  `json:"user"`
	Count   int     `json:"count"`
	IPs     int     `json:"ips"`
	First   int64   `json:"first"`
	Last    int64   `json:"last"`
	PerHr   float64 `json:"per_hour"`
	Unusual bool    `json:"unusual"`
	ipset   map[string]bool
}

// outboundSenders counts authenticated submissions per account in Postfix's log, busiest
// first. Many messages, or one account sending from many addresses, is how a stolen
// password usually shows up.
func outboundSenders(lines []logLine) ([]*outSender, int64, int64) {
	by := map[string]*outSender{}
	var lo, hi int64
	for _, l := range lines {
		t, _ := l.Time.Int64()
		if t > 0 && (lo == 0 || t < lo) {
			lo = t
		}
		if t > hi {
			hi = t
		}
		if strings.Contains(l.Message, "authentication failed") || !strings.Contains(l.Message, "sasl_username=") || !strings.Contains(l.Message, "client=") {
			continue
		}
		m := reSASLUser.FindStringSubmatch(l.Message)
		if m == nil {
			continue
		}
		u := strings.ToLower(m[1])
		s := by[u]
		if s == nil {
			s = &outSender{User: u, First: t, ipset: map[string]bool{}}
			by[u] = s
		}
		s.Count++
		s.Last = t
		if p := rePostfixIP.FindStringSubmatch(l.Message); p != nil {
			s.ipset[p[1]] = true
		}
	}
	window := float64(hi-lo) / 3600
	if window < 1 {
		window = 1
	}
	out := []*outSender{}
	for _, s := range by {
		s.IPs = len(s.ipset)
		s.PerHr = float64(s.Count) / window
		s.Unusual = s.Count >= 200 || s.IPs >= 5
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].User < out[j].User
	})
	return out, lo, hi
}

func isCIDR(s string) bool { _, _, err := net.ParseCIDR(s); return err == nil }

func appendUniq(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func nz(s []signIn) []signIn {
	if s == nil {
		return []signIn{}
	}
	return s
}

func nzf(s []failure) []failure {
	if s == nil {
		return []failure{}
	}
	return s
}
