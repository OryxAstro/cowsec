package mailcow

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Deliverability: MTA-STS per domain, a scorecard for every domain (DNS, DKIM, SPF, DMARC,
// MTA-STS, TLS reporting, reverse DNS, blocklists) and one-click sign-in as a domain admin.

// MTASTS is a domain's policy as mailcow stores it.
type MTASTS struct {
	Active  bool     `json:"active"`
	Mode    string   `json:"mode"`
	MaxAge  int      `json:"max_age"`
	MX      []string `json:"mx"`
	ID      string   `json:"id"`
	Version string   `json:"version"`
	Exists  bool     `json:"exists"`
}

func (c *Client) mtaSTS(domain string) MTASTS {
	out := MTASTS{}
	if c.gate == nil {
		return out
	}
	raw, err := c.gate("mailcow-mta-sts", domain)
	if err != nil {
		return out
	}
	json.Unmarshal(raw, &out)
	return out
}

// Blocklists checked for the server's IPv4 addresses. Spamhaus answers 127.255.255.x when it
// refuses a query (for example through a large public resolver); that's reported as unknown.
var blocklists = []struct{ zone, name, url string }{
	{"zen.spamhaus.org", "Spamhaus ZEN", "https://check.spamhaus.org/"},
	{"b.barracudacentral.org", "Barracuda", "https://www.barracudacentral.org/lookups"},
	{"bl.spamcop.net", "SpamCop", "https://www.spamcop.net/bl.shtml"},
	{"psbl.surriel.com", "PSBL", "https://psbl.org/"},
	{"dnsbl-1.uceprotect.net", "UCEPROTECT 1", "https://www.uceprotect.net/en/rblcheck.php"},
	{"ix.dnsbl.manitu.net", "NiX Spam", "https://www.dnsbl.manitu.net/"},
	{"bl.mailspike.net", "Mailspike", "https://mailspike.org/"},
}

type listing struct {
	IP     string `json:"ip"`
	List   string `json:"list"`
	URL    string `json:"url"`
	State  string `json:"state"` // clean | listed | unknown
	Answer string `json:"answer,omitempty"`
}

func checkBlocklists(ctx context.Context, ips []string) []listing {
	out := []listing{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	lookup := func(name string) ([]string, error) {
		cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		return net.DefaultResolver.LookupHost(cctx, name)
	}
	listedAnswer := func(addrs []string) bool {
		for _, a := range addrs {
			if strings.HasPrefix(a, "127.") && !strings.HasPrefix(a, "127.255.255.") {
				return true
			}
		}
		return false
	}
	for _, bl := range blocklists {
		wg.Add(1)
		go func(bl struct{ zone, name, url string }) {
			defer wg.Done()
			// RFC 5782 self-test: 127.0.0.2 is always listed. If this resolver can't show that
			// (a filtering resolver, or the list refusing it), no answer from it can be trusted.
			test, _ := lookup("2.0.0.127." + bl.zone)
			usable := listedAnswer(test)
			for _, ip := range ips {
				p := net.ParseIP(ip).To4()
				if p == nil || !publicIP(ip) {
					continue
				}
				l := listing{IP: ip, List: bl.name, URL: bl.url, State: "clean"}
				if !usable {
					l.State, l.Answer = "unknown", "this server's DNS resolver can't query this list"
				} else if addrs, err := lookup(fmt.Sprintf("%d.%d.%d.%d.%s", p[3], p[2], p[1], p[0], bl.zone)); err == nil && listedAnswer(addrs) {
					l.State, l.Answer = "listed", strings.Join(addrs, ", ")
				} else if err != nil {
					if dnsErr, ok := err.(*net.DNSError); !ok || !dnsErr.IsNotFound {
						l.State, l.Answer = "unknown", "no answer"
					}
				}
				mu.Lock()
				out = append(out, l)
				mu.Unlock()
			}
		}(bl)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].List+out[i].IP < out[j].List+out[j].IP })
	return out
}

// Check is one line of a domain's scorecard.
type Check struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	State  string `json:"state"` // ok | warn | fail | info
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
	Points int    `json:"points"`
	Max    int    `json:"max"`
}

func (c *Client) scorecard(ctx context.Context, d string, ptrOK bool, listed bool) map[string]interface{} {
	recs := c.dnsChecklist(ctx, d)
	find := func(typ string) *DNSRecord {
		for i := range recs {
			if strings.HasPrefix(recs[i].Type, typ) {
				return &recs[i]
			}
		}
		return nil
	}
	checks := []Check{}
	add := func(ch Check) { checks = append(checks, ch) }
	if r := find("MX"); r != nil {
		ch := Check{ID: "mx", Label: "Mail routing (MX)", Max: 15}
		switch r.State {
		case "ok":
			ch.State, ch.Points, ch.Detail = "ok", 15, "Points at this server."
		case "mismatch":
			ch.State, ch.Points, ch.Detail, ch.Fix = "warn", 5, "Points elsewhere: "+strings.Join(r.Current, ", "), "Set the MX record to "+r.Expected+"."
		default:
			ch.State, ch.Detail, ch.Fix = "fail", "No MX record.", "Add an MX record: "+r.Expected+"."
		}
		add(ch)
	}
	if r := find("TXT (SPF)"); r != nil {
		ch := Check{ID: "spf", Label: "SPF", Max: 15}
		switch {
		case r.State == "ok" && strings.Contains(strings.ToLower(strings.Join(r.Current, "")), "-all"):
			ch.State, ch.Points, ch.Detail = "ok", 15, "Strict (-all)."
		case r.State == "ok":
			ch.State, ch.Points, ch.Detail, ch.Fix = "warn", 11, "Present, but soft (~all or ?all).", "End the record with -all once every sender is listed."
		case r.State == "mismatch":
			ch.State, ch.Points, ch.Detail, ch.Fix = "fail", 3, "More than one SPF record; receivers treat that as an error.", "Merge them into a single record."
		default:
			ch.State, ch.Detail, ch.Fix = "fail", "No SPF record.", "Add a TXT record: "+r.Expected
		}
		add(ch)
	}
	if r := find("TXT (DKIM)"); r != nil {
		ch := Check{ID: "dkim", Label: "DKIM signing", Max: 20}
		switch r.State {
		case "ok":
			ch.State, ch.Points, ch.Detail = "ok", 20, "Key published and matching."
		case "mismatch":
			ch.State, ch.Points, ch.Detail, ch.Fix = "fail", 5, "DNS has a different key from the one mailcow signs with.", "Publish the current key (DNS records → DKIM)."
		default:
			ch.State, ch.Detail, ch.Fix = "fail", "Not published.", "Create a key and publish it (DNS records → DKIM)."
		}
		add(ch)
	}
	if r := find("TXT (DMARC)"); r != nil {
		ch := Check{ID: "dmarc", Label: "DMARC", Max: 15}
		pol := ""
		for _, t := range r.Current {
			for _, part := range strings.Split(t, ";") {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) == 2 && strings.EqualFold(kv[0], "p") {
					pol = strings.ToLower(strings.TrimSpace(kv[1]))
				}
			}
		}
		switch {
		case pol == "reject" || pol == "quarantine":
			ch.State, ch.Points, ch.Detail = "ok", 15, "Policy: "+pol+"."
		case pol == "none":
			ch.State, ch.Points, ch.Detail, ch.Fix = "warn", 8, "Monitoring only (p=none).", "Move to p=quarantine once reports show your mail passes."
		case len(r.Current) > 0:
			ch.State, ch.Points, ch.Detail = "warn", 5, "Record present, but no p= policy."
		default:
			ch.State, ch.Detail, ch.Fix = "fail", "No DMARC record.", "Add a TXT record at _dmarc."+d+": "+r.Expected
		}
		add(ch)
	}
	ptr := Check{ID: "ptr", Label: "Reverse DNS (server)", Max: 10}
	if ptrOK {
		ptr.State, ptr.Points, ptr.Detail = "ok", 10, "The server's address names this server."
	} else {
		ptr.State, ptr.Detail, ptr.Fix = "fail", "The server's address doesn't name it back.", "Ask whoever owns the IP (ISP or VPS provider) to set reverse DNS to "+c.host+"."
	}
	add(ptr)
	bl := Check{ID: "blocklists", Label: "Blocklists (server)", Max: 10}
	if listed {
		bl.State, bl.Detail, bl.Fix = "fail", "The server's address is on a blocklist.", "See the server card for which list, and request removal there."
	} else {
		bl.State, bl.Points, bl.Detail = "ok", 10, "Not listed on the lists checked."
	}
	add(bl)
	sts := c.mtaSTS(d)
	ms := Check{ID: "mta-sts", Label: "MTA-STS", Max: 10}
	switch {
	case sts.Active && sts.Mode == "enforce" && c.mtaSTSServed(ctx, d, sts):
		ms.State, ms.Points, ms.Detail = "ok", 10, "Enforced, and the policy is reachable."
	case sts.Active && c.mtaSTSServed(ctx, d, sts):
		ms.State, ms.Points, ms.Detail, ms.Fix = "warn", 6, "Policy in "+sts.Mode+" mode.", "Switch to enforce once TLS reports look clean."
	case sts.Active:
		ms.State, ms.Points, ms.Detail, ms.Fix = "warn", 2, "Configured, but the policy isn't reachable yet.", "Publish the mta-sts and _mta-sts records (DNS records), and make sure the certificate covers mta-sts."+d+"."
	default:
		ms.State, ms.Detail, ms.Fix = "info", "Not set up.", "Turn on MTA-STS (edit the domain → MTA-STS) so other servers always use TLS to reach you."
	}
	add(ms)
	tlsrpt := Check{ID: "tls-rpt", Label: "TLS reporting", Max: 5}
	if v, _ := net.DefaultResolver.LookupTXT(ctx, "_smtp._tls."+d); len(v) > 0 && strings.HasPrefix(strings.ToLower(v[0]), "v=tlsrptv1") {
		tlsrpt.State, tlsrpt.Points, tlsrpt.Detail = "ok", 5, "Reports go to "+strings.TrimPrefix(strings.SplitN(v[0], "rua=", 2)[len(strings.SplitN(v[0], "rua=", 2))-1], "mailto:")+"."
	} else {
		tlsrpt.State, tlsrpt.Detail, tlsrpt.Fix = "info", "Not set up.", "Add a TXT record at _smtp._tls."+d+": v=TLSRPTv1; rua=mailto:postmaster@"+d
	}
	add(tlsrpt)
	score, max := 0, 0
	for _, ch := range checks {
		score += ch.Points
		max += ch.Max
	}
	pct := 0
	if max > 0 {
		pct = score * 100 / max
	}
	grade := "F"
	for _, g := range []struct {
		min int
		g   string
	}{{90, "A"}, {80, "B"}, {65, "C"}, {50, "D"}} {
		if pct >= g.min {
			grade = g.g
			break
		}
	}
	return map[string]interface{}{"domain": d, "score": pct, "grade": grade, "checks": checks, "mta_sts": sts}
}

// mtaSTSServed fetches https://mta-sts.<domain>/.well-known/mta-sts.txt the way a sending
// server would (certificate checked) and confirms the published policy matches.
func (c *Client) mtaSTSServed(ctx context.Context, d string, sts MTASTS) bool {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "https://mta-sts."+d+"/.well-known/mta-sts.txt", nil)
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := strings.ToLower(string(buf[:n]))
	return resp.StatusCode == 200 && strings.Contains(body, "version: stsv1") && strings.Contains(body, "mode: "+sts.Mode)
}

func (c *Client) mtaSTSRecords(ctx context.Context, d string, add func(DNSRecord)) {
	sts := c.mtaSTS(d)
	if !sts.Active {
		return
	}
	res := net.DefaultResolver
	norm := func(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }
	want := "v=STSv1; id=" + sts.ID
	cur := []string{}
	st := "missing"
	if v, _ := res.LookupTXT(ctx, "_mta-sts."+d); len(v) > 0 {
		for _, t := range v {
			if strings.HasPrefix(strings.ToLower(t), "v=stsv1") {
				cur = append(cur, t)
				st = "mismatch"
				if strings.Contains(strings.ReplaceAll(t, " ", ""), "id="+sts.ID) {
					st = "ok"
				}
			}
		}
	}
	add(DNSRecord{Group: "policy", Name: "_mta-sts." + d, Type: "TXT (MTA-STS)", Expected: want, Current: cur, State: st,
		Help: "Announces the MTA-STS policy. The id changes whenever the policy does."})
	cn, err := res.LookupCNAME(ctx, "mta-sts."+d)
	ccur := []string{}
	cst := "missing"
	if err == nil && norm(cn) != norm("mta-sts."+d) {
		ccur = append(ccur, norm(cn))
		cst = map[bool]string{true: "ok", false: "mismatch"}[norm(cn) == norm(c.host)]
	} else if a, err := res.LookupHost(ctx, "mta-sts."+d); err == nil && len(a) > 0 {
		ccur, cst = a, "ok"
	}
	add(DNSRecord{Group: "policy", Name: "mta-sts." + d, Type: "CNAME", Expected: c.host, Current: ccur, State: cst,
		Help: "Where other servers fetch the policy from (https://mta-sts." + d + "/.well-known/mta-sts.txt). The certificate must cover this name."})
}

var (
	scoreMu    sync.Mutex
	scoreCache map[string]interface{}
	scoreTime  time.Time
)

func mountDeliver(r chi.Router, c *Client, o Options) {
	change := func(w http.ResponseWriter, path string, body interface{}) {
		msgs, err := c.Change(path, body)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, 200, map[string]interface{}{"status": "ok", "messages": msgs})
	}

	// ---- MTA-STS per domain
	r.Get("/domains/{domain}/mta-sts", func(w http.ResponseWriter, req *http.Request) {
		d := strings.ToLower(param(req, "domain"))
		if !reDomain.MatchString(d) {
			fail(w, 400, fmt.Errorf("invalid domain"))
			return
		}
		sts := c.mtaSTS(d)
		if !sts.Exists {
			sts.Mode, sts.MaxAge, sts.MX = "testing", 86400, []string{c.host}
		}
		writeJSON(w, 200, map[string]interface{}{"policy": sts, "hostname": c.host, "served": sts.Active && c.mtaSTSServed(req.Context(), d, sts)})
	})
	r.Put("/domains/{domain}/mta-sts", func(w http.ResponseWriter, req *http.Request) {
		d := strings.ToLower(param(req, "domain"))
		var in struct {
			Active bool     `json:"active"`
			Mode   string   `json:"mode"`
			MaxAge int      `json:"max_age"`
			MX     []string `json:"mx"`
		}
		if !reDomain.MatchString(d) || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		if in.Mode != "enforce" && in.Mode != "testing" && in.Mode != "none" {
			fail(w, 400, fmt.Errorf("mode: enforce, testing or none"))
			return
		}
		if in.MaxAge < 86400 || in.MaxAge > 31536000 {
			fail(w, 400, fmt.Errorf("max age: between 1 day and 1 year"))
			return
		}
		mx := []string{}
		for _, m := range in.MX {
			m = strings.ToLower(strings.TrimSpace(m))
			if m == "" {
				continue
			}
			if !reDomain.MatchString(strings.TrimPrefix(m, "*.")) {
				fail(w, 400, fmt.Errorf("%q is not a host name", m))
				return
			}
			mx = append(mx, m)
		}
		if len(mx) == 0 {
			mx = []string{c.host}
		}
		attr := map[string]interface{}{"version": "STSv1", "mode": in.Mode, "max_age": strconv.Itoa(in.MaxAge), "mx": strings.Join(mx, ","), "active": flag(in.Active)}
		if c.mtaSTS(d).Exists {
			change(w, "edit/mta-sts", map[string]interface{}{"items": []string{d}, "attr": attr})
			return
		}
		attr["domain"] = d
		change(w, "add/mta-sts", attr)
	})

	// ---- deliverability scorecard for every domain, plus the server itself
	r.Get("/deliverability", func(w http.ResponseWriter, req *http.Request) {
		scoreMu.Lock()
		if scoreCache != nil && time.Since(scoreTime) < 10*time.Minute && req.URL.Query().Get("refresh") == "" {
			out := scoreCache
			scoreMu.Unlock()
			writeJSON(w, 200, out)
			return
		}
		scoreMu.Unlock()
		ctx, cancel := context.WithTimeout(req.Context(), 90*time.Second)
		defer cancel()
		var doms []struct {
			Name   string      `json:"domain_name"`
			Active json.Number `json:"active"`
		}
		data, err := c.List("get/domain/all")
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		json.Unmarshal(data, &doms)
		// the server: addresses, reverse DNS and blocklists
		ips, _ := net.DefaultResolver.LookupHost(ctx, c.host)
		sort.Strings(ips)
		ptrs := map[string][]string{}
		ptrOK := len(ips) > 0
		for _, ip := range ips {
			names, _ := net.DefaultResolver.LookupAddr(ctx, ip)
			if names == nil {
				names = []string{}
			}
			ptrs[ip] = names
			ok := false
			for _, n := range names {
				ok = ok || strings.EqualFold(strings.TrimSuffix(n, "."), c.host)
			}
			ptrOK = ptrOK && ok
		}
		lists := checkBlocklists(ctx, ips)
		listed := false
		for _, l := range lists {
			listed = listed || l.State == "listed"
		}
		cards := make([]map[string]interface{}, len(doms))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 3)
		for i, d := range doms {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				sem <- struct{}{}
				cards[i] = c.scorecard(ctx, strings.ToLower(name), ptrOK, listed)
				<-sem
			}(i, d.Name)
		}
		wg.Wait()
		sort.SliceStable(cards, func(i, j int) bool { return cards[i]["score"].(int) < cards[j]["score"].(int) })
		out := map[string]interface{}{"checked": time.Now().UTC(), "server": map[string]interface{}{"hostname": c.host, "ips": ips, "ptr": ptrs, "ptr_ok": ptrOK, "blocklists": lists, "listed": listed}, "domains": cards}
		scoreMu.Lock()
		scoreCache, scoreTime = out, time.Now()
		scoreMu.Unlock()
		writeJSON(w, 200, out)
	})

	// ---- open mailcow as a domain admin (single-use token, valid 30 seconds)
	r.Post("/domain-admins/{username}/sso", func(w http.ResponseWriter, req *http.Request) {
		u := param(req, "username")
		if !reUser.MatchString(u) {
			fail(w, 400, fmt.Errorf("invalid username"))
			return
		}
		raw, err := c.do(http.MethodPost, "add/sso/domain-admin", map[string]string{"username": u})
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		var tok struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(raw, &tok) != nil || tok.Token == "" {
			fail(w, 400, fmt.Errorf("mailcow didn't issue a sign-in token for %s (is the account active?)", u))
			return
		}
		writeJSON(w, 200, map[string]string{"url": "https://" + c.host + "/domainadmin/?sso_token=" + url.QueryEscape(tok.Token)})
	})
}
