package mailcow

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// Options connects the mailcow routes to things that live on the host side.
type Options struct {
	// Gate runs an allowlisted verb through cowsec-hostctl (domain-admin ACLs live in
	// mailcow's database; netfilter coordination runs as a timer on the host).
	Gate func(verb string, args ...string) ([]byte, error)
}

var (
	reUser      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	reACLKey    = regexp.MustCompile(`^[a-z_]{2,40}$`)
	reHost      = regexp.MustCompile(`^(?i)\[?[a-z0-9.:-]{1,253}\]?(:\d{1,5})?$`)
	tlsPolicies = map[string]bool{"none": true, "may": true, "encrypt": true, "dane": true, "dane-only": true,
		"fingerprint": true, "verify": true, "secure": true}
	rlFrames = map[string]bool{"s": true, "m": true, "h": true, "d": true}
)

func mountAdmin(r chi.Router, c *Client, o Options) {
	c.dnsRoutes(r)
	change := func(w http.ResponseWriter, path string, body interface{}) {
		msgs, err := c.Change(path, body)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, 200, map[string]interface{}{"status": "ok", "messages": msgs})
	}
	list := func(path string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			data, err := c.List(path)
			if err != nil {
				fail(w, http.StatusBadGateway, err)
				return
			}
			writeRaw(w, data)
		}
	}
	gate := func(verb string, args ...string) (json.RawMessage, error) {
		if o.Gate == nil {
			return nil, fmt.Errorf("host helper not available")
		}
		out, err := o.Gate(verb, args...)
		return json.RawMessage(out), err
	}

	// ---- domain administrators and their permissions
	r.Get("/domain-admins", func(w http.ResponseWriter, _ *http.Request) {
		admins, err := c.List("get/domain-admin/all")
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		acl, err := gate("mailcow-da-acl")
		if err != nil {
			acl = json.RawMessage(`{"keys":[],"acls":{},"error":"permissions unavailable"}`)
		}
		writeJSON(w, 200, map[string]json.RawMessage{"admins": admins, "acl": acl})
	})
	r.Post("/domain-admins", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Username string   `json:"username"`
			Password string   `json:"password"`
			Domains  []string `json:"domains"`
			Active   bool     `json:"active"`
		}
		if err := decode(req, &in); err != nil || !reUser.MatchString(in.Username) {
			fail(w, 400, fmt.Errorf("username: letters, digits, dot, dash and underscore"))
			return
		}
		if len(in.Password) < 8 {
			fail(w, 400, fmt.Errorf("password: at least 8 characters"))
			return
		}
		if err := domains(in.Domains); err != nil {
			fail(w, 400, err)
			return
		}
		change(w, "add/domain-admin", map[string]interface{}{"username": strings.ToLower(in.Username), "password": in.Password,
			"password2": in.Password, "domains": in.Domains, "active": flag(in.Active)})
	})
	r.Patch("/domain-admins/{username}", func(w http.ResponseWriter, req *http.Request) {
		u := param(req, "username")
		var in struct {
			Domains  *[]string `json:"domains"`
			Active   *bool     `json:"active"`
			Password *string   `json:"password"`
		}
		if !reUser.MatchString(u) || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		attr := map[string]interface{}{}
		if in.Domains != nil {
			if err := domains(*in.Domains); err != nil {
				fail(w, 400, err)
				return
			}
			attr["domains"] = *in.Domains
		}
		if in.Active != nil {
			attr["active"] = flag(*in.Active)
		}
		if in.Password != nil {
			if len(*in.Password) < 8 {
				fail(w, 400, fmt.Errorf("password: at least 8 characters"))
				return
			}
			attr["password"], attr["password2"] = *in.Password, *in.Password
		}
		change(w, "edit/domain-admin", map[string]interface{}{"items": []string{u}, "attr": attr})
	})
	r.Put("/domain-admins/{username}/acl", func(w http.ResponseWriter, req *http.Request) {
		u := param(req, "username")
		var in struct {
			Allow []string `json:"allow"`
		}
		if !reUser.MatchString(u) || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		for _, k := range in.Allow {
			if !reACLKey.MatchString(k) {
				fail(w, 400, fmt.Errorf("invalid permission %q", k))
				return
			}
		}
		// mailcow turns off every permission not in the list
		change(w, "edit/da-acl", map[string]interface{}{"items": []string{u}, "attr": map[string]interface{}{"da_acl": in.Allow}})
	})
	r.Delete("/domain-admins/{username}", func(w http.ResponseWriter, req *http.Request) {
		u := param(req, "username")
		if !reUser.MatchString(u) {
			fail(w, 400, fmt.Errorf("invalid username"))
			return
		}
		change(w, "delete/domain-admin", []string{u})
	})

	// ---- rate limits (messages per second/minute/hour/day)
	r.Get("/ratelimits", func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]json.RawMessage{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for key, path := range map[string]string{"domains": "get/rl-domain/all", "mailboxes": "get/rl-mbox/all"} {
			wg.Add(1)
			go func(key, path string) {
				defer wg.Done()
				data, err := c.List(path)
				if err != nil {
					data, _ = json.Marshal(map[string]string{"error": err.Error()})
				}
				mu.Lock()
				out[key] = data
				mu.Unlock()
			}(key, path)
		}
		wg.Wait()
		writeJSON(w, 200, out)
	})
	r.Put("/ratelimits/{kind}/{object}", func(w http.ResponseWriter, req *http.Request) {
		kind, obj := chi.URLParam(req, "kind"), param(req, "object")
		var in struct {
			Value int    `json:"value"`
			Frame string `json:"frame"`
		}
		path := map[string]string{"domain": "edit/rl-domain", "mailbox": "edit/rl-mbox"}[kind]
		if path == "" || decode(req, &in) != nil || in.Value < 0 || in.Value > 1000000 || !rlFrames[in.Frame] {
			fail(w, 400, fmt.Errorf("a limit is a number of messages per s, m, h or d (0 removes it)"))
			return
		}
		if (kind == "domain" && !reDomain.MatchString(obj)) || (kind == "mailbox" && !reEmail.MatchString(obj)) {
			fail(w, 400, fmt.Errorf("invalid %s", kind))
			return
		}
		change(w, path, map[string]interface{}{"items": []string{obj}, "attr": map[string]interface{}{"rl_value": strconv.Itoa(in.Value), "rl_frame": in.Frame}})
	})

	// ---- TLS policy maps (outbound TLS requirements per destination)
	r.Get("/tls-policies", list("get/tls-policy-map/all"))
	r.Post("/tls-policies", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Dest       string `json:"dest"`
			Policy     string `json:"policy"`
			Parameters string `json:"parameters"`
			Active     bool   `json:"active"`
		}
		if err := decode(req, &in); err != nil || !(reDomain.MatchString(in.Dest) || reEmail.MatchString(in.Dest)) {
			fail(w, 400, fmt.Errorf("destination: a domain like bank.example, or an address"))
			return
		}
		if !tlsPolicies[in.Policy] {
			fail(w, 400, fmt.Errorf("unknown TLS policy"))
			return
		}
		change(w, "add/tls-policy-map", map[string]interface{}{"dest": strings.ToLower(in.Dest), "policy": in.Policy,
			"parameters": trim(in.Parameters, 255), "active": flag(in.Active)})
	})
	r.Patch("/tls-policies/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := chi.URLParam(req, "id")
		var in struct {
			Policy     *string `json:"policy"`
			Parameters *string `json:"parameters"`
			Active     *bool   `json:"active"`
		}
		if _, err := strconv.Atoi(id); err != nil || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		attr := map[string]interface{}{}
		if in.Policy != nil {
			if !tlsPolicies[*in.Policy] {
				fail(w, 400, fmt.Errorf("unknown TLS policy"))
				return
			}
			attr["policy"] = *in.Policy
		}
		if in.Parameters != nil {
			attr["parameters"] = trim(*in.Parameters, 255)
		}
		if in.Active != nil {
			attr["active"] = flag(*in.Active)
		}
		change(w, "edit/tls-policy-map", map[string]interface{}{"items": []string{id}, "attr": attr})
	})
	r.Delete("/tls-policies/{id}", deleteByID(change, "delete/tls-policy-map"))

	// ---- relay hosts (sender-dependent) and transport maps (destination-dependent)
	r.Get("/relayhosts", list("get/relayhost/all"))
	r.Post("/relayhosts", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Hostname string `json:"hostname"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decode(req, &in); err != nil || !reHost.MatchString(in.Hostname) {
			fail(w, 400, fmt.Errorf("host: name or [name]:port, e.g. [smtp.example.net]:587"))
			return
		}
		change(w, "add/relayhost", map[string]interface{}{"hostname": in.Hostname, "username": trim(in.Username, 255), "password": in.Password})
	})
	r.Patch("/relayhosts/{id}", activeToggle(change, "edit/relayhost"))
	r.Delete("/relayhosts/{id}", deleteByID(change, "delete/relayhost"))
	r.Put("/domains/{domain}/relayhost", func(w http.ResponseWriter, req *http.Request) {
		d := param(req, "domain")
		var in struct {
			ID int `json:"id"` // 0 = send directly
		}
		if !reDomain.MatchString(d) || decode(req, &in) != nil || in.ID < 0 {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		change(w, "edit/domain", map[string]interface{}{"items": []string{d}, "attr": map[string]interface{}{"relayhost": strconv.Itoa(in.ID)}})
	})
	r.Get("/transports", list("get/transport/all"))
	r.Post("/transports", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Destination string `json:"destination"`
			Nexthop     string `json:"nexthop"`
			Username    string `json:"username"`
			Password    string `json:"password"`
			Active      bool   `json:"active"`
			MXBased     bool   `json:"mxBased"`
		}
		if err := decode(req, &in); err != nil || in.Destination == "" || len(in.Destination) > 255 || strings.ContainsAny(in.Destination, "\n\r") {
			fail(w, 400, fmt.Errorf("enter a destination (domain, .subdomains, address or *)"))
			return
		}
		if !reHost.MatchString(in.Nexthop) {
			fail(w, 400, fmt.Errorf("next hop: name or [name]:port"))
			return
		}
		change(w, "add/transport", map[string]interface{}{"destination": strings.ToLower(in.Destination), "nexthop": in.Nexthop,
			"username": trim(in.Username, 255), "password": in.Password, "active": flag(in.Active), "is_mx_based": flag(in.MXBased)})
	})
	r.Patch("/transports/{id}", activeToggle(change, "edit/transport"))
	r.Delete("/transports/{id}", deleteByID(change, "delete/transport"))

	// ---- netfilter: mailcow's own ban engine, and how it works with CrowdSec
	r.Get("/netfilter", func(w http.ResponseWriter, _ *http.Request) {
		f2b, err := c.Get("get/fail2ban")
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		st, err := gate("netfilter-state")
		if err != nil {
			st = json.RawMessage(`{"mode":"side-by-side","syncTrusted":false}`)
		}
		writeJSON(w, 200, map[string]json.RawMessage{"settings": f2b, "coordination": st})
	})
	r.Put("/netfilter/settings", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			BanTime          int    `json:"ban_time"`
			MaxBanTime       int    `json:"max_ban_time"`
			BanTimeIncrement bool   `json:"ban_time_increment"`
			MaxAttempts      int    `json:"max_attempts"`
			RetryWindow      int    `json:"retry_window"`
			NetbanIPv4       int    `json:"netban_ipv4"`
			NetbanIPv6       int    `json:"netban_ipv6"`
			Whitelist        string `json:"whitelist"`
			Blacklist        string `json:"blacklist"`
		}
		if decode(req, &in) != nil || in.BanTime < 60 || in.MaxBanTime < in.BanTime || in.MaxAttempts < 1 || in.RetryWindow < 1 ||
			in.NetbanIPv4 < 8 || in.NetbanIPv4 > 32 || in.NetbanIPv6 < 8 || in.NetbanIPv6 > 128 {
			fail(w, 400, fmt.Errorf("check the values: ban time ≥ 60 s, max ban time ≥ ban time, IPv4 /8–/32, IPv6 /8–/128"))
			return
		}
		for _, list := range []string{in.Whitelist, in.Blacklist} {
			if err := networks(list); err != nil {
				fail(w, 400, err)
				return
			}
		}
		cur, err := c.Get("get/fail2ban")
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		var now struct {
			ManageExternal int `json:"manage_external"`
		}
		json.Unmarshal(cur, &now)
		// mailcow resets every field an edit leaves out, so always send the full set
		change(w, "edit/fail2ban", map[string]interface{}{"items": []string{"none"}, "attr": map[string]interface{}{
			"ban_time": in.BanTime, "max_ban_time": in.MaxBanTime, "ban_time_increment": flag(in.BanTimeIncrement),
			"max_attempts": in.MaxAttempts, "retry_window": in.RetryWindow, "netban_ipv4": in.NetbanIPv4, "netban_ipv6": in.NetbanIPv6,
			"whitelist": in.Whitelist, "blacklist": in.Blacklist, "manage_external": now.ManageExternal}})
	})
	r.Post("/netfilter/{action}", func(w http.ResponseWriter, req *http.Request) {
		action := chi.URLParam(req, "action")
		var in struct {
			Network string `json:"network"`
		}
		if !map[string]bool{"unban": true, "whitelist": true, "blacklist": true}[action] || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		n, err := network(in.Network)
		if err != nil {
			fail(w, 400, err)
			return
		}
		change(w, "edit/fail2ban", map[string]interface{}{"items": []string{n}, "attr": map[string]interface{}{"action": action}})
	})
	r.Post("/netfilter-sync", func(w http.ResponseWriter, _ *http.Request) {
		st, err := gate("netfilter-sync")
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		if len(st) == 0 {
			st = json.RawMessage(`{"status":"ok"}`)
		}
		writeRaw(w, st)
	})
	r.Put("/netfilter/coordination", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Mode        string `json:"mode"`
			SyncTrusted bool   `json:"syncTrusted"`
		}
		if decode(req, &in) != nil || (in.Mode != "side-by-side" && in.Mode != "crowdsec") {
			fail(w, 400, fmt.Errorf("mode must be side-by-side or crowdsec"))
			return
		}
		st, err := gate("netfilter-coordinate", in.Mode, flag(in.SyncTrusted))
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		writeRaw(w, st)
	})
}

// Unban lifts a network from mailcow's netfilter too, so a ban lifted in CowSec is gone everywhere.
func (c *Client) Unban(value string) error {
	n, err := network(value)
	if err != nil {
		return err
	}
	_, err = c.Change("edit/fail2ban", map[string]interface{}{"items": []string{n}, "attr": map[string]interface{}{"action": "unban"}})
	return err
}

func deleteByID(change func(http.ResponseWriter, string, interface{}), path string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		id := chi.URLParam(req, "id")
		if _, err := strconv.Atoi(id); err != nil {
			fail(w, 400, fmt.Errorf("invalid id"))
			return
		}
		change(w, path, []string{id})
	}
}

func activeToggle(change func(http.ResponseWriter, string, interface{}), path string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		id := chi.URLParam(req, "id")
		var in struct {
			Active bool `json:"active"`
		}
		if _, err := strconv.Atoi(id); err != nil || decode(req, &in) != nil {
			fail(w, 400, fmt.Errorf("invalid request"))
			return
		}
		change(w, path, map[string]interface{}{"items": []string{id}, "attr": map[string]interface{}{"active": flag(in.Active)}})
	}
}

func domains(list []string) error {
	if len(list) == 0 || len(list) > 500 {
		return fmt.Errorf("choose at least one domain")
	}
	for _, d := range list {
		if !reDomain.MatchString(d) {
			return fmt.Errorf("%q is not a domain", d)
		}
	}
	return nil
}

// network normalises an IP or CIDR the way netfilter stores it (1.2.3.4 -> 1.2.3.4/32).
func network(s string) (string, error) {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String(), nil
	}
	return "", fmt.Errorf("%q is not an IP address or network", s)
}

func networks(list string) error {
	for _, x := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' || r == '\r' }) {
		if _, err := network(x); err != nil && !reDomain.MatchString(x) {
			return err
		}
	}
	return nil
}
