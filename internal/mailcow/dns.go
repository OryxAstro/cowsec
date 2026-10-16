package mailcow

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSRecord is one row of a domain's DNS checklist: what mailcow needs, and what DNS
// answers right now.
type DNSRecord struct {
	Group    string   `json:"group"` // server, mail, autoconfig, policy, signing
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Expected string   `json:"expected"`
	Current  []string `json:"current"`
	State    string   `json:"state"` // ok | mismatch | missing | info
	Optional bool     `json:"optional"`
	Help     string   `json:"help"`
}

func (c *Client) dnsRoutes(r interface {
	Get(string, http.HandlerFunc)
}) {
	r.Get("/dns/{domain}", func(w http.ResponseWriter, req *http.Request) {
		d := strings.ToLower(param(req, "domain"))
		if !reDomain.MatchString(d) {
			fail(w, 400, fmt.Errorf("invalid domain"))
			return
		}
		writeJSON(w, 200, map[string]interface{}{"domain": d, "hostname": c.host, "records": c.dnsChecklist(req.Context(), d)})
	})
}

func (c *Client) dnsChecklist(ctx context.Context, d string) []DNSRecord {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	h := c.host
	res := net.DefaultResolver
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := []DNSRecord{}
	add := func(rec DNSRecord) {
		mu.Lock()
		out = append(out, rec)
		mu.Unlock()
	}
	run := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	norm := func(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

	// the server's own name, its address and reverse DNS
	addrs, _ := res.LookupHost(ctx, h)
	sort.Strings(addrs)
	add(DNSRecord{Group: "server", Name: h, Type: "A / AAAA", Expected: "this server's public address", Current: addrs,
		State: map[bool]string{true: "ok", false: "missing"}[len(addrs) > 0], Help: "Mail servers find yours through this name."})
	for _, ip := range addrs {
		ip := ip
		run(func() {
			names, _ := res.LookupAddr(ctx, ip)
			st := "mismatch"
			for _, n := range names {
				if norm(n) == norm(h) {
					st = "ok"
				}
			}
			if len(names) == 0 {
				st = "missing"
			}
			add(DNSRecord{Group: "server", Name: ip, Type: "PTR", Expected: h, Current: names, State: st,
				Help: "Reverse DNS, set by whoever owns the IP (your ISP or VPS provider). Many receivers reject mail without it."})
		})
	}
	run(func() {
		want := c.tlsaExpected(h)
		got := lookupTLSA("_25._tcp." + h)
		st := "info"
		if want != "" && len(got) > 0 {
			st = "mismatch"
			for _, g := range got {
				if g == want {
					st = "ok"
				}
			}
		} else if want != "" {
			st = "missing"
		}
		add(DNSRecord{Group: "server", Name: "_25._tcp." + h, Type: "TLSA", Expected: want, Current: got, State: st, Optional: true,
			Help: "DANE: lets other servers pin your mail certificate. Only useful with DNSSEC; update it when the certificate's key changes."})
	})
	// mail routing
	run(func() {
		mx, _ := res.LookupMX(ctx, d)
		cur := []string{}
		st := "missing"
		for _, m := range mx {
			cur = append(cur, fmt.Sprintf("%d %s", m.Pref, norm(m.Host)))
			if norm(m.Host) == norm(h) {
				st = "ok"
			}
		}
		if st != "ok" && len(mx) > 0 {
			st = "mismatch"
		}
		add(DNSRecord{Group: "mail", Name: d, Type: "MX", Expected: "10 " + h, Current: cur, State: st, Help: "Where other servers deliver mail for this domain."})
	})
	// client autoconfiguration
	for _, sub := range []string{"autodiscover", "autoconfig"} {
		sub := sub
		run(func() {
			cn, err := res.LookupCNAME(ctx, sub+"."+d)
			cur := []string{}
			st := "missing"
			if err == nil && norm(cn) != norm(sub+"."+d) {
				cur = append(cur, norm(cn))
				st = map[bool]string{true: "ok", false: "mismatch"}[norm(cn) == norm(h)]
			}
			add(DNSRecord{Group: "autoconfig", Name: sub + "." + d, Type: "CNAME", Expected: h, Current: cur, State: st, Optional: true,
				Help: "Lets Outlook, Thunderbird and phones set themselves up from just the address."})
		})
	}
	for _, s := range []struct{ svc, port string }{{"autodiscover", "443"}, {"imaps", "993"}, {"submissions", "465"}, {"submission", "587"}} {
		s := s
		run(func() {
			_, srv, _ := res.LookupSRV(ctx, s.svc, "tcp", d)
			cur := []string{}
			st := "missing"
			for _, r := range srv {
				cur = append(cur, fmt.Sprintf("%s %d", norm(r.Target), r.Port))
				if norm(r.Target) == norm(h) && fmt.Sprint(r.Port) == s.port {
					st = "ok"
				}
			}
			if st != "ok" && len(srv) > 0 {
				st = "mismatch"
			}
			add(DNSRecord{Group: "autoconfig", Name: "_" + s.svc + "._tcp." + d, Type: "SRV", Expected: "0 1 " + s.port + " " + h, Current: cur, State: st, Optional: true,
				Help: "Service discovery for mail clients."})
		})
	}
	// sender policy
	txt := func(name string) []string {
		v, _ := res.LookupTXT(ctx, name)
		return v
	}
	run(func() {
		cur := []string{}
		for _, t := range txt(d) {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				cur = append(cur, t)
			}
		}
		st := "missing"
		if len(cur) == 1 {
			st = "ok"
		} else if len(cur) > 1 {
			st = "mismatch" // more than one SPF record is an error
		}
		add(DNSRecord{Group: "policy", Name: d, Type: "TXT (SPF)", Expected: "v=spf1 mx a -all", Current: cur, State: st,
			Help: "Which servers may send for this domain. Keep exactly one SPF record; add include: entries for other senders."})
	})
	run(func() {
		cur := []string{}
		for _, t := range txt("_dmarc." + d) {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				cur = append(cur, t)
			}
		}
		st := map[bool]string{true: "ok", false: "missing"}[len(cur) > 0]
		add(DNSRecord{Group: "policy", Name: "_dmarc." + d, Type: "TXT (DMARC)", Expected: "v=DMARC1; p=quarantine; rua=mailto:postmaster@" + d,
			Current: cur, State: st, Help: "Tells receivers what to do with mail that fails SPF and DKIM, and where to send reports."})
	})
	run(func() { c.mtaSTSRecords(ctx, d, add) })
	// signing
	run(func() {
		var k struct {
			Selector string `json:"dkim_selector"`
			Txt      string `json:"dkim_txt"`
		}
		if raw, err := c.Get("get/dkim/" + d); err == nil {
			json.Unmarshal(raw, &k)
		}
		if k.Txt == "" {
			add(DNSRecord{Group: "signing", Name: "dkim._domainkey." + d, Type: "TXT (DKIM)", Expected: "", State: "missing",
				Help: "No DKIM key yet. Generate one, then publish it here."})
			return
		}
		name := k.Selector + "._domainkey." + d
		cur := txt(name)
		st := "missing"
		squash := func(s string) string { return strings.Join(strings.Fields(strings.ReplaceAll(s, "\"", "")), "") }
		for _, t := range cur {
			st = "mismatch"
			if squash(t) == squash(k.Txt) {
				st = "ok"
				break
			}
		}
		add(DNSRecord{Group: "signing", Name: name, Type: "TXT (DKIM)", Expected: k.Txt, Current: cur, State: st,
			Help: "The public half of the key mailcow signs outgoing mail with."})
	})
	wg.Wait()
	order := map[string]int{"server": 0, "mail": 1, "policy": 2, "signing": 3, "autoconfig": 4}
	typeOrder := map[string]int{"A / AAAA": 0, "PTR": 1, "TLSA": 2, "CNAME": 0, "SRV": 1, "TXT (SPF)": 0, "TXT (DMARC)": 1, "TXT (MTA-STS)": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Group] != order[out[j].Group] {
			return order[out[i].Group] < order[out[j].Group]
		}
		ti, tj := typeOrder[out[i].Type], typeOrder[out[j].Type]
		if ti != tj {
			return ti < tj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// tlsaExpected builds "3 1 1 <sha256 of the key>" from the certificate postfix presents.
func (c *Client) tlsaExpected(host string) string {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:25", 6*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		return ""
	}
	defer cl.Close()
	if err := cl.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true}); err != nil { //nolint:gosec // we only read the key
		return ""
	}
	st, ok := cl.TLSConnectionState()
	if !ok || len(st.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(st.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return "3 1 1 " + hex.EncodeToString(sum[:])
}

// lookupTLSA asks the system's first resolver for TLSA records (the standard library can't).
func lookupTLSA(name string) []string {
	server := "127.0.0.53:53"
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) == 2 && f[0] == "nameserver" {
				server = net.JoinHostPort(f[1], "53")
				break
			}
		}
	}
	qn, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil
	}
	const typeTLSA dnsmessage.Type = 52
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qn, Type: typeTLSA, Class: dnsmessage.ClassINET}}}
	pkt, err := msg.Pack()
	if err != nil {
		return nil
	}
	conn, err := net.DialTimeout("udp", server, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	var resp dnsmessage.Message
	if resp.Unpack(buf[:n]) != nil {
		return nil
	}
	out := []string{}
	for _, a := range resp.Answers {
		if u, ok := a.Body.(*dnsmessage.UnknownResource); ok && a.Header.Type == typeTLSA && len(u.Data) > 3 {
			out = append(out, fmt.Sprintf("%d %d %d %s", u.Data[0], u.Data[1], u.Data[2], hex.EncodeToString(u.Data[3:])))
		}
	}
	return out
}
