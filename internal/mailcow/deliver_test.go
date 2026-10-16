package mailcow

import (
	"strings"
	"testing"
	"time"
)

func goodRecs() []DNSRecord {
	return []DNSRecord{
		{Type: "MX", State: "ok", Expected: "10 mail.example.org", Current: []string{"10 mail.example.org"}},
		{Type: "TXT (SPF)", State: "ok", Current: []string{"v=spf1 mx a -all"}},
		{Type: "TXT (DKIM)", State: "ok"},
		{Type: "TXT (DMARC)", State: "ok", Current: []string{"v=DMARC1; p=reject; rua=mailto:postmaster@example.org"}},
	}
}

func check(checks []Check, id string) Check {
	for _, c := range checks {
		if c.ID == id {
			return c
		}
	}
	return Check{}
}

func TestGradePerfect(t *testing.T) {
	sts := MTASTS{Active: true, Mode: "enforce"}
	checks, pct, grade := gradeDomain("example.org", "mail.example.org", goodRecs(), true, false, sts, true, []string{"v=TLSRPTv1; rua=mailto:tls@example.org"})
	if pct != 100 || grade != "A" {
		t.Errorf("all green should be 100/A, got %d/%s: %+v", pct, grade, checks)
	}
	if c := check(checks, "tls-rpt"); c.State != "ok" || !strings.Contains(c.Detail, "tls@example.org") {
		t.Errorf("TLS-RPT detail wrong: %+v", c)
	}
}

func TestGradeProblems(t *testing.T) {
	recs := goodRecs()
	recs[1] = DNSRecord{Type: "TXT (SPF)", State: "ok", Current: []string{"v=spf1 mx ~all"}}
	recs[3] = DNSRecord{Type: "TXT (DMARC)", State: "ok", Current: []string{"v=DMARC1; p=none"}}
	checks, pct, grade := gradeDomain("example.org", "mail.example.org", recs, false, true, MTASTS{}, false, nil)
	if c := check(checks, "spf"); c.State != "warn" || c.Points != 11 {
		t.Errorf("soft SPF should warn: %+v", c)
	}
	if c := check(checks, "dmarc"); c.State != "warn" || c.Points != 8 {
		t.Errorf("p=none should warn: %+v", c)
	}
	if c := check(checks, "ptr"); c.State != "fail" || !strings.Contains(c.Fix, "mail.example.org") {
		t.Errorf("missing PTR should fail and name the host: %+v", c)
	}
	if c := check(checks, "blocklists"); c.State != "fail" || c.Points != 0 {
		t.Errorf("a listing should fail: %+v", c)
	}
	if c := check(checks, "mta-sts"); c.State != "info" {
		t.Errorf("no MTA-STS is informational: %+v", c)
	}
	if pct >= 80 || grade == "A" || grade == "B" {
		t.Errorf("this domain shouldn't score well: %d/%s", pct, grade)
	}
}

func TestGradeMissingEverything(t *testing.T) {
	recs := []DNSRecord{{Type: "MX", State: "missing", Expected: "10 mail.example.org"}, {Type: "TXT (SPF)", State: "missing", Expected: "v=spf1 mx a -all"},
		{Type: "TXT (DKIM)", State: "missing"}, {Type: "TXT (DMARC)", State: "missing", Expected: "v=DMARC1; p=quarantine"}}
	checks, pct, grade := gradeDomain("example.org", "mail.example.org", recs, false, false, MTASTS{}, false, nil)
	if grade != "F" || pct > 20 {
		t.Errorf("nothing set up should be F, got %d/%s", pct, grade)
	}
	for _, id := range []string{"mx", "spf", "dkim", "dmarc"} {
		if c := check(checks, id); c.State != "fail" || c.Fix == "" {
			t.Errorf("%s should fail with a fix: %+v", id, c)
		}
	}
}

func TestMTASTSServedStates(t *testing.T) {
	_, _, _ = gradeDomain("example.org", "h", goodRecs(), true, false, MTASTS{Active: true, Mode: "testing"}, true, nil)
	checks, _, _ := gradeDomain("example.org", "h", goodRecs(), true, false, MTASTS{Active: true, Mode: "testing"}, true, nil)
	if c := check(checks, "mta-sts"); c.State != "warn" || c.Points != 6 {
		t.Errorf("testing mode, reachable: %+v", c)
	}
	checks, _, _ = gradeDomain("example.org", "h", goodRecs(), true, false, MTASTS{Active: true, Mode: "enforce"}, false, nil)
	if c := check(checks, "mta-sts"); c.State != "warn" || c.Points != 2 {
		t.Errorf("configured but unreachable: %+v", c)
	}
}

func TestListedAnswer(t *testing.T) {
	for _, c := range []struct {
		addrs []string
		want  bool
	}{
		{[]string{"127.0.0.2"}, true},
		{[]string{"127.0.0.10", "127.0.0.4"}, true},
		{[]string{"127.255.255.254"}, false}, // Spamhaus: query refused
		{[]string{"0.0.0.0"}, false},         // a filtering resolver's "blocked" answer
		{[]string{"192.168.1.1"}, false},     // a resolver answering with itself
		{nil, false},
	} {
		if got := listedAnswer(c.addrs); got != c.want {
			t.Errorf("listedAnswer(%v) = %v, want %v", c.addrs, got, c.want)
		}
	}
}

func TestDKIMP(t *testing.T) {
	if got := dkimP("v=DKIM1; k=rsa; t=s; p=MIIBIj ANBgk"); got != "MIIBIjANBgk" {
		t.Errorf("dkimP joined value wrong: %q", got)
	}
	if got := dkimP("v=DKIM1; k=rsa"); got != "" {
		t.Errorf("no p= should give empty, got %q", got)
	}
}

func TestForgetScores(t *testing.T) {
	scoreMu.Lock()
	scoreCache, scoreTime = map[string]interface{}{"domains": []string{"gone.example"}}, time.Now()
	scoreMu.Unlock()
	forgetScores()
	if scoreCache != nil {
		t.Error("the scorecard cache should be empty after a domain is added or removed")
	}
}
