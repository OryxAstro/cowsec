package mailcow

import (
	"reflect"
	"strings"
	"testing"
)

func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }
func bp(b bool) *bool     { return &b }

func TestMailboxSenderACL(t *testing.T) {
	cases := []struct {
		in      []string
		want    []string
		wantErr bool
	}{
		{[]string{"Sales@Example.org", "@example.net", " "}, []string{"sales@example.org", "@example.net"}, false},
		{[]string{"*"}, []string{"*"}, false},
		{[]string{}, []string{"default"}, false}, // mailcow's way of clearing the list
		{[]string{"not an address"}, nil, true},
		{[]string{"@bad_domain"}, nil, true},
	}
	for _, c := range cases {
		in := c.in
		a, err := mailboxIn{SenderACL: &in}.attrs()
		if c.wantErr {
			if err == nil {
				t.Errorf("%v: expected an error", c.in)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(a["sender_acl"], c.want) {
			t.Errorf("%v: got %v (%v), want %v", c.in, a["sender_acl"], err, c.want)
		}
	}
}

func TestMailboxFields(t *testing.T) {
	protos := []string{"imap", "smtp"}
	a, err := mailboxIn{Name: sp("  Alice  "), Password: sp("0123456789"), Quota: ip(512), ForceTFA: bp(true), Protocols: &protos}.attrs()
	if err != nil {
		t.Fatal(err)
	}
	if a["name"] != "Alice" || a["password"] != "0123456789" || a["password2"] != "0123456789" || a["quota"] != "512" || a["force_tfa"] != "1" {
		t.Errorf("fields wrong: %v", a)
	}
	if a["imap_access"] != "1" || a["smtp_access"] != "1" || a["pop3_access"] != "0" || a["eas_access"] != "0" {
		t.Errorf("protocol flags wrong: %v", a)
	}
	for name, in := range map[string]mailboxIn{
		"short password": {Password: sp("short")},
		"quota too big":  {Quota: ip(20000000)},
		"bad protocol":   {Protocols: &[]string{"telnet"}},
		"bad tag":        {Tags: &[]string{"<script>"}},
		"bad handler":    {TaggedMailHandler: sp("elsewhere")},
	} {
		if _, err := in.attrs(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestDomainRateLimit(t *testing.T) {
	a, err := domainIn{RLValue: ip(100), RLFrame: sp("h")}.attrs()
	if err != nil || a["rl_value"] != "100" || a["rl_frame"] != "h" {
		t.Errorf("rate limit not set: %v %v", a, err)
	}
	if _, err := (domainIn{RLValue: ip(100), RLFrame: sp("w")}).attrs(); err == nil {
		t.Error("an unknown time frame should be rejected")
	}
	a, _ = domainIn{RLValue: ip(0)}.attrs()
	if _, ok := a["rl_value"]; ok {
		t.Error("a zero limit should be left out")
	}
}

func TestAliasModes(t *testing.T) {
	a, err := aliasIn{Goto: sp("Alice@example.org; bob@example.org")}.attrs()
	if err != nil || a["goto"] != "alice@example.org,bob@example.org" {
		t.Errorf("addresses: %v %v", a, err)
	}
	for mode, key := range map[string]string{"discard": "goto_null", "spam": "goto_spam", "ham": "goto_ham"} {
		m := mode
		a, err := aliasIn{GotoMode: &m}.attrs()
		if err != nil || a[key] != "1" {
			t.Errorf("%s: %v %v", mode, a, err)
		}
	}
	if _, err := (aliasIn{Goto: sp("not-an-address")}).attrs(); err == nil {
		t.Error("an invalid destination should be rejected")
	}
	if _, err := gotoList(strings.Repeat("a@example.org,", 101)); err == nil {
		t.Error("more than 100 destinations should be rejected")
	}
}
