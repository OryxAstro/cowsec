package crowdsec

import (
	"errors"
	"testing"
)

func TestHostnameRe(t *testing.T) {
	for _, ok := range []string{"home.example-dyndns.org", "a.b.example.de", "x1.duckdns.org"} {
		if !hostnameRe.MatchString(ok) {
			t.Errorf("%q should be accepted", ok)
		}
	}
	for _, bad := range []string{"", "localhost", "1.2.3.4", "a b.example.org", "-x.example.org", "home.example.org extra", "home.example.org\n"} {
		if hostnameRe.MatchString(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestHelperMessage(t *testing.T) {
	err := errors.New("dyndns-add failed: exit status 4 (doesn't resolve (Name or service not known))")
	if got := helperMessage(err); got != "doesn't resolve (Name or service not known)" {
		t.Errorf("got %q", got)
	}
}
