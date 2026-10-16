package crowdsec

import "testing"

func TestRelevantHubItem(t *testing.T) {
	for name, want := range map[string]bool{
		"crowdsecurity/postfix":                 true,
		"crowdsecurity/dovecot":                 true,
		"crowdsecurity/sshd":                    true,
		"crowdsecurity/nginx":                   true,
		"crowdsecurity/appsec-virtual-patching": true,
		"crowdsecurity/linux":                   true,
		"crowdsecurity/wordpress":               false,
		"crowdsecurity/apache2":                 false,
		"crowdsecurity/exchange":                false, // a different mail server
		"crowdsecurity/home-assistant":          false,
		"crowdsecurity/traefik":                 false,
		"crowdsecurity/mysql":                   false,
	} {
		if got := RelevantHubItem(ItemInfo{Name: name}); got != want {
			t.Errorf("RelevantHubItem(%q) = %v, want %v", name, got, want)
		}
	}
}
