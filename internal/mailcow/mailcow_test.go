package mailcow

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeMailcow answers mailcow's API the way mailcow does, quirks included.
func fakeMailcow(t *testing.T, routes map[string]string) *Client {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Client{base: srv.URL, key: "k", http: srv.Client()}
}

func TestListNormalises(t *testing.T) {
	c := fakeMailcow(t, map[string]string{
		"/api/v1/get/empty":  "{}",
		"/api/v1/get/one":    `{"domain_name":"example.org"}`,
		"/api/v1/get/many":   `[{"a":1},{"a":2}]`,
		"/api/v1/get/nulled": "null",
	})
	for path, want := range map[string]string{"get/empty": "[]", "get/one": `[{"domain_name":"example.org"}]`, "get/many": `[{"a":1},{"a":2}]`, "get/nulled": "[]"} {
		got, err := c.List(path)
		if err != nil || strings.TrimSpace(string(got)) != want {
			t.Errorf("List(%s) = %s (%v), want %s", path, got, err, want)
		}
	}
}

func TestChangeResults(t *testing.T) {
	c := fakeMailcow(t, map[string]string{
		"/api/v1/ok":      `[{"type":"success","msg":["mailbox_added","alice@example.org"]}]`,
		"/api/v1/mixed":   `[{"type":"success","msg":"domain_modified"},{"type":"danger","msg":["sender_acl_invalid","x"]}]`,
		"/api/v1/single":  `{"type":"success","msg":"dkim_added"}`,
		"/api/v1/garbage": `<html>oops</html>`,
	})
	msgs, err := c.Change("ok", nil)
	if err != nil || len(msgs) != 1 || msgs[0] != "mailbox added: alice@example.org" {
		t.Errorf("success: %v %v", msgs, err)
	}
	if _, err := c.Change("mixed", nil); err == nil || !strings.Contains(err.Error(), "sender acl invalid: x") {
		t.Errorf("a failed entry must surface as an error: %v", err)
	}
	if msgs, err := c.Change("single", nil); err != nil || msgs[0] != "dkim added" {
		t.Errorf("single-object answer: %v %v", msgs, err)
	}
	if _, err := c.Change("garbage", nil); err == nil {
		t.Error("an unreadable answer must be an error")
	}
}

func TestBadKey(t *testing.T) {
	c := fakeMailcow(t, nil)
	c.key = "wrong"
	if _, err := c.Get("get/status/version"); err == nil || !strings.Contains(err.Error(), "refused the API key") {
		t.Errorf("a rejected key should explain itself: %v", err)
	}
}

func TestAppPassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := appPassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 27 || strings.Count(pw, "-") != 3 || !strings.ContainsAny(pw, "ABCDEFGHJKLMNPQRSTUVWXYZ") ||
			!strings.ContainsAny(pw, "abcdefghjkmnpqrstuvwxyz") || !strings.ContainsAny(pw, "23456789") || strings.ContainsAny(pw, "0O1lI") {
			t.Fatalf("bad app password %q", pw)
		}
		if seen[pw] {
			t.Fatalf("repeated app password %q", pw)
		}
		seen[pw] = true
	}
}

func TestPolicyTarget(t *testing.T) {
	if s, tg, ok := policyTarget("mailbox", " Alice@Example.org "); !ok || s != "mailbox" || tg != "alice@example.org" {
		t.Errorf("mailbox target: %v %v %v", s, tg, ok)
	}
	if _, _, ok := policyTarget("domain", "not a domain"); ok {
		t.Error("an invalid domain should be refused")
	}
	if _, _, ok := policyTarget("everyone", "example.org"); ok {
		t.Error("an unknown scope should be refused")
	}
}
