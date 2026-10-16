package mailcow

import (
	"encoding/json"
	"testing"
)

func lines(msgs ...string) []logLine {
	out := make([]logLine, len(msgs))
	for i, m := range msgs {
		out[i] = logLine{Time: json.Number([]string{"1760000000", "1760000600", "1760001200", "1760003600", "1760007200"}[i%5]), Message: m}
	}
	return out
}

func TestPostfixFailures(t *testing.T) {
	ls := lines(
		"warning: unknown[203.0.113.7]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=alice@example.org",
		"warning: unknown[203.0.113.8]: SASL PLAIN authentication failed: UGFzc3dvcmQ6, sasl_username=alice",
		"warning: unknown[198.51.100.1]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=bob@example.org",
		"connect from unknown[203.0.113.7]",
	)
	got := postfixFailures(ls, mailboxMatcher("Alice@Example.org"))
	if len(got) != 2 {
		t.Fatalf("want 2 failures for alice (full address and local part), got %+v", got)
	}
	if got[0].IP != "203.0.113.7" || got[0].Source != "smtp" || got[0].Time != 1760000000 || got[1].IP != "203.0.113.8" {
		t.Errorf("wrong details: %+v", got)
	}
}

func TestAuthFailuresCountEachAttemptOnce(t *testing.T) {
	// one wrong SMTP password and one wrong IMAP password, as mailcow logs them
	dovecot := lines(
		"auth-worker(496): conn unix:auth-worker (pid=133,uid=401): auth-worker<17>: lua(alice@example.org,203.0.113.9): Password mismatch (SHA1 of given password: 6809ff)",
		"auth-worker(629): conn unix:auth-worker (pid=133,uid=401): auth-worker<2>: lua(alice@example.org,198.51.100.4,<ULuA4vddrODAqApJ>): Password mismatch (SHA1 of given password: 6809ff)",
		"imap-login: Disconnected: Aborted login by logging out (auth failed, 1 attempts in 2 secs): user=<alice@example.org>, method=PLAIN, rip=198.51.100.4, lip=172.22.1.250, TLS",
		"auth-worker(496): conn unix:auth-worker (pid=133,uid=401): auth-worker<20>: sql(watchdog@invalid,172.22.1.12): unknown user ",
		"auth-worker(629): auth-worker<4>: lua(bob@example.org,198.51.100.5,<Kz+a4vddvODAqApJ>): Password mismatch",
	)
	postfix := lines("warning: unknown[203.0.113.9]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=alice@example.org")
	got := authFailures(dovecot, postfix, mailboxMatcher("alice@example.org"))
	if len(got) != 2 {
		t.Fatalf("want one entry per attempt (2), got %+v", got)
	}
	if got[0].Source != "smtp" || got[0].IP != "203.0.113.9" || got[1].Source != "imap" || got[1].IP != "198.51.100.4" {
		t.Errorf("wrong sources: %+v", got)
	}
}

func TestAuthFailuresFallBack(t *testing.T) {
	// a Dovecot that doesn't log its password checks: use Postfix's and the login process's lines
	dovecot := lines("imap-login: Disconnected: Connection closed (auth failed, 3 attempts in 12 secs): user=<alice@example.org>, method=PLAIN, rip=203.0.113.9, lip=172.22.1.250, TLS",
		"pop3-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<alice>, method=PLAIN, rip=203.0.113.10")
	postfix := lines("warning: unknown[203.0.113.8]: SASL PLAIN authentication failed: UGFzc3dvcmQ6, sasl_username=alice")
	got := authFailures(dovecot, postfix, mailboxMatcher("alice@example.org"))
	if len(got) != 3 || got[0].Source != "smtp" || got[1].Source != "imap" || got[2].Source != "pop3" {
		t.Errorf("fallback wrong: %+v", got)
	}
}

func TestOutboundSenders(t *testing.T) {
	msgs := []string{}
	for i := 0; i < 6; i++ {
		msgs = append(msgs, "4Xyz: client=unknown[203.0.113."+string(rune('1'+i))+"], sasl_method=PLAIN, sasl_username=spammer@example.org")
	}
	msgs = append(msgs,
		"4Abc: client=unknown[192.0.2.20], sasl_method=PLAIN, sasl_username=alice@example.org",
		"warning: unknown[203.0.113.50]: SASL LOGIN authentication failed: x, sasl_username=alice@example.org", // a failure isn't a sent message
		"4Def: client=mx.example.net[198.51.100.9]",                                                            // unauthenticated relay: not a sender
	)
	got, lo, hi := outboundSenders(lines(msgs...))
	if len(got) != 2 {
		t.Fatalf("want 2 senders, got %+v", got)
	}
	if got[0].User != "spammer@example.org" || got[0].Count != 6 || got[0].IPs != 6 || !got[0].Unusual {
		t.Errorf("busy multi-address sender should be first and flagged: %+v", got[0])
	}
	if got[1].User != "alice@example.org" || got[1].Count != 1 || got[1].Unusual {
		t.Errorf("normal sender wrong: %+v", got[1])
	}
	if lo != 1760000000 || hi != 1760007200 {
		t.Errorf("window wrong: %d..%d", lo, hi)
	}
}

func TestPublicIP(t *testing.T) {
	for ip, want := range map[string]bool{"203.0.113.9": true, "8.8.8.8": true, "192.168.1.5": false, "10.0.0.1": false, "127.0.0.1": false, "::1": false, "fe80::1": false, "not-an-ip": false} {
		if got := publicIP(ip); got != want {
			t.Errorf("publicIP(%q) = %v, want %v", ip, got, want)
		}
	}
}
