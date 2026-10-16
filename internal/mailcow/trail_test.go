package mailcow

import (
	"encoding/json"
	"strconv"
	"testing"
)

type pl struct {
	t       int64
	program string
	msg     string
}

// Real mailcow Postfix lines (addresses swapped for documentation ones), oldest first.
var sample = []pl{
	// alice -> bob, local delivery
	{100, "postfix/submission/smtpd", "41C7CA37D1: client=unknown[203.0.113.73], sasl_method=PLAIN, sasl_username=alice@herd.test"},
	{100, "postfix/cleanup", "41C7CA37D1: message-id=<rota-1@herd.test>"},
	{100, "postfix/qmgr", "41C7CA37D1: from=<alice@herd.test>, size=384, nrcpt=1 (queue active)"},
	{101, "postfix/lmtp", "41C7CA37D1: to=<bob@herd.test>, relay=dovecot[172.22.1.250]:24, delay=0.95, delays=0.9/0.01/0/0.05, dsn=2.0.0, status=sent (250 2.0.0 <bob@herd.test> cPQXOPtO0mr4BAAAgs8C7g Saved)"},
	{101, "postfix/qmgr", "41C7CA37D1: removed"},
	// carol -> null-MX domain: bounced, with Postfix's notice back to carol
	{110, "postfix/submission/smtpd", "B0CFCA3817: client=unknown[203.0.113.73], sasl_method=PLAIN, sasl_username=carol@herd.test"},
	{110, "postfix/qmgr", "B0CFCA3817: from=<carol@herd.test>, size=387, nrcpt=1 (queue active)"},
	{111, "postfix/smtp", "B0CFCA3817: to=<nobody@example.net>, relay=none, delay=0.37, delays=0.35/0.03/0/0, dsn=5.1.0, status=bounced (Domain example.net does not accept mail (nullMX))"},
	{111, "postfix/cleanup", "0B9C3A381E: message-id=<20261016162117.0B9C3A381E@mail.herd.test>"},
	{111, "postfix/bounce", "B0CFCA3817: sender non-delivery notification: 0B9C3A381E"},
	{111, "postfix/qmgr", "0B9C3A381E: from=<>, size=3016, nrcpt=1 (queue active)"},
	{111, "postfix/qmgr", "B0CFCA3817: removed"},
	{112, "postfix/lmtp", "0B9C3A381E: to=<carol@herd.test>, relay=dovecot[172.22.1.250]:24, delay=0.05, delays=0.01/0/0/0.03, dsn=2.0.0, status=sent (250 2.0.0 <carol@herd.test> 4G2fA/1O0mr4BAAAgs8C7g Saved)"},
	// alice -> unreachable server: deferred twice
	{120, "postfix/submission/smtpd", "0CB07A381F: client=unknown[203.0.113.73], sasl_method=PLAIN, sasl_username=alice@herd.test"},
	{120, "postfix/qmgr", "0CB07A381F: from=<alice@herd.test>, size=381, nrcpt=1 (queue active)"},
	{150, "postfix/smtp", "0CB07A381F: to=<farmer@[192.0.2.1]>, relay=none, delay=30, delays=0.09/0/30/0, dsn=4.4.1, status=deferred (connect to 192.0.2.1[192.0.2.1]:25: Connection timed out)"},
	{450, "postfix/smtp", "0CB07A381F: to=<farmer@[192.0.2.1]>, relay=none, delay=330, delays=300/0/30/0, dsn=4.4.1, status=deferred (connect to 192.0.2.1[192.0.2.1]:25: Connection timed out)"},
	// refused at the door, and by rspamd
	{200, "postfix/smtpd", "NOQUEUE: reject: RCPT from unknown[198.51.100.9]: 550 5.1.1 <nobody@herd.test>: Recipient address rejected: User unknown in virtual mailbox table; from=<someone@example.org> to=<nobody@herd.test> proto=ESMTP helo=<mx.example.org>"},
	{201, "postfix/postscreen", "NOQUEUE: reject: RCPT from [198.51.100.10]:4321: 550 5.7.1 Service unavailable; client [198.51.100.10] blocked using zen.spamhaus.org; from=<x@example.org>, to=<bob@herd.test>, proto=ESMTP, helo=<spam.example>"},
	{210, "postfix/smtpd", "F3803A37CB: client=unknown[198.51.100.9]"},
	{211, "postfix/cleanup", "F3803A37CB: milter-reject: END-OF-MESSAGE from unknown[198.51.100.9]: 5.7.1 Gtube pattern; from=<prize@example.org> to=<carol@herd.test> proto=ESMTP helo=<mx.example.org>"},
	{211, "postfix/cleanup", "F3803A37CB: removed (canceled)"},
	// inbound from outside, delivered to two mailboxes
	{300, "postfix/smtpd", "AAAA11112222: client=mx.example.org[198.51.100.20]"},
	{300, "postfix/qmgr", "AAAA11112222: from=<news@example.org>, size=5000, nrcpt=2 (queue active)"},
	{301, "postfix/lmtp", "AAAA11112222: to=<bob@herd.test>, relay=dovecot[172.22.1.250]:24, delay=0.2, delays=0.1/0/0/0.1, dsn=2.0.0, status=sent (250 2.0.0 Saved)"},
	{301, "postfix/lmtp", "AAAA11112222: to=<carol@herd.test>, relay=dovecot[172.22.1.250]:24, delay=0.2, delays=0.1/0/0/0.1, dsn=2.0.0, status=sent (250 2.0.0 Saved)"},
	// noise that must be ignored, and a failed sign-in
	{400, "postfix/postscreen", "CONNECT from [198.51.100.9]:57486 to [172.22.1.253]:25"},
	{400, "postfix/postscreen", "warning: read TCP map reply from 127.0.0.1:10027: malformed reply"},
	{401, "postfix/submission/smtpd", "warning: unknown[203.0.113.50]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=bob@herd.test"},
}

func run(t *testing.T) (*trail, map[string]int) {
	t.Helper()
	tr := newTrail()
	got := map[string]int{}
	for _, l := range sample {
		for _, x := range tr.postfix(l.t, l.program, l.msg) {
			got[x.kind]++
		}
	}
	return tr, got
}

func TestTrailJourneys(t *testing.T) {
	tr, _ := run(t)
	cases := []struct{ id, status, dir string }{
		{"41C7CA37D1", "delivered", "internal"},
		{"B0CFCA3817", "bounced", "out"},
		{"0CB07A381F", "deferred", "out"},
		{"F3803A37CB", "refused", "in"},
		{"AAAA11112222", "delivered", "in"},
		{"0B9C3A381E", "delivered", "system"},
	}
	for _, c := range cases {
		m := tr.msgs[c.id]
		if m == nil {
			t.Fatalf("%s missing", c.id)
		}
		if m.Status() != c.status || m.Direction() != c.dir {
			t.Errorf("%s: status %s/%s, want %s/%s", c.id, m.Status(), m.Direction(), c.status, c.dir)
		}
	}
	m := tr.msgs["41C7CA37D1"]
	if m.User != "alice@herd.test" || m.Via != "submission" || m.MessageID != "rota-1@herd.test" || m.Size != 384 || !m.Done || !m.Hops[0].Local {
		t.Errorf("alice's message details wrong: %+v", m)
	}
	if d := tr.msgs["0CB07A381F"].Hops[0]; d.Attempts != 2 || d.First != 150 || d.Time != 450 || d.DSN != "4.4.1" {
		t.Errorf("deferred hop should count both tries: %+v", d)
	}
	if b := tr.msgs["B0CFCA3817"]; b.Notice != "0B9C3A381E" || tr.msgs["0B9C3A381E"].NoticeFor != "B0CFCA3817" {
		t.Error("the bounce should link to Postfix's notice back to the sender")
	}
	if g := tr.msgs["F3803A37CB"]; g.Refused.Stage != "content" || g.Refused.Reason != "Gtube pattern" || !g.Spam() {
		t.Errorf("rspamd refusal wrong: %+v", g.Refused)
	}
	doors := 0
	for _, m := range tr.msgs {
		if m.Refused != nil && m.Refused.Stage == "door" {
			doors++
			if m.Status() != "refused" || m.Direction() != "in" || len(m.To) != 1 {
				t.Errorf("door refusal wrong: %+v", m)
			}
		}
	}
	if doors != 2 {
		t.Errorf("want 2 door refusals (recipient check and postscreen), got %d", doors)
	}
}

func TestTrailTallies(t *testing.T) {
	_, got := run(t)
	want := map[string]int{"sent": 3, "delivered_local": 4, "received": 1, "bounced": 1, "deferred": 1, "refused": 2, "spam": 1, "authfail": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
	if got["delivered_remote"] != 0 {
		t.Errorf("nothing left the server: %v", got)
	}
}

func TestRspamdJoin(t *testing.T) {
	tr, _ := run(t)
	// no Message-ID (rspamd says "undef"): matched by time, address and recipients
	if !tr.attach(rspamdEntry{Time: 211, MessageID: "undef", Rcpt: []string{"carol@herd.test"}, IP: "198.51.100.9", Subject: "You won", Action: "reject", Score: 1000, Required: 15,
		Symbols: map[string]rspamdS{"GTUBE": {Score: 1000}, "ZERO": {}}}) {
		t.Fatal("the GTUBE verdict should find its message")
	}
	g := tr.msgs["F3803A37CB"]
	if g.Subject != "You won" || g.Verdict.Score != 1000 || len(g.Verdict.Symbols) != 1 {
		t.Errorf("verdict not attached properly: %+v %+v", g.Subject, g.Verdict)
	}
	// by Message-ID, even though the time is further off
	if !tr.attach(rspamdEntry{Time: 160, MessageID: "rota-1@herd.test", Rcpt: []string{"bob@herd.test"}, Subject: "Milking rota", Action: "no action"}) ||
		tr.msgs["41C7CA37D1"].Subject != "Milking rota" {
		t.Error("Message-ID match failed")
	}
	// a door refusal at the same moment, to the same mailbox, never reached rspamd
	tr.postfix(212, "postfix/smtpd", "NOQUEUE: reject: RCPT from unknown[198.51.100.9]: 550 5.7.27 <x@example.org>: Sender address rejected: Domain example.org does not accept mail (nullMX); from=<x@example.org> to=<carol@herd.test> proto=ESMTP helo=<mx.example.org>")
	tr.postfix(213, "postfix/smtpd", "B1B1B1B1B1: client=unknown[198.51.100.9]")
	tr.postfix(214, "postfix/cleanup", "B1B1B1B1B1: milter-reject: END-OF-MESSAGE from unknown[198.51.100.9]: 5.7.1 Spam; from=<cow.sec.news+farm@gmail.com> to=<carol@herd.test> proto=ESMTP helo=<mx.example.org>")
	if !tr.attach(rspamdEntry{Time: 214, MessageID: "undef", Sender: "cowsecnews@gmail.com", Rcpt: []string{"carol@herd.test"}, IP: "198.51.100.9", Subject: "Spring seed catalogue", Action: "reject"}) {
		t.Fatal("rspamd's dot-less Gmail sender should still match")
	}
	if tr.msgs["B1B1B1B1B1"].Subject != "Spring seed catalogue" {
		t.Error("the verdict went to the wrong message")
	}
	for _, m := range tr.msgs {
		if m.Refused != nil && m.Refused.Stage == "door" && m.Verdict != nil {
			t.Errorf("a door refusal took a verdict: %+v", m)
		}
	}
	if tr.attach(rspamdEntry{Time: 5000, MessageID: "undef", Rcpt: []string{"nobody@elsewhere.example"}}) {
		t.Error("a verdict with no matching message must stay unattached")
	}
}

func TestInsightReadsEachLineOnce(t *testing.T) {
	in := newInsight(nil, "")
	toLines := func(ps []pl) []logLine {
		out := []logLine{}
		for i := len(ps) - 1; i >= 0; i-- { // mailcow answers newest first
			out = append(out, logLine{Time: json.Number(strconv.FormatInt(ps[i].t, 10)), Program: ps[i].program, Message: ps[i].msg})
		}
		return out
	}
	// two overlapping reads of the log, the second one with new lines on the end
	in.ingestPostfix(in.fresh("postfix", toLines(sample[:14]), 5000))
	in.ingestPostfix(in.fresh("postfix", toLines(sample), 5000))
	in.ingestPostfix(in.fresh("postfix", toLines(sample), 5000))
	total := counts{}
	for _, h := range in.st.Hours {
		for k, v := range h.Counts {
			total[k] += v
		}
	}
	if total["sent"] != 3 || total["delivered_local"] != 4 || total["refused"] != 2 {
		t.Errorf("lines were counted more than once: %v", total)
	}
	if len(in.st.Gaps) != 0 {
		t.Errorf("no lines were lost: %v", in.st.Gaps)
	}
	if box := in.st.Hours[0].Boxes["alice@herd.test"]; box["sent"] != 2 {
		t.Errorf("alice sent 2: %v", box)
	}
}

func TestInsightHealthBuckets(t *testing.T) {
	in := newInsight(nil, "")
	in.add(tally{t: 3600*10 + 5, kind: "received"})
	in.add(tally{t: 3600*11 + 5, kind: "received"})
	in.add(tally{t: 3600*11 + 9, kind: "authfail", user: "bob@herd.test"})
	in.add(tally{t: 3600*2 + 1, kind: "received"}) // the period before
	h := in.health(3600*8, 3600*12, 3600, 0)
	s := h["series"].([]healthPoint)
	if len(s) != 4 || s[2].C["received"] != 1 || s[3].C["received"] != 1 || s[3].C["authfail"] != 1 {
		t.Errorf("hourly buckets wrong: %+v", s)
	}
	if h["total"].(counts)["received"] != 2 || h["previous"].(counts)["received"] != 0 {
		t.Errorf("totals wrong: %v %v", h["total"], h["previous"])
	}
	if rows := h["mailboxes"].([]boxRow); len(rows) != 1 || rows[0].User != "bob@herd.test" {
		t.Errorf("mailbox rows wrong: %+v", rows)
	}
	// daily buckets start at the viewer's midnight: one hour east of UTC
	d := in.health(0, 86400*2, 86400, 3600)
	if d["series"].([]healthPoint)[0].T != -3600 {
		t.Errorf("day buckets should follow the viewer's time zone: %+v", d["series"])
	}
}

func TestInsightCountsSignInFailuresOnce(t *testing.T) {
	in := newInsight(nil, "")
	in.ingestDovecot([]logLine{
		{Time: "401", Message: "auth-worker(496): auth-worker<17>: lua(bob@herd.test,203.0.113.50): Password mismatch"},
		{Time: "402", Message: "auth-worker(629): auth-worker<2>: lua(bob@herd.test,198.51.100.4,<ULuA4vddrODAqApJ>): Password mismatch"},
		{Time: "404", Message: "imap-login: Disconnected: Aborted login by logging out (auth failed, 1 attempts in 2 secs): user=<bob@herd.test>, method=PLAIN, rip=198.51.100.4"},
	})
	in.ingestPostfix([]logLine{{Time: "401", Program: "postfix/submission/smtpd", Message: "warning: unknown[203.0.113.50]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=bob@herd.test"}})
	if got := in.st.Hours[0].Counts["authfail"]; got != 2 {
		t.Errorf("two wrong passwords (SMTP and IMAP), counted %d times", got)
	}
	if got := in.st.Hours[0].Boxes["bob@herd.test"]["authfail"]; got != 2 {
		t.Errorf("bob's failures: %d", got)
	}
}
