package mailcow

// Mail trail: follows each message through Postfix's log by queue ID (arrived, queued, delivered,
// deferred, bounced or refused) and joins rspamd's verdict, which is also where the subject comes
// from. Everything here is pure: the collector in insight.go feeds it log lines in order.

import (
	"fmt"
	"hash/fnv"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Hop is one recipient's outcome. Deferred deliveries are retried, so Attempts counts them.
type Hop struct {
	To       string  `json:"to"`
	OrigTo   string  `json:"orig_to,omitempty"`
	Status   string  `json:"status"` // sent | deferred | bounced | expired
	Relay    string  `json:"relay,omitempty"`
	Local    bool    `json:"local"` // delivered into a mailbox on this server
	DSN      string  `json:"dsn,omitempty"`
	Reason   string  `json:"reason,omitempty"`
	Delay    float64 `json:"delay,omitempty"`
	First    int64   `json:"first"`
	Time     int64   `json:"time"`
	Attempts int     `json:"attempts"`
}

type Symbol struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// Verdict is rspamd's opinion of a message.
type Verdict struct {
	Action   string   `json:"action"`
	Score    float64  `json:"score"`
	Required float64  `json:"required"`
	Symbols  []Symbol `json:"symbols,omitempty"`
	Time     int64    `json:"time"`
}

// Refusal is mail turned away before delivery: at the door (recipient or sender checks, blocklists)
// or after rspamd read it.
type Refusal struct {
	Stage  string `json:"stage"` // door | content
	Code   string `json:"code"`
	Reason string `json:"reason"`
	Temp   bool   `json:"temporary"` // 4xx: the sender should try again (greylisting, rate limits)
	Time   int64  `json:"time"`
}

type Message struct {
	ID        string   `json:"id"` // Postfix queue ID, or "nq…" for mail refused before it got one
	Time      int64    `json:"time"`
	Updated   int64    `json:"updated"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Subject   string   `json:"subject,omitempty"`
	MessageID string   `json:"message_id,omitempty"`
	Size      int64    `json:"size,omitempty"`
	Client    string   `json:"client,omitempty"`
	IP        string   `json:"ip,omitempty"`
	User      string   `json:"user,omitempty"` // signed-in sender (SMTP AUTH)
	Via       string   `json:"via,omitempty"`  // smtp | submission | local
	Helo      string   `json:"helo,omitempty"`
	Refused   *Refusal `json:"refused,omitempty"`
	Verdict   *Verdict `json:"verdict,omitempty"`
	Hops      []*Hop   `json:"hops"`
	Notice    string   `json:"notice,omitempty"` // the non-delivery report this message caused
	NoticeFor string   `json:"notice_for,omitempty"`
	Done      bool     `json:"done"`              // left the queue
	Counted   bool     `json:"counted,omitempty"` // already counted as received mail
}

// Status sums up where a message got to.
func (m *Message) Status() string {
	if m.Refused != nil {
		if m.Refused.Temp {
			return "greylisted"
		}
		return "refused"
	}
	var sent, deferred, bounced int
	for _, h := range m.Hops {
		switch h.Status {
		case "sent":
			sent++
		case "deferred":
			deferred++
		default:
			bounced++
		}
	}
	switch {
	case len(m.Hops) == 0:
		return "queued"
	case deferred > 0 && sent == 0 && bounced == 0:
		return "deferred"
	case bounced > 0 && sent == 0 && deferred == 0:
		return "bounced"
	case sent == len(m.Hops):
		return "delivered"
	}
	return "partial"
}

// Direction: "in" from outside, "out" sent by a signed-in user to someone elsewhere, "internal"
// when everything stayed on this server, "system" for Postfix's own notices.
func (m *Message) Direction() string {
	if m.NoticeFor != "" || (m.From == "" && m.User == "" && m.Client == "") {
		return "system"
	}
	if m.User == "" && m.Via != "local" {
		return "in"
	}
	for _, h := range m.Hops {
		if !h.Local {
			return "out"
		}
	}
	if len(m.Hops) == 0 && m.Refused == nil {
		return "out"
	}
	return "internal"
}

// Spam is true when rspamd refused the message or sent it to Junk.
func (m *Message) Spam() bool {
	if m.Refused != nil && m.Refused.Stage == "content" && !m.Refused.Temp {
		return true
	}
	return m.Verdict != nil && (m.Verdict.Action == "add header" || m.Verdict.Action == "rewrite subject")
}

// tally is one countable event for the dashboard.
type tally struct {
	t      int64
	kind   string // received sent delivered_local delivered_remote deferred bounced refused spam junk greylisted authfail
	user   string // the mailbox it belongs to, if any
	reason string
}

var (
	reQIDLine   = regexp.MustCompile(`^([0-9A-Za-z]{8,20}): (.*)$`)
	reClient    = regexp.MustCompile(`^client=([^\[\s,]*)\[([^\]]+)\]`)
	rePickup    = regexp.MustCompile(`^uid=\d+ from=<([^>]*)>`)
	reMsgID     = regexp.MustCompile(`^message-id=<?([^>]*)>?`)
	reQueued    = regexp.MustCompile(`^from=<([^>]*)>, size=(\d+), nrcpt=\d+`)
	reExpired   = regexp.MustCompile(`^from=<([^>]*)>, status=expired`)
	reDelivery  = regexp.MustCompile(`^to=<([^>]*)>,(?: orig_to=<([^>]*)>,)? relay=([^,]+),.*?delay=([\d.]+),.*?dsn=([\d.]+), status=(\w+) ?\(?(.*?)\)?$`)
	reMilterRej = regexp.MustCompile(`^milter-reject: \S+ from ([^\[\s]*)\[([^\]]+)\]: (\d\.\d+\.\d+) (.*?); from=<([^>]*)>,? to=<([^>]*)>(?:,? proto=\S+)?(?:,? helo=<([^>]*)>)?`)
	reNDR       = regexp.MustCompile(`^sender non-delivery notification: (\w+)`)
	reNoQueue   = regexp.MustCompile(`^NOQUEUE: (?:reject|milter-reject): \S+ from ([^\[\s]*)\[([^\]]+)\](?::\d+)?: (\d{3})(?: (\d\.\d+\.\d+))? (.*?); from=<([^>]*)>,? to=<([^>]*)>(?:,? proto=\S+)?(?:,? helo=<([^>]*)>)?`)
	reAddrHead  = regexp.MustCompile(`^<[^>]*>: `)
)

type trail struct {
	msgs map[string]*Message
}

func newTrail() *trail { return &trail{msgs: map[string]*Message{}} }

func (t *trail) get(id string, at int64) *Message {
	m := t.msgs[id]
	if m == nil {
		m = &Message{ID: id, Time: at, Hops: []*Hop{}, To: []string{}}
		t.msgs[id] = m
	}
	if at > m.Updated {
		m.Updated = at
	}
	return m
}

func addRcpt(m *Message, to string) {
	to = strings.ToLower(to)
	for _, x := range m.To {
		if x == to {
			return
		}
	}
	m.To = append(m.To, to)
}

// postfix reads one Postfix log line and returns what it adds to the dashboard.
func (t *trail) postfix(at int64, program, msg string) []tally {
	if strings.Contains(msg, "authentication failed") && strings.Contains(msg, "SASL") {
		u := ""
		if s := reSASLUser.FindStringSubmatch(msg); s != nil {
			u = strings.ToLower(s[1])
		}
		return []tally{{t: at, kind: "authfail", user: u}}
	}
	if m := reNoQueue.FindStringSubmatch(msg); m != nil {
		temp := m[3][0] == '4'
		reason := reAddrHead.ReplaceAllString(m[5], "")
		h := fnv.New32a()
		fmt.Fprintf(h, "%d|%s|%s|%s", at, m[6], m[7], reason)
		id := fmt.Sprintf("nq%08x", h.Sum32())
		x := t.get(id, at)
		x.Client, x.IP, x.From, x.Helo, x.Via = m[1], m[2], strings.ToLower(m[6]), m[8], "smtp"
		addRcpt(x, m[7])
		x.Refused = &Refusal{Stage: "door", Code: strings.TrimSpace(m[3] + " " + m[4]), Reason: reason, Temp: temp, Time: at}
		x.Done = true
		kind := "refused"
		if temp {
			kind = "greylisted"
		}
		return []tally{{t: at, kind: kind, reason: refusalKind(reason)}}
	}
	q := reQIDLine.FindStringSubmatch(msg)
	if q == nil || !strings.ContainsAny(q[1], "0123456789") {
		return nil
	}
	id, rest := q[1], q[2]
	m := t.get(id, at)
	switch {
	case reClient.MatchString(rest):
		c := reClient.FindStringSubmatch(rest)
		m.Client, m.IP, m.Via = c[1], c[2], "smtp"
		if strings.Contains(program, "submission") || strings.Contains(program, "smtps") {
			m.Via = "submission"
		}
		if s := reSASLUser.FindStringSubmatch(rest); s != nil {
			m.User = strings.ToLower(s[1])
			return []tally{{t: at, kind: "sent", user: m.User}}
		}
	case rePickup.MatchString(rest):
		m.Via = "local"
		m.From = strings.ToLower(rePickup.FindStringSubmatch(rest)[1])
	case reMsgID.MatchString(rest):
		m.MessageID = strings.Trim(reMsgID.FindStringSubmatch(rest)[1], "<> ")
	case reQueued.MatchString(rest):
		s := reQueued.FindStringSubmatch(rest)
		m.From = strings.ToLower(s[1])
		m.Size, _ = strconv.ParseInt(s[2], 10, 64)
	case reExpired.MatchString(rest):
		for _, h := range m.Hops {
			if h.Status == "deferred" {
				h.Status, h.Time = "expired", at
			}
		}
	case rest == "removed" || strings.HasPrefix(rest, "removed "):
		m.Done = true
	case reNDR.MatchString(rest):
		n := reNDR.FindStringSubmatch(rest)[1]
		m.Notice = n
		t.get(n, at).NoticeFor = id
	case reMilterRej.MatchString(rest):
		s := reMilterRej.FindStringSubmatch(rest)
		if m.Client == "" {
			m.Client, m.IP = s[1], s[2]
		}
		m.From, m.Helo = strings.ToLower(s[5]), s[7]
		addRcpt(m, s[6])
		temp := s[3][0] == '4'
		m.Refused = &Refusal{Stage: "content", Code: s[3], Reason: s[4], Temp: temp, Time: at}
		m.Done = true
		if temp {
			return []tally{{t: at, kind: "greylisted", reason: "Greylisted (try again later)"}}
		}
		return []tally{{t: at, kind: "spam", reason: "Spam: " + s[4]}}
	case reDelivery.MatchString(rest):
		return t.delivery(m, at, reDelivery.FindStringSubmatch(rest))
	}
	return nil
}

func (t *trail) delivery(m *Message, at int64, s []string) []tally {
	to, orig := strings.ToLower(s[1]), strings.ToLower(s[2])
	addRcpt(m, to)
	var h *Hop
	for _, x := range m.Hops {
		if x.To == to && x.OrigTo == orig {
			h = x
		}
	}
	if h == nil {
		h = &Hop{To: to, OrigTo: orig, First: at}
		m.Hops = append(m.Hops, h)
	}
	prev := h.Status
	h.Relay, h.DSN, h.Status, h.Reason, h.Time = s[3], s[5], s[6], s[7], at
	h.Delay, _ = strconv.ParseFloat(s[4], 64)
	h.Local = strings.HasPrefix(h.Relay, "dovecot") || strings.HasPrefix(h.Relay, "local") || strings.HasPrefix(h.Relay, "virtual")
	h.Attempts++
	if prev == h.Status && h.Status != "deferred" {
		return nil // the same outcome logged twice
	}
	switch h.Status {
	case "sent":
		out := []tally{}
		if h.Local {
			out = append(out, tally{t: at, kind: "delivered_local", user: to})
			if m.User == "" && m.NoticeFor == "" && m.Via != "local" && !m.Counted {
				m.Counted = true
				out = append(out, tally{t: at, kind: "received"})
			}
		} else {
			out = append(out, tally{t: at, kind: "delivered_remote", user: m.User})
		}
		return out
	case "deferred":
		if prev == "deferred" {
			return nil // a retry; count each recipient's delay once
		}
		return []tally{{t: at, kind: "deferred", user: m.User, reason: "Delayed: " + shortReason(h.Reason)}}
	case "bounced", "expired":
		return []tally{{t: at, kind: "bounced", user: m.User, reason: "Bounced: " + shortReason(h.Reason)}}
	}
	return nil
}

// rspamdEntry is the part of an rspamd history row the trail uses.
type rspamdEntry struct {
	Time      int64              `json:"unix_time"`
	MessageID string             `json:"message-id"`
	Sender    string             `json:"sender_smtp"`
	Rcpt      []string           `json:"rcpt_smtp"`
	Subject   string             `json:"subject"`
	Action    string             `json:"action"`
	Score     float64            `json:"score"`
	Required  float64            `json:"required_score"`
	IP        string             `json:"ip"`
	User      string             `json:"user"`
	Symbols   map[string]rspamdS `json:"symbols,omitempty"`
}

type rspamdS struct {
	Score float64 `json:"score"`
}

func (e rspamdEntry) verdict() *Verdict {
	v := &Verdict{Action: e.Action, Score: e.Score, Required: e.Required, Time: e.Time}
	for n, s := range e.Symbols {
		if s.Score != 0 {
			v.Symbols = append(v.Symbols, Symbol{Name: n, Score: s.Score})
		}
	}
	sort.Slice(v.Symbols, func(i, j int) bool {
		if math.Abs(v.Symbols[i].Score) != math.Abs(v.Symbols[j].Score) {
			return math.Abs(v.Symbols[i].Score) > math.Abs(v.Symbols[j].Score)
		}
		return v.Symbols[i].Name < v.Symbols[j].Name
	})
	if len(v.Symbols) > 12 {
		v.Symbols = v.Symbols[:12]
	}
	return v
}

// attach finds the message an rspamd row belongs to: by Message-ID when the message has one,
// otherwise by time, client address and recipients (rspamd doesn't log Postfix's queue ID).
func (t *trail) attach(e rspamdEntry) bool {
	mid := strings.Trim(e.MessageID, "<> ")
	rcpt := map[string]bool{}
	for _, r := range e.Rcpt {
		rcpt[strings.ToLower(r)] = true
	}
	var best *Message
	bestGap := int64(1 << 62)
	for _, m := range t.msgs {
		if m.Verdict != nil || m.NoticeFor != "" || (m.Refused != nil && m.Refused.Stage == "door") {
			continue // refused at the door: rspamd never saw it
		}
		if e.Sender != "" && m.From != "" && sameSender(e.Sender) != sameSender(m.From) {
			continue
		}
		gap := e.Time - m.Time
		if gap < 0 {
			gap = -gap
		}
		if mid != "" && mid != "undef" && m.MessageID != "" {
			if m.MessageID != mid || gap > 3600 {
				continue
			}
		} else {
			if gap > 20 || (e.IP != "" && m.IP != "" && e.IP != m.IP) {
				continue
			}
			overlap := false
			for _, to := range m.To {
				if rcpt[to] {
					overlap = true
				}
			}
			if !overlap && len(m.To) > 0 {
				continue
			}
		}
		if gap < bestGap {
			best, bestGap = m, gap
		}
	}
	if best == nil {
		return false
	}
	best.Verdict = e.verdict()
	if best.Subject == "" {
		best.Subject = e.Subject
	}
	if best.MessageID == "" && mid != "undef" {
		best.MessageID = mid
	}
	return true
}

// sameSender normalises an address the way rspamd does before logging it: lower case, without a
// +tag, and without dots in the local part (rspamd logs Gmail addresses with the dots removed).
func sameSender(a string) string {
	a = strings.ToLower(strings.Trim(a, "<> "))
	local, dom, ok := strings.Cut(a, "@")
	if !ok {
		return a
	}
	if i := strings.IndexByte(local, '+'); i > 0 {
		local = local[:i]
	}
	return strings.ReplaceAll(local, ".", "") + "@" + dom
}

// refusalKind groups door refusals into a few plain reasons for the dashboard.
func refusalKind(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "user unknown") || strings.Contains(r, "recipient address rejected"):
		return "Unknown recipient"
	case strings.Contains(r, "blocked using") || strings.Contains(r, "listed"):
		return "Sender on a blocklist"
	case strings.Contains(r, "does not accept mail") || strings.Contains(r, "nullmx"):
		return "Sender domain doesn't accept mail"
	case strings.Contains(r, "sender address rejected"):
		return "Sender address refused"
	case strings.Contains(r, "helo"):
		return "Bad HELO name"
	case strings.Contains(r, "relay access denied"):
		return "Relaying refused"
	case strings.Contains(r, "rate") || strings.Contains(r, "too many"):
		return "Rate limited"
	case strings.Contains(r, "greylist") || strings.Contains(r, "try again"):
		return "Greylisted (try again later)"
	}
	return "Other: " + shortReason(reason)
}

func shortReason(r string) string {
	r = strings.TrimSpace(r)
	if i := strings.Index(r, " (in reply to"); i > 0 {
		r = r[:i]
	}
	if len(r) > 80 {
		r = r[:77] + "…"
	}
	return r
}
