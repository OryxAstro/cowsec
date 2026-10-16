package mailcow

// Mail insight: a collector that reads mailcow's Postfix, Dovecot and rspamd logs every minute,
// keeps hourly counts for 31 days and message journeys (the mail trail) for 7 days, and serves the
// Herd Health dashboard and the trail search. mailcow only keeps the last few thousand log lines,
// so this is what gives CowSec a history at all. Kept in the state folder (root only).

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	insightEvery    = time.Minute
	insightHours    = 31 * 24
	trailDays       = 7
	trailMax        = 20000
	pendingVerdicts = 10 * 60 // seconds an unmatched rspamd row waits for its message
)

// counts per hour, by event kind
type counts map[string]int

type hourData struct {
	Counts  counts            `json:"counts"`
	Boxes   map[string]counts `json:"boxes,omitempty"`   // mailbox -> its counts
	Reasons map[string]int    `json:"reasons,omitempty"` // why mail was refused, delayed or bounced
}

// mark remembers how far a log has been read: lines are only counted once.
type mark struct {
	Last int64    `json:"last"`
	Seen []uint32 `json:"seen,omitempty"` // fingerprints of the lines at the Last second
}

type insightState struct {
	Version int                 `json:"version"`
	Since   int64               `json:"since"`
	Marks   map[string]*mark    `json:"marks"`
	Hours   map[int64]*hourData `json:"hours"`
	Gaps    []int64             `json:"gaps,omitempty"` // times a log rolled over before it was read
	Msgs    map[string]*Message `json:"messages"`
	Pending []rspamdEntry       `json:"pending,omitempty"`
	// DovecotChecks: this Dovecot logs every password check, so those are what failed sign-ins count
	// (Postfix's own SASL lines would count SMTP failures twice).
	DovecotChecks bool `json:"dovecot_checks,omitempty"`
}

type Insight struct {
	c        *Client
	path     string
	mu       sync.Mutex
	st       *insightState
	tr       *trail
	lastPoll time.Time
	pollErr  string
	kick     chan struct{}
	dirty    bool
}

func newInsight(c *Client, stateDir string) *Insight {
	in := &Insight{c: c, kick: make(chan struct{}, 1)}
	if stateDir != "" {
		in.path = filepath.Join(stateDir, "mail-insight.json")
	}
	in.st = &insightState{Version: 1, Marks: map[string]*mark{}, Hours: map[int64]*hourData{}, Msgs: map[string]*Message{}}
	if in.path != "" {
		if b, err := os.ReadFile(in.path); err == nil {
			var st insightState
			if json.Unmarshal(b, &st) == nil && st.Version == 1 {
				if st.Marks == nil {
					st.Marks = map[string]*mark{}
				}
				if st.Hours == nil {
					st.Hours = map[int64]*hourData{}
				}
				if st.Msgs == nil {
					st.Msgs = map[string]*Message{}
				}
				in.st = &st
			}
		}
	}
	in.tr = &trail{msgs: in.st.Msgs}
	return in
}

func (in *Insight) run() {
	for {
		in.poll()
		select {
		case <-time.After(insightEvery):
		case <-in.kick:
		}
	}
}

// fresh returns the lines newer than the mark, oldest first, and moves the mark on.
// mailcow's API answers newest first. A batch that starts after the mark means lines were lost.
func (in *Insight) fresh(source string, lines []logLine, asked int) []logLine {
	mk := in.st.Marks[source]
	if mk == nil {
		mk = &mark{}
		in.st.Marks[source] = mk
	}
	out := make([]logLine, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		out = append(out, lines[i])
	}
	sort.SliceStable(out, func(i, j int) bool { return lineTime(out[i]) < lineTime(out[j]) })
	if len(out) >= asked && mk.Last > 0 && lineTime(out[0]) > mk.Last {
		in.st.Gaps = append(in.st.Gaps, mk.Last)
	}
	seen := map[uint32]bool{}
	for _, f := range mk.Seen {
		seen[f] = true
	}
	keep := out[:0]
	for _, l := range out {
		t := lineTime(l)
		f := fingerprint(l.Program + "|" + l.Message)
		if t < mk.Last || (t == mk.Last && seen[f]) {
			continue
		}
		if t > mk.Last {
			mk.Last, seen = t, map[uint32]bool{}
		}
		seen[f] = true
		keep = append(keep, l)
	}
	mk.Seen = mk.Seen[:0]
	for f := range seen {
		mk.Seen = append(mk.Seen, f)
	}
	return keep
}

func lineTime(l logLine) int64 {
	t, _ := l.Time.Int64()
	return t
}

func fingerprint(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func (in *Insight) poll() {
	pf, errP := in.c.logs("postfix", 5000)
	dv, errD := in.c.logs("dovecot", 2000)
	rs, errR := in.c.rspamdHistory(500)
	in.mu.Lock()
	defer in.mu.Unlock()
	in.lastPoll = time.Now()
	in.pollErr = ""
	for _, e := range []error{errP, errD, errR} {
		if e != nil {
			in.pollErr = e.Error()
		}
	}
	if errD == nil {
		in.ingestDovecot(in.fresh("dovecot", dv, 2000))
	}
	if errP == nil {
		in.ingestPostfix(in.fresh("postfix", pf, 5000))
	}
	if errR == nil {
		in.ingestRspamd(rs)
	}
	in.prune(time.Now().Unix())
	if in.dirty {
		in.save()
	}
}

func (in *Insight) ingestPostfix(lines []logLine) {
	for _, l := range lines {
		t := lineTime(l)
		if in.st.Since == 0 || t < in.st.Since {
			in.st.Since = t
		}
		for _, x := range in.tr.postfix(t, l.Program, l.Message) {
			if x.kind == "authfail" && in.st.DovecotChecks {
				continue
			}
			in.add(x)
		}
		in.dirty = true
	}
}

func (in *Insight) ingestDovecot(lines []logLine) {
	all := func(string) bool { return true }
	for _, l := range lines {
		if reAuthCheck.MatchString(l.Message) {
			in.st.DovecotChecks = true
		}
	}
	for _, l := range lines {
		if in.st.DovecotChecks {
			if m := reAuthCheck.FindStringSubmatch(l.Message); m != nil {
				in.add(tally{t: lineTime(l), kind: "authfail", user: strings.ToLower(m[1])})
				in.dirty = true
			}
			continue
		}
		for _, f := range loginFailures([]logLine{l}, all) {
			in.add(tally{t: f.Time, kind: "authfail", user: strings.ToLower(f.Tried)})
			in.dirty = true
		}
	}
}

// ingestRspamd dedups by time and Message-ID, then joins each new row to its message.
func (in *Insight) ingestRspamd(rows []rspamdEntry) {
	mk := in.st.Marks["rspamd"]
	if mk == nil {
		mk = &mark{}
		in.st.Marks["rspamd"] = mk
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Time < rows[j].Time })
	seen := map[uint32]bool{}
	for _, f := range mk.Seen {
		seen[f] = true
	}
	for _, e := range rows {
		f := fingerprint(fmt.Sprintf("%s|%s|%v|%v", e.MessageID, e.Sender, e.Rcpt, e.Score))
		if e.Time < mk.Last || (e.Time == mk.Last && seen[f]) {
			continue
		}
		if e.Time > mk.Last {
			mk.Last, seen = e.Time, map[uint32]bool{}
		}
		seen[f] = true
		if e.Action == "add header" || e.Action == "rewrite subject" {
			user := ""
			if len(e.Rcpt) == 1 {
				user = strings.ToLower(e.Rcpt[0])
			}
			in.add(tally{t: e.Time, kind: "junk", user: user, reason: "Sent to Junk"})
		}
		in.st.Pending = append(in.st.Pending, e)
		in.dirty = true
	}
	mk.Seen = mk.Seen[:0]
	for f := range seen {
		mk.Seen = append(mk.Seen, f)
	}
	now := time.Now().Unix()
	keep := in.st.Pending[:0]
	for _, e := range in.st.Pending {
		if !in.tr.attach(e) && now-e.Time < pendingVerdicts {
			keep = append(keep, e)
		}
	}
	in.st.Pending = keep
}

func (in *Insight) add(x tally) {
	h := x.t - x.t%3600
	d := in.st.Hours[h]
	if d == nil {
		d = &hourData{Counts: counts{}}
		in.st.Hours[h] = d
	}
	d.Counts[x.kind]++
	if x.user != "" && strings.Contains(x.user, "@") {
		if d.Boxes == nil {
			d.Boxes = map[string]counts{}
		}
		if d.Boxes[x.user] == nil {
			d.Boxes[x.user] = counts{}
		}
		d.Boxes[x.user][x.kind]++
	}
	if x.reason != "" {
		if d.Reasons == nil {
			d.Reasons = map[string]int{}
		}
		d.Reasons[x.reason]++
	}
}

func (in *Insight) prune(now int64) {
	for h := range in.st.Hours {
		if h < now-insightHours*3600 {
			delete(in.st.Hours, h)
			in.dirty = true
		}
	}
	for id, m := range in.st.Msgs {
		if m.Updated < now-trailDays*86400 {
			delete(in.st.Msgs, id)
			in.dirty = true
		}
	}
	if len(in.st.Msgs) > trailMax {
		ms := make([]*Message, 0, len(in.st.Msgs))
		for _, m := range in.st.Msgs {
			ms = append(ms, m)
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i].Updated < ms[j].Updated })
		for _, m := range ms[:len(ms)-trailMax] {
			delete(in.st.Msgs, m.ID)
		}
		in.dirty = true
	}
	if len(in.st.Gaps) > 50 {
		in.st.Gaps = in.st.Gaps[len(in.st.Gaps)-50:]
	}
}

func (in *Insight) save() {
	if in.path == "" {
		return
	}
	b, err := json.Marshal(in.st)
	if err != nil {
		return
	}
	tmp := in.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("mail insight: %v", err)
		return
	}
	if err := os.Rename(tmp, in.path); err != nil {
		log.Printf("mail insight: %v", err)
		return
	}
	in.dirty = false
}

func (c *Client) logs(kind string, n int) ([]logLine, error) {
	data, err := c.List(fmt.Sprintf("get/logs/%s/%d", kind, n))
	if err != nil {
		return nil, err
	}
	var lines []logLine
	err = json.Unmarshal(data, &lines)
	return lines, err
}

func (c *Client) rspamdHistory(n int) ([]rspamdEntry, error) {
	data, err := c.List(fmt.Sprintf("get/logs/rspamd-history/%d", n))
	if err != nil {
		return nil, err
	}
	var rows []rspamdEntry
	err = json.Unmarshal(data, &rows)
	return rows, err
}

// ---- the dashboard

var healthKinds = []string{"received", "sent", "delivered_local", "delivered_remote", "deferred", "bounced", "refused", "spam", "junk", "greylisted", "authfail"}

type healthPoint struct {
	T int64  `json:"t"`
	C counts `json:"c"`
}

type boxRow struct {
	User string `json:"user"`
	C    counts `json:"c"`
}

type reasonRow struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// health sums the hours in [from, to) into buckets of step seconds, shifted by tz seconds so
// daily buckets start at the viewer's midnight.
func (in *Insight) health(from, to, step, tz int64) map[string]interface{} {
	in.mu.Lock()
	defer in.mu.Unlock()
	start := from - ((from+tz)%step+step)%step
	n := int((to - start + step - 1) / step)
	series := make([]healthPoint, n)
	for i := range series {
		series[i] = healthPoint{T: start + int64(i)*step, C: counts{}}
	}
	total, prev := counts{}, counts{}
	boxes := map[string]counts{}
	reasons := map[string]int{}
	span := to - from
	for h, d := range in.st.Hours {
		if h >= from-span && h < from {
			for k, v := range d.Counts {
				prev[k] += v
			}
		}
		if h < from || h >= to {
			continue
		}
		i := int((h - start) / step)
		if i < 0 || i >= n {
			continue
		}
		for k, v := range d.Counts {
			series[i].C[k] += v
			total[k] += v
		}
		for u, c := range d.Boxes {
			if boxes[u] == nil {
				boxes[u] = counts{}
			}
			for k, v := range c {
				boxes[u][k] += v
			}
		}
		for r, v := range d.Reasons {
			reasons[r] += v
		}
	}
	rows := make([]boxRow, 0, len(boxes))
	for u, c := range boxes {
		rows = append(rows, boxRow{User: u, C: c})
	}
	activity := func(c counts) int { return c["sent"] + c["delivered_local"] + c["authfail"] + c["bounced"] }
	sort.Slice(rows, func(i, j int) bool {
		if activity(rows[i].C) != activity(rows[j].C) {
			return activity(rows[i].C) > activity(rows[j].C)
		}
		return rows[i].User < rows[j].User
	})
	if len(rows) > 50 {
		rows = rows[:50]
	}
	rr := make([]reasonRow, 0, len(reasons))
	for r, v := range reasons {
		rr = append(rr, reasonRow{r, v})
	}
	sort.Slice(rr, func(i, j int) bool {
		if rr[i].Count != rr[j].Count {
			return rr[i].Count > rr[j].Count
		}
		return rr[i].Reason < rr[j].Reason
	})
	if len(rr) > 10 {
		rr = rr[:10]
	}
	gaps := []int64{}
	for _, g := range in.st.Gaps {
		if g >= from && g < to {
			gaps = append(gaps, g)
		}
	}
	out := map[string]interface{}{"from": from, "to": to, "step": step, "series": series, "total": total, "previous": prev,
		"mailboxes": rows, "reasons": rr, "since": in.st.Since, "gaps": gaps, "kinds": healthKinds, "error": in.pollErr}
	if !in.lastPoll.IsZero() {
		out["last_poll"] = in.lastPoll.Unix()
	}
	return out
}

// ---- the trail

type trailRow struct {
	ID        string   `json:"id"`
	Time      int64    `json:"time"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Subject   string   `json:"subject,omitempty"`
	Status    string   `json:"status"`
	Direction string   `json:"direction"`
	Spam      bool     `json:"spam"`
	Score     *float64 `json:"score,omitempty"`
	User      string   `json:"user,omitempty"`
	IP        string   `json:"ip,omitempty"`
	Door      bool     `json:"door,omitempty"` // turned away before the message itself was sent
}

func row(m *Message) trailRow {
	r := trailRow{ID: m.ID, Time: m.Time, From: m.From, To: m.To, Subject: m.Subject, Status: m.Status(), Direction: m.Direction(), Spam: m.Spam(), User: m.User, IP: m.IP}
	if m.Verdict != nil {
		s := m.Verdict.Score
		r.Score = &s
	}
	r.Door = m.Refused != nil && m.Refused.Stage == "door"
	return r
}

func matches(m *Message, q string) bool {
	if q == "" {
		return true
	}
	for _, f := range append([]string{m.ID, m.From, m.Subject, m.MessageID, m.IP, m.Client, m.User}, m.To...) {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	for _, h := range m.Hops {
		if strings.Contains(strings.ToLower(h.OrigTo), q) {
			return true
		}
	}
	return false
}

func (in *Insight) search(q, status, dir string, limit int) map[string]interface{} {
	in.mu.Lock()
	defer in.mu.Unlock()
	q = strings.ToLower(strings.TrimSpace(q))
	all := make([]*Message, 0, len(in.st.Msgs))
	for _, m := range in.st.Msgs {
		if m.NoticeFor != "" && dir != "system" {
			continue // Postfix's own bounce notices live inside the message they're about
		}
		all = append(all, m)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Time != all[j].Time {
			return all[i].Time > all[j].Time
		}
		return all[i].ID > all[j].ID
	})
	out, found := []trailRow{}, 0
	for _, m := range all {
		if !matches(m, q) {
			continue
		}
		st := m.Status()
		if status == "spam" && !m.Spam() || status != "" && status != "spam" && st != status {
			continue
		}
		if dir != "" && m.Direction() != dir {
			continue
		}
		found++
		if len(out) < limit {
			out = append(out, row(m))
		}
	}
	oldest := int64(0)
	for _, m := range in.st.Msgs {
		if oldest == 0 || m.Time < oldest {
			oldest = m.Time
		}
	}
	return map[string]interface{}{"messages": out, "found": found, "kept": len(in.st.Msgs), "oldest": oldest, "days": trailDays}
}

func (in *Insight) message(id string) (map[string]interface{}, bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	m, ok := in.st.Msgs[id]
	if !ok {
		return nil, false
	}
	out := map[string]interface{}{"message": m, "status": m.Status(), "direction": m.Direction(), "spam": m.Spam()}
	if m.Notice != "" {
		if n, ok := in.st.Msgs[m.Notice]; ok {
			out["notice"] = row(n)
		}
	}
	if m.NoticeFor != "" {
		if n, ok := in.st.Msgs[m.NoticeFor]; ok {
			out["notice_for"] = row(n)
		}
	}
	return out, true
}

func mountInsight(r chi.Router, c *Client, o Options) {
	in := newInsight(c, o.StateDir)
	if c != nil {
		go in.run()
	}
	lastKick := time.Time{}
	var kickMu sync.Mutex

	r.Get("/insight/health", func(w http.ResponseWriter, req *http.Request) {
		now := time.Now().Unix()
		tz, _ := strconv.ParseInt(req.URL.Query().Get("tz"), 10, 64) // the viewer's offset from UTC, in minutes
		if tz < -14*60 || tz > 14*60 {
			tz = 0
		}
		var span, step int64
		switch req.URL.Query().Get("range") {
		case "7d":
			span, step = 7*86400, 6*3600
		case "30d":
			span, step = 30*86400, 86400
		default:
			span, step = 86400, 3600
		}
		to := now - now%3600 + 3600
		writeJSON(w, 200, in.health(to-span, to, step, tz*60))
	})
	r.Post("/insight/refresh", func(w http.ResponseWriter, _ *http.Request) {
		kickMu.Lock()
		defer kickMu.Unlock()
		if time.Since(lastKick) > 10*time.Second {
			lastKick = time.Now()
			select {
			case in.kick <- struct{}{}:
			default:
			}
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	r.Get("/trail", func(w http.ResponseWriter, req *http.Request) {
		qs := req.URL.Query()
		limit, _ := strconv.Atoi(qs.Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 200
		}
		status, dir := qs.Get("status"), qs.Get("dir")
		if !map[string]bool{"": true, "delivered": true, "deferred": true, "bounced": true, "refused": true, "greylisted": true, "partial": true, "queued": true, "spam": true}[status] ||
			!map[string]bool{"": true, "in": true, "out": true, "internal": true, "system": true}[dir] {
			fail(w, 400, fmt.Errorf("unknown filter"))
			return
		}
		writeJSON(w, 200, in.search(qs.Get("q"), status, dir, limit))
	})
	r.Get("/trail/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := param(req, "id")
		if !reQueueID.MatchString(id) {
			fail(w, 400, fmt.Errorf("invalid message id"))
			return
		}
		out, ok := in.message(id)
		if !ok {
			fail(w, 404, fmt.Errorf("that message isn't in the trail (it keeps %d days)", trailDays))
			return
		}
		writeJSON(w, 200, out)
	})
}
