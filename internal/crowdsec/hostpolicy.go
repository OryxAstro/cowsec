package crowdsec

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// Policy is a host's ban policy: which countries count as home, the stricter rule for
// failed mail logins from elsewhere, and escalating ban durations for repeat offenders.
// cowsec-hostctl renders it into CrowdSec (profiles.yaml + a local scenario).
type Policy struct {
	HomeCountries []string `json:"homeCountries"`
	Abroad        struct {
		Enabled     bool `json:"enabled"`
		SMTP        bool `json:"smtp"`
		IMAP        bool `json:"imap"`
		Failures    int  `json:"failures"`
		WindowHours int  `json:"windowHours"`
	} `json:"abroad"`
	Escalation struct {
		Enabled      bool   `json:"enabled"`
		IncludeHome  bool   `json:"includeHome"` // escalate home-country IPs too (off: they keep the first-ban length)
		BaseHours    int    `json:"baseHours"`
		Mode         string `json:"mode"` // linear | double
		MaxHours     int    `json:"maxHours"`
		LookbackDays int    `json:"lookbackDays"`
	} `json:"escalation"`
}

var isoCode = regexp.MustCompile(`^[A-Z]{2}$`)

// Validate mirrors the helper's checks so the UI gets a clear message before anything is written.
func (p *Policy) Validate() error {
	if len(p.HomeCountries) < 1 || len(p.HomeCountries) > 30 {
		return fmt.Errorf("choose between 1 and 30 home countries")
	}
	for _, c := range p.HomeCountries {
		if !isoCode.MatchString(c) {
			return fmt.Errorf("%q is not a two-letter country code", c)
		}
	}
	a, e := p.Abroad, p.Escalation
	switch {
	case a.Failures < 1 || a.Failures > 20:
		return fmt.Errorf("failed logins must be 1-20")
	case a.WindowHours < 1 || a.WindowHours > 168:
		return fmt.Errorf("the window must be 1-168 hours")
	case a.Enabled && !a.SMTP && !a.IMAP:
		return fmt.Errorf("choose SMTP and/or IMAP/POP for the abroad rule")
	case e.BaseHours < 1 || e.BaseHours > 168:
		return fmt.Errorf("the first ban must be 1-168 hours")
	case e.Mode != "linear" && e.Mode != "double":
		return fmt.Errorf("escalation must be linear or double")
	case e.MaxHours < e.BaseHours || e.MaxHours > 720:
		return fmt.Errorf("the longest ban must be between the first ban and 720 hours")
	case e.LookbackDays < 1 || e.LookbackDays > 30:
		return fmt.Errorf("the look-back must be 1-30 days")
	}
	return nil
}

// HostPolicy returns the saved policy, whether CrowdSec is using it, and repeat-offender stats.
func (t *Target) HostPolicy() (map[string]interface{}, error) {
	return t.gateJSON("policy-get")
}

// ApplyHostPolicy saves the policy and has the helper render, test and load it.
func (t *Target) ApplyHostPolicy(p Policy) (map[string]interface{}, error) {
	if t.stateDir == "" {
		return nil, fmt.Errorf("no state directory configured for %s", t.ID)
	}
	// Staged: the helper promotes policy.pending.json to policy.json only once CrowdSec
	// has accepted it, so a rejected policy never replaces the one in use.
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(filepath.Join(t.stateDir, "policy.pending.json"), b, 0o600); err != nil {
		return nil, err
	}
	t.invalidate()
	return t.gateJSON("policy-apply")
}

// CountryFailures is one country's failed mail logins over the helper's window.
type CountryFailures struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	IPs      int    `json:"ips"`
	Attempts int    `json:"attempts"`
	SMTPIPs  int    `json:"smtpIps"`
	IMAPIPs  int    `json:"imapIps"`
	// PerIP[n] = IPs with n+1 failed logins (the last bucket is "10 or more")
	PerIP []int `json:"perIp"`
}

// HostAuthFailures groups failed SMTP AUTH and IMAP/POP logins by country (local GeoLite2
// lookup, nothing leaves the host), so the policy page can show what a rule would catch.
func (t *Target) HostAuthFailures() (map[string]interface{}, error) {
	out, err := t.gate("auth-failures")
	if err != nil {
		return nil, err
	}
	var raw struct {
		Hours int            `json:"hours"`
		SMTP  map[string]int `json:"smtp"`
		IMAP  map[string]int `json:"imap"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("bad auth-failures output: %v", err)
	}
	type perIP struct{ smtp, imap int }
	ips := map[string]*perIP{}
	for ip, n := range raw.SMTP {
		if ips[ip] == nil {
			ips[ip] = &perIP{}
		}
		ips[ip].smtp += n
	}
	for ip, n := range raw.IMAP {
		if ips[ip] == nil {
			ips[ip] = &perIP{}
		}
		ips[ip].imap += n
	}
	countries := map[string]*CountryFailures{}
	for ip, c := range ips {
		code, name := t.geo.Country(ip)
		cf := countries[code]
		if cf == nil {
			cf = &CountryFailures{Code: code, Name: name, PerIP: make([]int, 10)}
			countries[code] = cf
		}
		n := c.smtp + c.imap
		cf.IPs++
		cf.Attempts += n
		if c.smtp > 0 {
			cf.SMTPIPs++
		}
		if c.imap > 0 {
			cf.IMAPIPs++
		}
		cf.PerIP[min(n, 10)-1]++
	}
	list := make([]*CountryFailures, 0, len(countries))
	for _, c := range countries {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].IPs != list[j].IPs {
			return list[i].IPs > list[j].IPs
		}
		return list[i].Code < list[j].Code
	})
	return map[string]interface{}{"hours": raw.Hours, "countries": list, "ips": len(ips), "geo": t.geo.Available()}, nil
}

// HostJobs are the long-running maintenance jobs the helper runs in the background.
var HostJobs = []string{"apt-refresh", "upgrade-crowdsec", "hub-upgrade", "mailcow-check", "mailcow-update"}

// HostUpdates returns package versions, hub item updates, the nightly hub auto-update
// timer and the state of background jobs.
func (t *Target) HostUpdates() (map[string]interface{}, error) {
	return t.gateJSON("updates")
}

// StartHostJob starts one allowlisted background job.
func (t *Target) StartHostJob(job string) error {
	ok := false
	for _, j := range HostJobs {
		ok = ok || j == job
	}
	if !ok {
		return fmt.Errorf("unknown job %q", job)
	}
	t.invalidate()
	_, err := t.gate("job", job)
	return err
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// HostJobState returns one background job's state, steps and live extras.
func (t *Target) HostJobState(job string) (map[string]interface{}, error) {
	for _, j := range HostJobs {
		if j == job {
			return t.gateJSON("job-state", job)
		}
	}
	return nil, fmt.Errorf("unknown job %q", job)
}

// HostListDir lists sub-directories for the backup folder picker.
func (t *Target) HostListDir(path string) (map[string]interface{}, error) {
	if path == "" {
		path = "/"
	}
	return t.gateJSON("fs-list", b64(path))
}

// HostMakeDir creates a folder for backups (validated by the helper).
func (t *Target) HostMakeDir(path string) (map[string]interface{}, error) {
	return t.gateJSON("fs-mkdir", b64(path))
}

// MailcowContainers returns container states from Docker (works during an update).
func (t *Target) MailcowContainers() (map[string]interface{}, error) {
	return t.gateJSON("mailcow-containers")
}

// SetMailcowUpdateOptions validates and stores the backup choice for mailcow updates.
func (t *Target) SetMailcowUpdateOptions(o map[string]interface{}) (map[string]interface{}, error) {
	b, _ := json.Marshal(o)
	return t.gateJSON("mailcow-update-options", b64(string(b)))
}
