// Package crowdsec manages the CrowdSec installation on this host: it runs cscli for
// hub, decision and metrics calls, and uses the cowsec-hostctl helper for anything that
// touches system services or files (status, reloads, ban policy, updates).
package crowdsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/OryxAstro/cowsec/internal/geo"
)

// Target is the CrowdSec installation CowSec manages.
type Target struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	helper   string // cowsec-hostctl: allowlisted status/actions/policy/updates
	stateDir string // policy.json lives here
	geo      *geo.DB

	overviewMu        sync.Mutex
	overviewCache     map[string]interface{}
	overviewCacheTime time.Time

	hubCacheMu   sync.RWMutex
	hubCache     map[string][]ItemInfo
	hubCacheTime time.Time

	// OnUnban, when set, runs after a ban on an IP or range is lifted (e.g. to lift it in mailcow's netfilter too).
	OnUnban func(value string)
}

// New returns the local CrowdSec target.
func New(id, name, description, helper, stateDir string, g *geo.DB) *Target {
	return &Target{ID: id, Name: name, Description: description, helper: helper, stateDir: stateDir, geo: g,
		hubCache: map[string][]ItemInfo{}}
}

func (t *Target) cscli(args ...string) ([]byte, error) {
	out, err := exec.Command("cscli", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cscli %v error: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Gate runs one allowlisted verb through the host helper (for other packages).
func (t *Target) Gate(verb string, args ...string) ([]byte, error) { return t.gate(verb, args...) }

// gate runs one allowlisted verb through the host helper.
func (t *Target) gate(verb string, args ...string) ([]byte, error) {
	if t.helper == "" {
		return nil, fmt.Errorf("no host helper configured")
	}
	cmd := exec.Command(t.helper)
	cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+strings.Join(append([]string{verb}, args...), " "), "SSH_CLIENT=cowsec 0 0")
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			msg = strings.TrimSpace(msg + " " + string(ee.Stderr))
		}
		return nil, fmt.Errorf("%s failed: %v (%s)", verb, err, msg)
	}
	return out, nil
}

// gateStdin runs a verb with a request body on standard input, for values (like an access
// token) that must not appear in a process's arguments or environment.
func (t *Target) gateStdin(verb string, stdin []byte) ([]byte, error) {
	if t.helper == "" {
		return nil, fmt.Errorf("no host helper configured")
	}
	cmd := exec.Command(t.helper)
	cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+verb, "SSH_CLIENT=cowsec 0 0")
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			msg = strings.TrimSpace(msg + " " + string(ee.Stderr))
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return out, nil
}

func (t *Target) gateJSON(verb string, args ...string) (map[string]interface{}, error) {
	out, err := t.gate(verb, args...)
	if err != nil {
		return nil, err
	}
	var v map[string]interface{}
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, fmt.Errorf("bad %s output: %v", verb, err)
	}
	return v, nil
}

func (t *Target) invalidate() {
	t.ClearHubCache()
	t.overviewMu.Lock()
	t.overviewCacheTime = time.Time{}
	t.overviewMu.Unlock()
}

// HostStatus returns the host's service, bouncer, AppSec, acquisition and TLS status.
func (t *Target) HostStatus() (map[string]interface{}, error) { return t.gateJSON("status") }

// HostActions are the service operations the helper allows.
var HostActions = []string{"reload-crowdsec", "restart-crowdsec", "restart-firewall-bouncer", "reload-openresty",
	"enable-hub-autoupdate", "disable-hub-autoupdate"}

// HostAction runs one allowlisted service action.
func (t *Target) HostAction(action string) (string, error) {
	allowed := false
	for _, a := range HostActions {
		allowed = allowed || a == action
	}
	if !allowed {
		return "", fmt.Errorf("unknown action %q", action)
	}
	t.invalidate()
	out, err := t.gate("action", action)
	return strings.TrimSpace(string(out)), err
}
