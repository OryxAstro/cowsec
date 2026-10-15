package crowdsec

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// managedAllowlist is CowSec's own CrowdSec allowlist. Allowlists (CrowdSec 1.7+) are
// checked by the LAPI, so they stop local detections *and* filter community-blocklist
// decisions, with no reload needed.
const managedAllowlist = "cowsec"

// ParserWhitelist is one whitelist parser file under parsers/s02-enrich (read-only view).
type ParserWhitelist struct {
	File        string   `json:"file"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Reason      string   `json:"reason"`
	IPs         []string `json:"ips"`
	CIDRs       []string `json:"cidrs"`
	Expressions []string `json:"expressions"`
	FromHub     bool     `json:"fromHub"`
}

// AllowlistEntry is one value in CowSec's allowlist.
type AllowlistEntry struct {
	Value      string `json:"value"`
	Comment    string `json:"comment"`
	CreatedAt  string `json:"createdAt"`
	Expiration string `json:"expiration"`
}

const parserDir = "/etc/crowdsec/parsers/s02-enrich"

func readParserWhitelists() []ParserWhitelist {
	files, _ := filepath.Glob(filepath.Join(parserDir, "*.yaml"))
	sort.Strings(files)
	out := []ParserWhitelist{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var doc struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
			Whitelist   *struct {
				Reason     string   `yaml:"reason"`
				IP         []string `yaml:"ip"`
				CIDR       []string `yaml:"cidr"`
				Expression []string `yaml:"expression"`
			} `yaml:"whitelist"`
		}
		if yaml.Unmarshal(b, &doc) != nil || doc.Whitelist == nil {
			continue
		}
		link, _ := os.Readlink(f)
		out = append(out, ParserWhitelist{
			File: filepath.Base(f), Name: doc.Name, Description: doc.Description, Reason: doc.Whitelist.Reason,
			IPs: doc.Whitelist.IP, CIDRs: doc.Whitelist.CIDR, Expressions: doc.Whitelist.Expression,
			FromHub: strings.Contains(link, "/hub/"),
		})
	}
	return out
}

func (t *Target) allowlistEntries() ([]AllowlistEntry, error) {
	out, err := t.cscli("allowlists", "inspect", managedAllowlist, "-o", "json")
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return []AllowlistEntry{}, nil
		}
		return nil, err
	}
	var al struct {
		Items []struct {
			Value       string `json:"value"`
			Description string `json:"description"`
			CreatedAt   string `json:"created_at"`
			Expiration  string `json:"expiration"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &al); err != nil {
		return nil, fmt.Errorf("bad allowlist output: %v", err)
	}
	entries := make([]AllowlistEntry, 0, len(al.Items))
	for _, i := range al.Items {
		entries = append(entries, AllowlistEntry{Value: i.Value, Comment: i.Description, CreatedAt: i.CreatedAt, Expiration: i.Expiration})
	}
	return entries, nil
}

// GetWhitelists returns CowSec's editable allowlist plus the whitelist parsers in use.
func (t *Target) GetWhitelists() (map[string]interface{}, error) {
	entries, err := t.allowlistEntries()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"allowlist": map[string]interface{}{"name": managedAllowlist, "entries": entries},
		"parsers":   readParserWhitelists(),
	}, nil
}

func validWhitelistValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	if ip := net.ParseIP(v); ip != nil {
		return ip.String(), nil
	}
	if _, n, err := net.ParseCIDR(v); err == nil {
		if ones, bits := n.Mask.Size(); (bits == 32 && ones < 8) || (bits == 128 && ones < 16) {
			return "", fmt.Errorf("%s is too broad to allowlist", v)
		}
		return n.String(), nil
	}
	return "", fmt.Errorf("%q is not an IP address or CIDR range", v)
}

// AddWhitelistEntry adds an IP or range to CowSec's allowlist (created on first use).
func (t *Target) AddWhitelistEntry(value, reason string) error {
	v, err := validWhitelistValue(value)
	if err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > 200 {
		reason = reason[:200]
	}
	if _, err := t.cscli("allowlists", "inspect", managedAllowlist, "-o", "json"); err != nil {
		if _, err := t.cscli("allowlists", "create", managedAllowlist, "-d", "Managed by CowSec"); err != nil {
			return err
		}
	}
	args := []string{"allowlists", "add", managedAllowlist, v}
	if reason != "" {
		args = append(args, "-d", reason)
	}
	_, err = t.cscli(args...)
	t.invalidate()
	return err
}

// RemoveWhitelistEntry removes a value from CowSec's allowlist.
func (t *Target) RemoveWhitelistEntry(value string) error {
	v, err := validWhitelistValue(value)
	if err != nil {
		return err
	}
	_, err = t.cscli("allowlists", "remove", managedAllowlist, v)
	t.invalidate()
	return err
}
