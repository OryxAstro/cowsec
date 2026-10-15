package crowdsec

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OryxAstro/cowsec/internal/geo"
)

var hubCategories = map[string]bool{"collections": true, "parsers": true, "scenarios": true, "postoverflows": true,
	"appsec-configs": true, "appsec-rules": true, "contexts": true}

var hubName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// validHubItem accepts only real hub categories and author/name item names.
func validHubItem(category, name string) error {
	if !hubCategories[category] {
		return fmt.Errorf("unknown hub category %q", category)
	}
	if !hubName.MatchString(name) {
		return fmt.Errorf("invalid hub item name %q", name)
	}
	return nil
}

// GeoInfo is the location of an IP (local GeoLite2 lookup, see internal/geo).
type GeoInfo = geo.Info

type RawDecision struct {
	ID        int    `json:"id"`
	Origin    string `json:"origin"`
	Scenario  string `json:"scenario"`
	Scope     string `json:"scope"`
	Simulated bool   `json:"simulated"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
}

type RawAlert struct {
	ID          int           `json:"id"`
	UUID        string        `json:"uuid"`
	Scenario    string        `json:"scenario"`
	Message     string        `json:"message"`
	CreatedAt   string        `json:"created_at"`
	StartAt     string        `json:"start_at"`
	StopAt      string        `json:"stop_at"`
	Capacity    int           `json:"capacity"`
	Leakspeed   string        `json:"leakspeed"`
	EventsCount int           `json:"events_count"`
	Simulated   bool          `json:"simulated"`
	Remediation bool          `json:"remediation"`
	MachineID   string        `json:"machine_id"`
	Decisions   []RawDecision `json:"decisions"`
	Source      struct {
		IP    string `json:"ip"`
		Scope string `json:"scope"`
		Value string `json:"value"`
		CN    string `json:"cn"`
		AS    string `json:"as_name"`
	} `json:"source"`
}

type DecisionView struct {
	ID        int      `json:"id"`
	Value     string   `json:"value"`
	Scope     string   `json:"scope"`
	Type      string   `json:"type"`
	Duration  string   `json:"duration"`
	Scenario  string   `json:"scenario"`
	Origin    string   `json:"origin"`
	Simulated bool     `json:"simulated"`
	AlertID   int      `json:"alertId"`
	CreatedAt string   `json:"createdAt"`
	Geo       *GeoInfo `json:"geo,omitempty"`
}

type AlertView struct {
	ID          int            `json:"id"`
	UUID        string         `json:"uuid"`
	Scenario    string         `json:"scenario"`
	Message     string         `json:"message"`
	IP          string         `json:"ip"`
	Scope       string         `json:"scope"`
	CreatedAt   string         `json:"createdAt"`
	EventsCount int            `json:"eventsCount"`
	Simulated   bool           `json:"simulated"`
	Decisions   []DecisionView `json:"decisions"`
	Geo         *GeoInfo       `json:"geo,omitempty"`
}

type BouncerView struct {
	Name       string  `json:"name"`
	IPAddress  string  `json:"ip_address"`
	Valid      bool    `json:"valid"`
	LastPull   *string `json:"last_pull"`
	Type       string  `json:"type"`
	Version    string  `json:"version"`
	AuthType   string  `json:"auth_type"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  *string `json:"updated_at"`
	AutoCreate bool    `json:"auto_created"`
}

type MachineView struct {
	MachineID     string  `json:"machineId"`
	IPAddress     string  `json:"ipAddress"`
	Version       string  `json:"version"`
	IsValidated   bool    `json:"isValidated"`
	LastHeartbeat *string `json:"last_heartbeat"`
	LastPush      *string `json:"last_push"`
	UpdatedAt     *string `json:"updated_at"`
	OS            string  `json:"os"`
	AuthType      string  `json:"auth_type"`
	CreatedAt     string  `json:"created_at"`
}

type ItemInfo struct {
	Name        string `json:"name"`
	Version     string `json:"local_version"`
	LocalPath   string `json:"local_path,omitempty"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Utf8Status  string `json:"utf8_status,omitempty"`
	Type        string `json:"type,omitempty"`
	Author      string `json:"author,omitempty"`
	ItemName    string `json:"itemName,omitempty"`
}

// GetOverview aggregates metrics, bouncer counts, machine counts, and decision totals with a 20s cache
func (t *Target) GetOverview() (map[string]interface{}, error) {
	t.overviewMu.Lock()
	if t.overviewCache != nil && time.Since(t.overviewCacheTime) < 20*time.Second {
		cached := make(map[string]interface{}, len(t.overviewCache))
		for k, v := range t.overviewCache {
			cached[k] = v
		}
		t.overviewMu.Unlock()
		return cached, nil
	}
	t.overviewMu.Unlock()

	overview := map[string]interface{}{
		"activeBansTotal": 0,
		"localBans":       0,
		"capiBans":        0,
		"totalAlerts":     0,
		"bouncersCount":   0,
		"machinesCount":   0,
		"appsecRules":     0,
		"scenariosCount":  0,
		"parsersCount":    0,
		"collections":     0,
		"appsecStatus":    "active",
	}

	// 1. Metrics JSON for decision counts
	if out, err := t.cscli("metrics", "-o", "json"); err == nil {
		var metricsData struct {
			Alerts    map[string]int `json:"alerts"`
			Decisions map[string]int `json:"decisions"`
			LapiDec   map[string]int `json:"lapi-decisions"`
		}
		if json.Unmarshal(out, &metricsData) == nil {
			totalAlerts := 0
			for _, c := range metricsData.Alerts {
				totalAlerts += c
			}
			overview["totalAlerts"] = totalAlerts
		}
	}

	// 2. Count active local decisions
	if out, err := t.cscli("decisions", "list", "-o", "json"); err == nil {
		var alerts []RawAlert
		if json.Unmarshal(out, &alerts) == nil {
			count := 0
			for _, a := range alerts {
				count += len(a.Decisions)
			}
			overview["localBans"] = count
		}
	}

	// 3. Count CAPI decisions via quick limit or metrics
	if out, err := t.cscli("metrics"); err == nil {
		// Parse from table output if available
		lines := strings.Split(string(out), "\n")
		capiCount := 0
		for _, line := range lines {
			if strings.Contains(line, "CAPI") {
				parts := strings.Split(line, "|")
				if len(parts) >= 5 {
					cntStr := strings.TrimSpace(parts[4])
					if cnt, e := strconv.Atoi(cntStr); e == nil {
						capiCount += cnt
					}
				}
			}
		}
		overview["capiBans"] = capiCount
		localBans, _ := overview["localBans"].(int)
		overview["activeBansTotal"] = localBans + capiCount
	}

	// 4. Bouncers
	if bouncers, err := t.GetBouncers(); err == nil {
		overview["bouncersCount"] = len(bouncers)
	}

	// 5. Machines
	if machines, err := t.GetMachines(); err == nil {
		overview["machinesCount"] = len(machines)
	}

	// 6. AppSec Rules
	if rules, err := t.GetAppSecRules(); err == nil {
		enabledCount := 0
		for _, r := range rules {
			if strings.Contains(r.Status, "enabled") {
				enabledCount++
			}
		}
		overview["appsecRules"] = enabledCount
		overview["appsecRulesTotal"] = len(rules)
	}

	// 7. Scenarios and Parsers
	if scenarios, err := t.GetScenarios(); err == nil {
		overview["scenariosCount"] = len(scenarios)
	}
	if parsers, err := t.GetParsers(); err == nil {
		overview["parsersCount"] = len(parsers)
	}
	if collections, err := t.GetCollections(); err == nil {
		overview["collections"] = len(collections)
	}

	t.overviewMu.Lock()
	t.overviewCache = overview
	t.overviewCacheTime = time.Now()
	t.overviewMu.Unlock()

	return overview, nil
}

// GetDecisions lists decisions focused on Local & Custom Bans, with fast single-IP checks
func (t *Target) GetDecisions(origin, search string, limit, offset int) ([]DecisionView, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	search = strings.TrimSpace(search)
	origin = strings.ToLower(strings.TrimSpace(origin))

	var args []string
	if search != "" && net.ParseIP(search) != nil {
		// Specific IP lookup: Fast index search across all databases (local + CAPI)
		args = []string{"decisions", "list", "--all", "--ip", search, "-o", "json"}
	} else if search != "" {
		if _, _, err := net.ParseCIDR(search); err == nil {
			// Specific CIDR range lookup
			args = []string{"decisions", "list", "--all", "--range", search, "-o", "json"}
		} else {
			// Substring / scenario search on local bans
			args = []string{"decisions", "list", "-o", "json"}
		}
	} else {
		// Default: list local bans only (instant response)
		args = []string{"decisions", "list", "-o", "json"}
	}

	out, err := t.cscli(args...)
	if err != nil {
		return nil, 0, err
	}

	var alerts []RawAlert
	if err := json.Unmarshal(out, &alerts); err != nil {
		return nil, 0, fmt.Errorf("failed to parse decisions output: %v (%s)", err, string(out))
	}

	var allDecisions []DecisionView
	var ipsToEnrich []string

	for _, alert := range alerts {
		for _, dec := range alert.Decisions {
			val := dec.Value
			if val == "" {
				val = alert.Source.Value
			}
			if val == "" {
				val = alert.Source.IP
			}

			item := DecisionView{
				ID:        dec.ID,
				Value:     val,
				Scope:     dec.Scope,
				Type:      dec.Type,
				Duration:  dec.Duration,
				Scenario:  dec.Scenario,
				Origin:    dec.Origin,
				Simulated: dec.Simulated,
				AlertID:   alert.ID,
				CreatedAt: alert.CreatedAt,
			}
			if item.Scenario == "" {
				item.Scenario = alert.Scenario
			}

			// Filter if search query matches scenario, value (IP), origin, or cached geo
			if search != "" {
				sLower := strings.ToLower(search)
				match := strings.Contains(strings.ToLower(val), sLower) ||
					strings.Contains(strings.ToLower(item.Scenario), sLower) ||
					strings.Contains(strings.ToLower(item.Origin), sLower)

				if !match {
					if g := t.geo.One(val); g.Status == "success" {
						if strings.Contains(strings.ToLower(g.Country), sLower) ||
							strings.Contains(strings.ToLower(g.CountryCode), sLower) ||
							strings.Contains(strings.ToLower(g.City), sLower) ||
							strings.Contains(strings.ToLower(g.AS), sLower) {
							match = true
						}
					}
				}

				if !match {
					continue
				}
			}

			allDecisions = append(allDecisions, item)
		}
	}

	total := len(allDecisions)

	// Apply pagination slice BEFORE GeoIP enrichment to avoid batch fetching thousands of IPs
	if offset > 0 && offset < len(allDecisions) {
		allDecisions = allDecisions[offset:]
	} else if offset >= len(allDecisions) && len(allDecisions) > 0 {
		allDecisions = []DecisionView{}
	}
	if len(allDecisions) > limit {
		allDecisions = allDecisions[:limit]
	}

	for _, item := range allDecisions {
		if item.Scope == "Ip" || item.Scope == "Range" || strings.Contains(item.Value, ".") || strings.Contains(item.Value, ":") {
			ipsToEnrich = append(ipsToEnrich, item.Value)
		}
	}

	// Enrich with GeoIP
	geoMap := t.geo.Lookup(ipsToEnrich)
	for i := range allDecisions {
		if geo, ok := geoMap[allDecisions[i].Value]; ok {
			allDecisions[i].Geo = geo
		}
	}

	return allDecisions, total, nil
}

// AddDecision creates a manual ban or captcha decision
func (t *Target) AddDecision(ip, duration, reason, decisionType string) (string, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", fmt.Errorf("IP address or CIDR range is required")
	}

	if duration == "" {
		duration = "4h"
	}
	if reason == "" {
		reason = "manual-admin-ban"
	}
	if decisionType == "" {
		decisionType = "ban"
	}
	if net.ParseIP(ip) == nil {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			return "", fmt.Errorf("%q is not an IP address or CIDR range", ip)
		}
	}
	if !regexp.MustCompile(`^[0-9]{1,5}[smhd]$`).MatchString(duration) {
		return "", fmt.Errorf("duration must look like 30m, 4h or 7d")
	}
	if decisionType != "ban" && decisionType != "captcha" && decisionType != "throttle" {
		return "", fmt.Errorf("type must be ban, captcha or throttle")
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}

	var args []string
	if strings.Contains(ip, "/") {
		args = []string{"decisions", "add", "--range", ip, "--duration", duration, "--reason", reason, "--type", decisionType}
	} else {
		args = []string{"decisions", "add", "--ip", ip, "--duration", duration, "--reason", reason, "--type", decisionType}
	}

	out, err := t.cscli(args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// DeleteDecision removes a decision by IP or ID
func (t *Target) DeleteDecision(ip, id string) (string, error) {
	var args []string
	if id != "" {
		args = []string{"decisions", "delete", "--id", id}
	} else if ip != "" {
		if strings.Contains(ip, "/") {
			args = []string{"decisions", "delete", "--range", ip}
		} else {
			args = []string{"decisions", "delete", "--ip", ip}
		}
	} else {
		return "", fmt.Errorf("either IP or Decision ID is required to unblock")
	}

	out, err := t.cscli(args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// GetAlerts lists recent alerts with GeoIP enrichment
func (t *Target) GetAlerts(limit int) ([]AlertView, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	out, err := t.cscli("alerts", "list", "--limit", strconv.Itoa(limit), "-o", "json")
	if err != nil {
		return nil, err
	}

	var alerts []RawAlert
	if err := json.Unmarshal(out, &alerts); err != nil {
		return nil, fmt.Errorf("failed to parse alerts: %v", err)
	}

	var views []AlertView
	var ipsToEnrich []string

	for _, a := range alerts {
		srcIP := a.Source.IP
		if srcIP == "" {
			srcIP = a.Source.Value
		}

		view := AlertView{
			ID:          a.ID,
			UUID:        a.UUID,
			Scenario:    a.Scenario,
			Message:     a.Message,
			IP:          srcIP,
			Scope:       a.Source.Scope,
			CreatedAt:   a.CreatedAt,
			EventsCount: a.EventsCount,
			Simulated:   a.Simulated,
		}

		for _, d := range a.Decisions {
			val := d.Value
			if val == "" {
				val = srcIP
			}
			view.Decisions = append(view.Decisions, DecisionView{
				ID:        d.ID,
				Value:     val,
				Scope:     d.Scope,
				Type:      d.Type,
				Duration:  d.Duration,
				Scenario:  d.Scenario,
				Origin:    d.Origin,
				Simulated: d.Simulated,
				AlertID:   a.ID,
				CreatedAt: a.CreatedAt,
			})
		}

		views = append(views, view)
		if srcIP != "" {
			ipsToEnrich = append(ipsToEnrich, srcIP)
		}
	}

	geoMap := t.geo.Lookup(ipsToEnrich)
	for i := range views {
		if geo, ok := geoMap[views[i].IP]; ok {
			views[i].Geo = geo
		}
	}

	return views, nil
}

// GetBouncers returns registered remediation components
func (t *Target) GetBouncers() ([]BouncerView, error) {
	out, err := t.cscli("bouncers", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var rawBouncers []struct {
		Name        string  `json:"name"`
		IPAddress   string  `json:"ip_address"`
		Revoked     bool    `json:"revoked"`
		LastPull    *string `json:"last_pull"`
		Type        string  `json:"type"`
		Version     string  `json:"version"`
		AuthType    string  `json:"auth_type"`
		CreatedAt   string  `json:"created_at"`
		UpdatedAt   *string `json:"updated_at"`
		AutoCreated bool    `json:"auto_created"`
	}

	if err := json.Unmarshal(out, &rawBouncers); err != nil {
		return nil, err
	}

	bouncers := make([]BouncerView, 0)
	for _, b := range rawBouncers {
		bouncers = append(bouncers, BouncerView{
			Name:       b.Name,
			IPAddress:  b.IPAddress,
			Valid:      !b.Revoked,
			LastPull:   b.LastPull,
			Type:       b.Type,
			Version:    b.Version,
			AuthType:   b.AuthType,
			CreatedAt:  b.CreatedAt,
			UpdatedAt:  b.UpdatedAt,
			AutoCreate: b.AutoCreated,
		})
	}
	return bouncers, nil
}

// GetMachines returns registered agents/runners
func (t *Target) GetMachines() ([]MachineView, error) {
	out, err := t.cscli("machines", "list", "-o", "json")
	if err != nil {
		return make([]MachineView, 0), err
	}

	machines := make([]MachineView, 0)
	if err := json.Unmarshal(out, &machines); err != nil {
		return make([]MachineView, 0), nil
	}
	if machines == nil {
		machines = make([]MachineView, 0)
	}
	return machines, nil
}

// DeleteMachine removes a specific machine registration by ID
func (t *Target) DeleteMachine(name string) error {
	_, err := t.cscli("machines", "delete", name, "--ignore-missing")
	return err
}

// PruneMachines removes machines that stopped reporting. Bouncers are never pruned:
// they are long-lived services, and the OpenResty bouncer in live mode only "pulls"
// when there is web traffic, so a quiet day would de-authorise the WAF.
func (t *Target) PruneMachines() error {
	_, err := t.cscli("machines", "prune", "--duration", "10m", "--force")
	return err
}

// GetAppSecRules returns all available and installed AppSec WAF rules and CVE virtual patches
func (t *Target) GetAppSecRules() ([]ItemInfo, error) {
	out, err := t.cscli("appsec-rules", "list", "-a", "-o", "json")
	if err != nil {
		return nil, err
	}

	var data struct {
		Rules []ItemInfo `json:"appsec-rules"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		// Might be directly an array
		var direct []ItemInfo
		if json.Unmarshal(out, &direct) == nil {
			return direct, nil
		}
		return nil, err
	}
	return data.Rules, nil
}

// ToggleAppSecRule enables (installs) or disables (removes) one AppSec rule and reloads.
func (t *Target) ToggleAppSecRule(name string, enable bool) error {
	if err := validHubItem("appsec-rules", name); err != nil {
		return err
	}
	t.ClearHubCache()
	action := []string{"appsec-rules", "remove", name, "--force"}
	if enable {
		action = []string{"appsec-rules", "install", name}
	}
	_, err := t.cscli(action...)
	if err == nil {
		t.reloadCrowdsec()
	}
	return err
}

// ToggleVirtualPatchingCollection installs or removes CrowdSec's virtual-patching
// collection (one AppSec rule per known CVE) and reloads.
func (t *Target) ToggleVirtualPatchingCollection(enable bool) error {
	t.ClearHubCache()
	var err error
	if enable {
		_, err = t.cscli("collections", "install", "crowdsecurity/appsec-virtual-patching", "--force")
	} else {
		_, err = t.cscli("collections", "remove", "crowdsecurity/appsec-virtual-patching", "--force")
	}
	if err == nil {
		t.reloadCrowdsec()
	}
	return err
}

// GetScenarios returns active detection scenarios
func (t *Target) GetScenarios() ([]ItemInfo, error) {
	out, err := t.cscli("scenarios", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var data struct {
		Scenarios []ItemInfo `json:"scenarios"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		var direct []ItemInfo
		if json.Unmarshal(out, &direct) == nil {
			return direct, nil
		}
		return nil, err
	}
	return data.Scenarios, nil
}

// GetParsers returns active parsers
func (t *Target) GetParsers() ([]ItemInfo, error) {
	out, err := t.cscli("parsers", "list", "-o", "json")
	if err != nil {
		return nil, err
	}

	var data struct {
		Parsers []ItemInfo `json:"parsers"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		var direct []ItemInfo
		if json.Unmarshal(out, &direct) == nil {
			return direct, nil
		}
		return nil, err
	}
	return data.Parsers, nil
}

// ClearHubCache clears the memory cache of hub items
func (t *Target) ClearHubCache() {
	t.hubCacheMu.Lock()
	defer t.hubCacheMu.Unlock()
	t.hubCache = make(map[string][]ItemInfo)
	t.hubCacheTime = time.Time{}
}

// FetchHubCategory fetches items for a given category (collections, scenarios, parsers, postoverflows, appsec-configs, appsec-rules)
func (t *Target) FetchHubCategory(category string, all bool) ([]ItemInfo, error) {
	cacheKey := fmt.Sprintf("%s_%v", category, all)
	t.hubCacheMu.RLock()
	if items, ok := t.hubCache[cacheKey]; ok && time.Since(t.hubCacheTime) < 2*time.Minute {
		t.hubCacheMu.RUnlock()
		return items, nil
	}
	t.hubCacheMu.RUnlock()

	args := []string{category, "list", "-o", "json"}
	if all {
		args = []string{category, "list", "-a", "-o", "json"}
	}
	out, err := t.cscli(args...)
	if err != nil {
		return nil, err
	}

	var rawMap map[string][]ItemInfo
	var result []ItemInfo
	if err := json.Unmarshal(out, &rawMap); err == nil {
		for _, items := range rawMap {
			result = items
			break
		}
	} else {
		var direct []ItemInfo
		if err := json.Unmarshal(out, &direct); err == nil {
			result = direct
		} else {
			return nil, fmt.Errorf("failed to parse %s json: %v", category, err)
		}
	}

	for i := range result {
		result[i].Type = category
		parts := strings.Split(result[i].Name, "/")
		if len(parts) >= 2 {
			result[i].Author = parts[0]
			result[i].ItemName = parts[1]
		} else {
			result[i].Author = "crowdsecurity"
			result[i].ItemName = result[i].Name
		}
	}

	t.hubCacheMu.Lock()
	t.hubCache[cacheKey] = result
	t.hubCacheTime = time.Now()
	t.hubCacheMu.Unlock()

	return result, nil
}

// GetHubCatalog returns items across one or all categories with total counts
func (t *Target) GetHubCatalog(category string, all bool) ([]ItemInfo, map[string]int, error) {
	categories := []string{"collections", "scenarios", "parsers", "postoverflows", "appsec-configs", "appsec-rules"}
	counts := make(map[string]int)

	if category != "" && category != "all" {
		items, err := t.FetchHubCategory(category, all)
		if err != nil {
			return nil, nil, err
		}
		counts[category] = len(items)
		return items, counts, nil
	}

	// cscli takes a few seconds per category, so list them in parallel.
	results := make([][]ItemInfo, len(categories))
	var wg sync.WaitGroup
	for i, cat := range categories {
		wg.Add(1)
		go func(i int, cat string) {
			defer wg.Done()
			if items, err := t.FetchHubCategory(cat, all); err == nil {
				results[i] = items
			}
		}(i, cat)
	}
	wg.Wait()
	var allItems []ItemInfo
	for i, cat := range categories {
		counts[cat] = len(results[i])
		allItems = append(allItems, results[i]...)
	}
	return allItems, counts, nil
}

func (t *Target) reloadCrowdsec() {
	_, _ = t.gate("action", "reload-crowdsec")
}

// InstallHubItem installs a hub item and reloads CrowdSec.
func (t *Target) InstallHubItem(category, name string) (string, error) {
	if err := validHubItem(category, name); err != nil {
		return "", err
	}
	t.ClearHubCache()
	out, err := t.cscli(category, "install", name)
	if err != nil {
		return "", err
	}
	t.reloadCrowdsec()
	return strings.TrimSpace(string(out)), nil
}

// RemoveHubItem removes a hub item and reloads CrowdSec.
func (t *Target) RemoveHubItem(category, name string) (string, error) {
	if err := validHubItem(category, name); err != nil {
		return "", err
	}
	t.ClearHubCache()
	out, err := t.cscli(category, "remove", name, "--force")
	if err != nil {
		return "", err
	}
	t.reloadCrowdsec()
	return strings.TrimSpace(string(out)), nil
}

// UpgradeHubItem upgrades a hub item and reloads crowdsec
func (t *Target) UpgradeHubItem(category, name string) (string, error) {
	if err := validHubItem(category, name); err != nil {
		return "", err
	}
	t.ClearHubCache()
	out, err := t.cscli(category, "upgrade", name)
	if err != nil {
		return "", err
	}
	t.reloadCrowdsec()
	return strings.TrimSpace(string(out)), nil
}

// GetCollections returns installed collections
func (t *Target) GetCollections() ([]ItemInfo, error) {
	return t.FetchHubCategory("collections", false)
}

// UpdateHub refreshes the hub index, upgrades installed items and reloads.
func (t *Target) UpdateHub() (string, error) {
	t.ClearHubCache()
	outUpdate, err := t.cscli("hub", "update")
	if err != nil {
		return "", err
	}
	outUpgrade, _ := t.cscli("hub", "upgrade")
	t.reloadCrowdsec()
	combined := strings.TrimSpace(string(outUpdate))
	if len(outUpgrade) > 0 {
		combined += "\n" + strings.TrimSpace(string(outUpgrade))
	}
	return combined, nil
}
