package crowdsec

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Routes mounts the CrowdSec management API for the local target.
func Routes(cr chi.Router, t *Target) {
	cr.Get("/info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"target": t, "actions": HostActions, "jobs": HostJobs})
	})
	cr.Post("/host/action", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		out, err := t.HostAction(req.Action)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": out})
	})
	// hostGet serves a read-only host endpoint (policy, failed logins, updates).
	hostGet := func(path string, fn func() (map[string]interface{}, error)) {
		cr.Get(path, func(w http.ResponseWriter, r *http.Request) {
			v, err := fn()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			json.NewEncoder(w).Encode(v)
		})
	}
	hostGet("/host/status", t.HostStatus)
	hostGet("/host/policy", t.HostPolicy)
	hostGet("/host/auth-failures", t.HostAuthFailures)
	hostGet("/host/updates", t.HostUpdates)
	cr.Put("/host/policy", func(w http.ResponseWriter, r *http.Request) {
		var p Policy
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			http.Error(w, "invalid policy: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := p.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := t.ApplyHostPolicy(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(res)
	})
	cr.Post("/host/jobs", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Job string `json:"job"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := t.StartHostJob(req.Job); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "started", "job": req.Job})
	})
	cr.Get("/overview", func(w http.ResponseWriter, r *http.Request) {
		overview, err := t.GetOverview()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(overview)
	})

	cr.Get("/decisions", func(w http.ResponseWriter, r *http.Request) {
		origin := r.URL.Query().Get("origin")
		search := r.URL.Query().Get("search")
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

		decisions, total, err := t.GetDecisions(origin, search, limit, offset)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decisions": decisions,
			"total":     total,
		})
	})

	cr.Post("/decisions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP       string `json:"ip"`
			Duration string `json:"duration"`
			Reason   string `json:"reason"`
			Type     string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg, err := t.AddDecision(req.IP, req.Duration, req.Reason, req.Type)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": msg,
		})
	})

	cr.Delete("/decisions", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		id := r.URL.Query().Get("id")
		msg, err := t.DeleteDecision(ip, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": msg,
		})
	})

	cr.Get("/alerts", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		alerts, err := t.GetAlerts(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(alerts)
	})

	cr.Get("/bouncers", func(w http.ResponseWriter, r *http.Request) {
		bouncers, err := t.GetBouncers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(bouncers)
	})

	cr.Get("/machines", func(w http.ResponseWriter, r *http.Request) {
		machines, err := t.GetMachines()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(machines)
	})

	cr.Post("/machines/prune", func(w http.ResponseWriter, r *http.Request) {
		if err := t.PruneMachines(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		machines, _ := t.GetMachines()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"machines": machines,
			"message":  "Stale machines pruned successfully (inactive >2m & terminated pods)",
		})
	})

	cr.Delete("/machines", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name query parameter required", http.StatusBadRequest)
			return
		}
		if err := t.DeleteMachine(name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		machines, _ := t.GetMachines()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"machines": machines,
			"message":  fmt.Sprintf("Machine %s deleted successfully", name),
		})
	})

	cr.Get("/appsec", func(w http.ResponseWriter, r *http.Request) {
		rules, err := t.GetAppSecRules()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "active",
			"host":   "127.0.0.1:7422",
			"rules":  rules,
		})
	})

	cr.Post("/appsec/toggle", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Rule    string `json:"rule"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := t.ToggleAppSecRule(req.Rule, req.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"rule":    req.Rule,
			"enabled": req.Enabled,
		})
	})

	cr.Post("/appsec/bulk-toggle", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			EnableAll bool `json:"enableAll"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := t.ToggleVirtualPatchingCollection(req.EnableAll); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"enableAll": req.EnableAll,
		})
	})

	cr.Get("/hub", func(w http.ResponseWriter, r *http.Request) {
		category := r.URL.Query().Get("category")
		all := r.URL.Query().Get("all") != "false"
		search := strings.ToLower(r.URL.Query().Get("search"))
		statusFilter := r.URL.Query().Get("status")

		items, counts, err := t.GetHubCatalog(category, all)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		filtered := []ItemInfo{}
		enabledCount := 0
		for _, itm := range items {
			isEnabled := strings.Contains(itm.Status, "enabled")
			if isEnabled {
				enabledCount++
			}
			if statusFilter == "enabled" && !isEnabled {
				continue
			}
			if statusFilter == "disabled" && isEnabled {
				continue
			}
			if search != "" {
				match := strings.Contains(strings.ToLower(itm.Name), search) ||
					strings.Contains(strings.ToLower(itm.Description), search) ||
					strings.Contains(strings.ToLower(itm.Type), search)
				if !match {
					continue
				}
			}
			filtered = append(filtered, itm)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"items":        filtered,
			"total":        len(filtered),
			"totalCatalog": len(items),
			"enabledCount": enabledCount,
			"counts":       counts,
		})
	})

	cr.Post("/hub/install", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Category string `json:"category"`
			Name     string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg, err := t.InstallHubItem(req.Category, req.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": msg,
		})
	})

	cr.Post("/hub/remove", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Category string `json:"category"`
			Name     string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg, err := t.RemoveHubItem(req.Category, req.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": msg,
		})
	})

	cr.Post("/hub/upgrade", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Category string `json:"category"`
			Name     string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg, err := t.UpgradeHubItem(req.Category, req.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": msg,
		})
	})

	cr.Post("/hub/update", func(w http.ResponseWriter, r *http.Request) {
		msg, err := t.UpdateHub()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": msg,
		})
	})

	cr.Get("/whitelists", func(w http.ResponseWriter, r *http.Request) {
		v, err := t.GetWhitelists()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(v)
	})
	// Entries in CowSec's own whitelist parser (never banned).
	cr.Post("/whitelists", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Value  string `json:"value"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := t.AddWhitelistEntry(req.Value, req.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	cr.Delete("/whitelists", func(w http.ResponseWriter, r *http.Request) {
		if err := t.RemoveWhitelistEntry(r.URL.Query().Get("value")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
}
