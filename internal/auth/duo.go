package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DuoConfig is a Duo "Auth API" application (COWSEC_DUO_*). Give CowSec its own
// application so it can be revoked without affecting anything else.
type DuoConfig struct {
	Host string // api-xxxxxxxx.duosecurity.com
	IKey string
	SKey string
}

func (c DuoConfig) Enabled() bool { return c.Host != "" && c.IKey != "" && c.SKey != "" }

type duoResponse struct {
	Stat     string          `json:"stat"`
	Message  string          `json:"message"`
	Response json.RawMessage `json:"response"`
}

// duoEscape matches Duo's canonicalisation (RFC 3986, spaces as %20).
func duoEscape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

func (c DuoConfig) call(method, path string, params map[string]string, timeout time.Duration) (json.RawMessage, error) {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, duoEscape(k)+"="+duoEscape(params[k]))
	}
	body := strings.Join(parts, "&")
	date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0000")
	canon := strings.Join([]string{date, strings.ToUpper(method), strings.ToLower(c.Host), path, body}, "\n")
	mac := hmac.New(sha1.New, []byte(c.SKey))
	mac.Write([]byte(canon))
	authz := base64.StdEncoding.EncodeToString([]byte(c.IKey + ":" + hex.EncodeToString(mac.Sum(nil))))

	u := "https://" + c.Host + path
	var req *http.Request
	var err error
	if method == http.MethodGet {
		req, err = http.NewRequest(method, u+"?"+body, nil)
	} else {
		req, err = http.NewRequest(method, u, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", "Basic "+authz)
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("Duo unreachable: %w", err)
	}
	defer resp.Body.Close()
	var dr duoResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, fmt.Errorf("Duo response: %w", err)
	}
	if dr.Stat != "OK" {
		return nil, fmt.Errorf("Duo error: %s", dr.Message)
	}
	return dr.Response, nil
}

// duoPreauth reports whether Duo will let this user authenticate ("auth"),
// bypass ("allow"), refuse ("deny") or needs enrolment ("enroll").
func (c DuoConfig) duoPreauth(user string) (string, string, error) {
	raw, err := c.call(http.MethodPost, "/auth/v2/preauth", map[string]string{"username": user}, 10*time.Second)
	if err != nil {
		return "", "", err
	}
	var r struct {
		Result    string `json:"result"`
		StatusMsg string `json:"status_msg"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.Result, r.StatusMsg, nil
}

// duoPush sends a push and blocks until it is approved, denied or times out.
func (c DuoConfig) duoPush(user, ip string) (bool, string, error) {
	params := map[string]string{"username": user, "factor": "push", "device": "auto", "pushinfo": url.Values{"service": {"CowSec"}}.Encode()}
	if ip != "" {
		params["ipaddr"] = ip
	}
	raw, err := c.call(http.MethodPost, "/auth/v2/auth", params, 75*time.Second)
	if err != nil {
		return false, "", err
	}
	var r struct {
		Result    string `json:"result"`
		StatusMsg string `json:"status_msg"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.Result == "allow", r.StatusMsg, nil
}
