// Package mailcow manages mailcow-dockerized through its REST API: domains, mailboxes,
// aliases, DKIM, quarantine, the mail queue, status and logs. CowSec only exposes the
// explicit, validated operations below; the browser can never send arbitrary API calls.
//
// The API key is mailcow's read-write key (API_KEY in mailcow.conf), restricted with
// API_ALLOW_FROM to localhost and mailcow's Docker gateway. CowSec reads it from
// /etc/cowsec/mailcow.env (root only), written by `cowsec-setup mailcow-api`.
package mailcow

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client talks to mailcow's API on this host.
type Client struct {
	base string // https://127.0.0.1:<port>
	host string // MAILCOW_HOSTNAME (sent as Host and TLS server name)
	key  string
	http *http.Client
	gate func(verb string, args ...string) ([]byte, error) // host helper, for what mailcow's API can't read
}

// FromEnv returns a client, or nil when the mailcow API has not been configured.
func FromEnv() *Client {
	key := strings.TrimSpace(os.Getenv("COWSEC_MAILCOW_API_KEY"))
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("COWSEC_MAILCOW_URL")), "/")
	if key == "" || base == "" {
		return nil
	}
	host := strings.TrimSpace(os.Getenv("COWSEC_MAILCOW_HOST"))
	tr := &http.Transport{
		// Loopback to mailcow's own nginx, which presents the public certificate for its
		// hostname; the connection never leaves the machine.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec
	}
	return &Client{base: base, host: host, key: key, http: &http.Client{Timeout: 60 * time.Second, Transport: tr}}
}

func (c *Client) do(method, path string, body interface{}) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+"/api/v1/"+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.host != "" {
		req.Host = c.host
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mailcow API unreachable: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("mailcow refused the API key (check API_KEY / API_ALLOW_FROM in mailcow.conf)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("mailcow API error %d: %s", resp.StatusCode, strings.TrimSpace(string(data[:min(len(data), 300)])))
	}
	return data, nil
}

// Get returns a GET result. Lists are normalised: mailcow answers an empty list with {}.
func (c *Client) Get(path string) (json.RawMessage, error) {
	return c.do(http.MethodGet, path, nil)
}

// List returns a GET result that should be a JSON array.
func (c *Client) List(path string) (json.RawMessage, error) {
	data, err := c.Get(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	switch {
	case len(trimmed) == 0, bytes.Equal(trimmed, []byte("{}")), bytes.Equal(trimmed, []byte("null")):
		return json.RawMessage("[]"), nil
	case trimmed[0] == '{':
		return json.RawMessage("[" + string(trimmed) + "]"), nil
	}
	return data, nil
}

// Result is one entry of mailcow's response to add/edit/delete calls.
type Result struct {
	Type string      `json:"type"`
	Msg  interface{} `json:"msg"`
}

// Change runs an add/edit/delete call and turns mailcow's result list into an error
// when any entry is not a success.
func (c *Client) Change(path string, body interface{}) ([]string, error) {
	data, err := c.do(http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	var results []Result
	if json.Unmarshal(data, &results) != nil {
		var one Result
		if json.Unmarshal(data, &one) != nil {
			return nil, fmt.Errorf("unexpected mailcow response: %s", strings.TrimSpace(string(data[:min(len(data), 200)])))
		}
		results = []Result{one}
	}
	var msgs, errs []string
	for _, r := range results {
		m := message(r.Msg)
		if r.Type == "success" || r.Type == "info" {
			msgs = append(msgs, m)
		} else {
			errs = append(errs, m)
		}
	}
	if len(errs) > 0 {
		return msgs, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return msgs, nil
}

// message flattens mailcow's msg field (a string or [key, args...]) into readable text.
func message(v interface{}) string {
	switch m := v.(type) {
	case string:
		return strings.ReplaceAll(m, "_", " ")
	case []interface{}:
		parts := make([]string, 0, len(m))
		for i, p := range m {
			s := fmt.Sprint(p)
			if i == 0 {
				s = strings.ReplaceAll(s, "_", " ")
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ": ")
	}
	b, _ := json.Marshal(v)
	return string(b)
}
