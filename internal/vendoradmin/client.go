package vendoradmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Default API base URLs.
const (
	GeminiBaseURL  = "https://cloudaicompanion.googleapis.com"
	GitHubBaseURL  = "https://api.github.com"
	githubVersion  = "2026-03-10" // X-GitHub-Api-Version on the Copilot REST pages (checked 2026-10-21)
	codeAssistProd = "GEMINI_CODE_ASSIST"
	maxBody        = 1 << 20
)

// Client reads and writes one vendor's console through its public API.
type Client struct {
	Vendor  string
	BaseURL string
	Target  policy.VendorTarget
	// Token is the bearer credential. It is sent only in the Authorization
	// header and scrubbed from every error.
	Token string
	HTTP  *http.Client
}

// NewClient returns the API client for vendor, or nil when it has no public
// read API (claude, codex, cursor: see ADR-0025). base "" uses the vendor's.
func NewClient(vendor, base, token string, t policy.VendorTarget) *Client {
	def := map[string]string{"gemini": GeminiBaseURL, "copilot": GitHubBaseURL}[vendor]
	if def == "" {
		return nil
	}
	if base == "" {
		base = def
	}
	return &Client{Vendor: vendor, BaseURL: strings.TrimRight(base, "/"), Target: t, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// redact removes the token from s.
func (c *Client) redact(s string) string {
	if c.Token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.Token, "[REDACTED]")
}

type statusErr struct{ code int }

func (e statusErr) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

// do sends one request; out (if non-nil) receives the JSON body.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return errors.New(c.redact(err.Error()))
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Vendor == "copilot" {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", githubVersion)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %s", method, path, c.redact(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("%s %s: read body: %s", method, path, c.redact(err.Error()))
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return fmt.Errorf("%s %s: %w: %s", method, path, statusErr{resp.StatusCode}, c.redact(msg))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%s %s: decode: %w", method, path, err)
		}
	}
	return nil
}

func notFound(err error) bool {
	var se statusErr
	return errors.As(err, &se) && se.code == http.StatusNotFound
}

// Read returns the live values of the settings p desires, keyed like Setting.Key.
func (c *Client) Read(ctx context.Context, p *Plan) (map[string]any, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("%s: no credential", c.Vendor)
	}
	switch c.Vendor {
	case "gemini":
		return c.geminiRead(ctx, p)
	case "copilot":
		return c.copilotRead(ctx)
	}
	return nil, fmt.Errorf("%s has no read API", c.Vendor)
}

// Apply writes p's writable changes. It refuses the whole plan when any
// change is a loosening, is not writable, or would emit a forbidden value;
// nothing is sent then.
func (c *Client) Apply(ctx context.Context, p *Plan) ([]Change, error) {
	if err := p.CheckForbidden(); err != nil {
		return nil, err
	}
	if l := p.Loosenings(); len(l) > 0 {
		keys := make([]string, len(l))
		for i, ch := range l {
			keys[i] = ch.Key
		}
		return nil, fmt.Errorf("%s: refusing to loosen %s; a human changes that in the console", c.Vendor, strings.Join(keys, ", "))
	}
	var w []Change
	for _, ch := range p.Changes {
		if ch.Access == AccessWrite {
			w = append(w, ch)
		}
	}
	if len(w) == 0 {
		return nil, nil
	}
	if c.Token == "" {
		return nil, fmt.Errorf("%s: no credential", c.Vendor)
	}
	switch c.Vendor {
	case "gemini":
		return w, c.geminiApply(ctx, w)
	case "copilot":
		return w, c.copilotApply(ctx, w)
	}
	return nil, fmt.Errorf("%s has no write API", c.Vendor)
}

// ---- Gemini for Google Cloud (cloudaicompanion v1) ----

// geminiKinds maps a settings collection to its documented fields and the
// create-id query parameter.
var geminiKinds = map[string]struct {
	fields []string
	idArg  string
}{
	"loggingSettings":        {[]string{"logMetadata", "logPromptsAndResponses"}, "logging_setting_id"},
	"releaseChannelSettings": {[]string{"releaseChannel"}, "release_channel_setting_id"},
}

func (c *Client) geminiParent() string {
	return fmt.Sprintf("/v1/projects/%s/locations/%s", url.PathEscape(c.Target.Project), url.PathEscape(c.Target.GeminiLocation()))
}

func kindsOf(keys []string) []string {
	var out []string
	for _, k := range keys {
		kind, _, _ := strings.Cut(k, "/")
		if _, ok := geminiKinds[kind]; ok && !slices.Contains(out, kind) {
			out = append(out, kind)
		}
	}
	slices.Sort(out)
	return out
}

func (c *Client) geminiRead(ctx context.Context, p *Plan) (map[string]any, error) {
	keys := make([]string, len(p.Desired))
	for i, s := range p.Desired {
		keys[i] = s.Key
	}
	cur := map[string]any{}
	for _, kind := range kindsOf(keys) {
		base := c.geminiParent() + "/" + kind + "/" + settingID
		var res map[string]any
		err := c.do(ctx, http.MethodGet, base, nil, &res)
		if notFound(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("gemini: %w", err)
		}
		for _, f := range geminiKinds[kind].fields {
			v, ok := res[f]
			if !ok { // proto3 JSON omits default values
				v = false
				if f == "releaseChannel" {
					v = "CHANNEL_TYPE_UNSPECIFIED"
				}
			}
			cur[geminiKey(kind, f)] = v
		}
		var b struct {
			Target string `json:"target"`
		}
		err = c.do(ctx, http.MethodGet, base+"/settingBindings/"+settingID, nil, &b)
		if err != nil && !notFound(err) {
			return nil, fmt.Errorf("gemini: %w", err)
		}
		if b.Target != "" {
			cur[geminiKey(kind, "binding")] = b.Target
		}
	}
	return cur, nil
}

func (c *Client) geminiApply(ctx context.Context, w []Change) error {
	keys := make([]string, len(w))
	for i, ch := range w {
		keys[i] = ch.Key
	}
	for _, kind := range kindsOf(keys) {
		base := c.geminiParent() + "/" + kind
		body, mask, created := map[string]any{}, []string{}, true
		var binding *Change
		for i, ch := range w {
			field, ok := strings.CutPrefix(ch.Key, kind+"/"+settingID+".")
			if !ok {
				continue
			}
			if field == "binding" {
				binding = &w[i]
				continue
			}
			body[field], mask = ch.Desired, append(mask, field)
			if ch.Current != nil {
				created = false
			}
		}
		if len(mask) > 0 {
			var err error
			if created {
				// a missing setting: create it with every desired field
				err = c.do(ctx, http.MethodPost, base+"?"+geminiKinds[kind].idArg+"="+settingID, body, nil)
			} else {
				slices.Sort(mask)
				err = c.do(ctx, http.MethodPatch, base+"/"+settingID+"?updateMask="+strings.Join(mask, ","), body, nil)
			}
			if err != nil {
				return fmt.Errorf("gemini: %w", err)
			}
		}
		if binding != nil {
			bb := map[string]any{"target": binding.Desired, "product": codeAssistProd}
			var err error
			if binding.Current == nil {
				err = c.do(ctx, http.MethodPost, base+"/"+settingID+"/settingBindings?setting_binding_id="+settingID, bb, nil)
			} else {
				err = c.do(ctx, http.MethodPatch, base+"/"+settingID+"/settingBindings/"+settingID+"?updateMask=product,target", bb, nil)
			}
			if err != nil {
				return fmt.Errorf("gemini: %w", err)
			}
		}
	}
	return nil
}

// ---- GitHub Copilot (REST, org scope) ----

func (c *Client) copilotOrg() string { return "/orgs/" + url.PathEscape(c.Target.Org) + "/copilot" }

func (c *Client) copilotExclusions(ctx context.Context) (map[string]any, error) {
	m := map[string]any{}
	if err := c.do(ctx, http.MethodGet, c.copilotOrg()+"/content_exclusion", nil, &m); err != nil {
		return nil, fmt.Errorf("copilot: %w", err)
	}
	return m, nil
}

func (c *Client) copilotRead(ctx context.Context) (map[string]any, error) {
	cur := map[string]any{}
	ex, err := c.copilotExclusions(ctx)
	if err != nil {
		return nil, err
	}
	if all, ok := ex["*"].([]any); ok {
		var globs []string
		for _, g := range all {
			if s, ok := g.(string); ok {
				globs = append(globs, s)
			}
		}
		slices.Sort(globs)
		cur["content_exclusion.*"] = globs
	}
	var billing struct {
		CLI string `json:"cli"`
	}
	if err := c.do(ctx, http.MethodGet, c.copilotOrg()+"/billing", nil, &billing); err != nil {
		return nil, fmt.Errorf("copilot: %w", err)
	}
	if billing.CLI != "" && billing.CLI != "unconfigured" {
		cur["billing.cli"] = billing.CLI
	}
	return cur, nil
}

// copilotApply PUTs the org's content exclusion map with the "*" entry
// replaced and every other repository's rules preserved as read.
func (c *Client) copilotApply(ctx context.Context, w []Change) error {
	for _, ch := range w {
		if ch.Key != "content_exclusion.*" {
			return fmt.Errorf("copilot: %s is not writable", ch.Key)
		}
		ex, err := c.copilotExclusions(ctx)
		if err != nil {
			return err
		}
		ex["*"] = ch.Desired
		if err := c.do(ctx, http.MethodPut, c.copilotOrg()+"/content_exclusion", ex, nil); err != nil {
			return fmt.Errorf("copilot: %w", err)
		}
	}
	return nil
}

// Cred is one vendor's credential and API base URL ("" = the vendor's).
type Cred struct {
	Token   string
	BaseURL string
}

// TokenEnv is the environment variable halo admin and the MCP admin_plan tool
// read a vendor's credential from by default.
func TokenEnv(vendor string) string { return "HALO_ADMIN_" + strings.ToUpper(vendor) + "_TOKEN" }

// Clients returns the API client for each vendor in r that has one, keyed by vendor.
func (r *Report) Clients(targets map[string]policy.VendorTarget, creds map[string]Cred) map[string]*Client {
	out := map[string]*Client{}
	for _, p := range r.Vendors {
		if !p.HasAPI() {
			continue
		}
		cr := creds[p.Vendor]
		if c := NewClient(p.Vendor, cr.BaseURL, cr.Token, targets[p.Vendor]); c != nil {
			out[p.Vendor] = c
		}
	}
	return out
}

// Targets maps each vendor name to its configured target.
func Targets(va *policy.VendorAdmin) map[string]policy.VendorTarget {
	out := map[string]policy.VendorTarget{}
	for _, v := range registry {
		if t := v.target(va); t != nil {
			out[v.name] = *t
		}
	}
	return out
}

// ReadLive reads and diffs every vendor that has an API client. A vendor
// that cannot be read gets Plan.Error (never a credential in it).
func (r *Report) ReadLive(ctx context.Context, clients map[string]*Client) {
	for _, p := range r.Vendors {
		c := clients[p.Vendor]
		if c == nil {
			continue
		}
		if c.Token == "" {
			p.Error = fmt.Sprintf("no credential: set %s or pass --%s-token-file", TokenEnv(p.Vendor), p.Vendor)
			continue
		}
		cur, err := c.Read(ctx, p)
		if err != nil {
			p.Error = err.Error()
			continue
		}
		p.Diff(cur)
	}
}

// Errors lists the vendors whose live state could not be read.
func (r *Report) Errors() []string {
	var out []string
	for _, p := range r.Vendors {
		if p.Error != "" {
			out = append(out, p.Vendor+": "+p.Error)
		}
	}
	return out
}
