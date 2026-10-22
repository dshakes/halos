package vendoradmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	maxPages       = 50 // bound on list pagination
)

// ErrStale means the console changed between the confirmed plan and apply.
var ErrStale = errors.New("the console changed since the plan was confirmed; nothing written, re-run `halo admin plan`")

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

// CheckBaseURL accepts an https API base URL, or http only to a loopback
// host (a local fake or proxy): a credential never leaves in clear text.
func CheckBaseURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("API base URL %q is not an absolute URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("API base URL %q must not carry userinfo, a query or a fragment", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("API base URL %q must be https (http only to a loopback host)", raw)
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
	return &Client{Vendor: vendor, BaseURL: strings.TrimRight(base, "/"), Target: t, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: noRedirect}}
}

// noRedirect: a redirect is never followed. net/http would resend the
// Authorization header to the same host over http, or to a subdomain.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// redact removes the token from s.
func (c *Client) redact(s string) string {
	if c.Token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.Token, "[REDACTED]")
}

type statusErr struct{ code int }

func (e statusErr) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

func hasStatus(err error, code int) bool {
	var se statusErr
	return errors.As(err, &se) && se.code == code
}

// do sends one request; out (if non-nil) receives the JSON body. hdr adds
// request headers. It returns the response headers.
func (c *Client) do(ctx context.Context, method, path string, body, out any, hdr ...string) (http.Header, error) {
	if err := CheckBaseURL(c.BaseURL); err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return nil, errors.New(c.redact(err.Error()))
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
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	hc := *c.HTTP // whatever client the caller set, it never follows a redirect
	hc.CheckRedirect = noRedirect
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %s", method, path, c.redact(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("%s %s: read body: %s", method, path, c.redact(err.Error()))
	}
	if resp.StatusCode/100 == 3 {
		return nil, fmt.Errorf("%s %s: %w: the API redirected (to %q); redirects are not followed so the credential is never resent, set the API base URL to the final location",
			method, path, statusErr{resp.StatusCode}, Sanitize(c.redact(resp.Header.Get("Location"))))
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return nil, fmt.Errorf("%s %s: %w: %s", method, path, statusErr{resp.StatusCode}, Sanitize(c.redact(msg)))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return nil, fmt.Errorf("%s %s: decode: %w", method, path, err)
		}
	}
	return resp.Header, nil
}

// Read returns the live values of the settings p desires, keyed like
// Setting.Key, plus conflictsKey when other resources govern the target.
func (c *Client) Read(ctx context.Context, p *Plan) (map[string]any, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("%s: no credential", c.Vendor)
	}
	switch c.Vendor {
	case "gemini":
		return c.geminiRead(ctx, p)
	case "copilot":
		cur, _, err := c.copilotRead(ctx)
		return cur, err
	}
	return nil, fmt.Errorf("%s has no read API", c.Vendor)
}

// Result is the outcome of one change Apply attempted.
type Result struct {
	Change Change `json:"change"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// Apply writes p's writable changes, p being the plan a human confirmed. It
// refuses the whole plan, sending no write, when a writable change loosens,
// a value is forbidden, a conflicting resource governs the target, or a
// fresh read of the console no longer matches the plan (ErrStale). It
// returns one Result per writable change it attempted, in order; a change
// after a failed write is not attempted.
func (c *Client) Apply(ctx context.Context, p *Plan) ([]Result, error) {
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
	if len(p.Conflicts) > 0 {
		return nil, fmt.Errorf("%s: refusing to write: %s also govern %s; reconcile them in the console", c.Vendor, strings.Join(p.Conflicts, ", "), p.Target)
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
	// Re-read and re-diff: the confirmed plan must still describe the console.
	fresh, err := c.Read(ctx, p)
	if err != nil {
		return nil, err
	}
	again := &Plan{Vendor: p.Vendor, Target: p.Target, Desired: p.Desired}
	again.Diff(fresh)
	if !equal(again.Changes, p.Changes) || len(again.Conflicts) > 0 {
		return nil, fmt.Errorf("%s: %w", c.Vendor, ErrStale)
	}
	var res []Result
	switch c.Vendor {
	case "gemini":
		res = c.geminiApply(ctx, w)
	case "copilot":
		res = c.copilotApply(ctx, w)
	default:
		return nil, fmt.Errorf("%s has no write API", c.Vendor)
	}
	// Every writable change gets a result, so the apply record is complete.
	for _, ch := range w {
		if !slices.ContainsFunc(res, func(r Result) bool { return r.Change.Key == ch.Key }) {
			res = append(res, Result{Change: ch, Error: "not attempted: an earlier write failed"})
		}
	}
	return res, nil
}

// results marks changes done OK, the failed one with err, and the rest not attempted.
func results(done []Change, failed *Change, err error) []Result {
	out := make([]Result, 0, len(done)+1)
	for _, ch := range done {
		out = append(out, Result{Change: ch, OK: true})
	}
	if failed != nil {
		out = append(out, Result{Change: *failed, Error: err.Error()})
	}
	return out
}

// ---- Gemini for Google Cloud (cloudaicompanion v1) ----
//
// The settings resources carry no etag (REST reference, checked
// 2026-10-21), so Apply's re-read and re-diff is the only staleness check;
// the window between it and the write is unavoidable.

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

// geminiList pages through a collection, collecting field (an array of
// objects with name and, for bindings, target) per AIP-132.
func (c *Client) geminiList(ctx context.Context, path, field string) ([]map[string]any, error) {
	var all []map[string]any
	token := ""
	for range maxPages {
		q := path
		if token != "" {
			q += "?pageToken=" + url.QueryEscape(token)
		}
		var page map[string]any
		if _, err := c.do(ctx, http.MethodGet, q, nil, &page); err != nil {
			return nil, err
		}
		items, _ := page[field].([]any)
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				all = append(all, m)
			}
		}
		token, _ = page["nextPageToken"].(string)
		if token == "" {
			return all, nil
		}
	}
	return nil, fmt.Errorf("GET %s: more than %d pages", path, maxPages)
}

func (c *Client) geminiRead(ctx context.Context, p *Plan) (map[string]any, error) {
	keys := make([]string, len(p.Desired))
	for i, s := range p.Desired {
		keys[i] = s.Key
	}
	target := "projects/" + c.Target.Project
	cur := map[string]any{}
	var conflicts []string
	for _, kind := range kindsOf(keys) {
		parent := c.geminiParent() + "/" + kind
		// other settings of this kind bound to the same target govern it too
		settings, err := c.geminiList(ctx, parent, kind)
		if err != nil {
			return nil, fmt.Errorf("gemini: %w", err)
		}
		for _, s := range settings {
			name, _ := s["name"].(string)
			if name == "" || strings.HasSuffix(name, "/"+kind+"/"+settingID) {
				continue
			}
			id := name[strings.LastIndex(name, "/")+1:]
			bindings, err := c.geminiList(ctx, parent+"/"+url.PathEscape(id)+"/settingBindings", "settingBindings")
			if err != nil {
				return nil, fmt.Errorf("gemini: %w", err)
			}
			for _, b := range bindings {
				if b["target"] == target {
					conflicts = append(conflicts, Sanitize(name))
				}
			}
		}
		var res map[string]any
		_, err = c.do(ctx, http.MethodGet, parent+"/"+settingID, nil, &res)
		if hasStatus(err, http.StatusNotFound) {
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
		_, err = c.do(ctx, http.MethodGet, parent+"/"+settingID+"/settingBindings/"+settingID, nil, &b)
		if err != nil && !hasStatus(err, http.StatusNotFound) {
			return nil, fmt.Errorf("gemini: %w", err)
		}
		if b.Target != "" {
			cur[geminiKey(kind, "binding")] = b.Target
		}
	}
	if len(conflicts) > 0 {
		cur[conflictsKey] = conflicts
	}
	return cur, nil
}

func (c *Client) geminiApply(ctx context.Context, w []Change) []Result {
	keys := make([]string, len(w))
	for i, ch := range w {
		keys[i] = ch.Key
	}
	var done []Change
	for _, kind := range kindsOf(keys) {
		base := c.geminiParent() + "/" + kind
		body, mask, fields, created := map[string]any{}, []string{}, []Change{}, true
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
			body[field], mask, fields = ch.Desired, append(mask, field), append(fields, ch)
			if ch.Current != nil {
				created = false
			}
		}
		if len(mask) > 0 {
			var err error
			if created {
				// a missing setting: create it with every desired field
				_, err = c.do(ctx, http.MethodPost, base+"?"+geminiKinds[kind].idArg+"="+settingID, body, nil)
			} else {
				slices.Sort(mask)
				_, err = c.do(ctx, http.MethodPatch, base+"/"+settingID+"?updateMask="+strings.Join(mask, ","), body, nil)
			}
			if err != nil {
				out := results(done, &fields[0], fmt.Errorf("gemini: %w", err))
				for _, f := range fields[1:] {
					out = append(out, Result{Change: f, Error: "not written: same request as " + fields[0].Key})
				}
				return out
			}
			done = append(done, fields...)
		}
		if binding != nil {
			bb := map[string]any{"target": binding.Desired, "product": codeAssistProd}
			// Apply refuses a rebind (Sticky), so a binding change is always a create.
			_, err := c.do(ctx, http.MethodPost, base+"/"+settingID+"/settingBindings?setting_binding_id="+settingID, bb, nil)
			if err != nil {
				return results(done, binding, fmt.Errorf("gemini: %w", err))
			}
			done = append(done, *binding)
		}
	}
	return results(done, nil, nil)
}

// ---- GitHub Copilot (REST, org scope) ----

const exclusionKey = "content_exclusion.*"

func (c *Client) copilotOrg() string { return "/orgs/" + url.PathEscape(c.Target.Org) + "/copilot" }

// copilotExclusions reads the org content exclusion map and its ETag ("" when
// GitHub sends none).
func (c *Client) copilotExclusions(ctx context.Context) (map[string]any, string, error) {
	m := map[string]any{}
	h, err := c.do(ctx, http.MethodGet, c.copilotOrg()+"/content_exclusion", nil, &m)
	if err != nil {
		return nil, "", fmt.Errorf("copilot: %w", err)
	}
	return m, h.Get("ETag"), nil
}

// normalizeAll is the "*" list as Diff compares it: its string entries sorted,
// then every other entry (an {"if-any-match": [...]} rule) in live order.
func normalizeAll(v any) (any, bool) {
	all, ok := v.([]any)
	if !ok {
		return nil, false
	}
	var strs []string
	for _, e := range all {
		if s, ok := e.(string); ok {
			strs = append(strs, s)
		}
	}
	return MergeList(strs, all), true
}

func (c *Client) copilotRead(ctx context.Context) (map[string]any, string, error) {
	cur := map[string]any{}
	ex, etag, err := c.copilotExclusions(ctx)
	if err != nil {
		return nil, "", err
	}
	if all, ok := normalizeAll(ex["*"]); ok {
		cur[exclusionKey] = all
	}
	var billing struct {
		CLI string `json:"cli"`
	}
	if _, err := c.do(ctx, http.MethodGet, c.copilotOrg()+"/billing", nil, &billing); err != nil {
		return nil, "", fmt.Errorf("copilot: %w", err)
	}
	if billing.CLI != "" && billing.CLI != "unconfigured" {
		cur["billing.cli"] = billing.CLI
	}
	return cur, etag, nil
}

// copilotApply PUTs the org's content exclusion map with the "*" entry
// replaced and every other repository's rules preserved as read. Immediately
// before the PUT it re-reads the map and aborts if "*" is no longer what the
// confirmed plan saw; when GitHub returns an ETag the PUT is conditional on it.
func (c *Client) copilotApply(ctx context.Context, w []Change) []Result {
	// content exclusion "*" is Copilot's only writable key
	if len(w) != 1 || w[0].Key != exclusionKey {
		return results(nil, &w[0], fmt.Errorf("copilot: only %s is writable", exclusionKey))
	}
	ch := &w[0]
	ex, etag, err := c.copilotExclusions(ctx)
	if err != nil {
		return results(nil, ch, err)
	}
	if live, _ := normalizeAll(ex["*"]); !equal(live, ch.Current) {
		return results(nil, ch, fmt.Errorf("copilot: %w", ErrStale))
	}
	ex["*"] = ch.Desired
	var hdr []string
	if etag != "" {
		hdr = []string{"If-Match", etag}
	}
	if _, err := c.do(ctx, http.MethodPut, c.copilotOrg()+"/content_exclusion", ex, nil, hdr...); err != nil {
		if hasStatus(err, http.StatusPreconditionFailed) {
			err = ErrStale
		}
		return results(nil, ch, fmt.Errorf("copilot: %w", err))
	}
	return results([]Change{*ch}, nil, nil)
}

// Cred is one vendor's credential and API base URL ("" = the vendor's).
type Cred struct {
	Token   string
	BaseURL string
}

// TokenEnv is the environment variable `halo admin` reads a vendor's
// credential from by default.
func TokenEnv(vendor string) string { return "HALO_ADMIN_" + strings.ToUpper(vendor) + "_TOKEN" }

// MCPTokenEnv is the environment variable the MCP admin_plan tool reads (only
// with `halo mcp serve --admin-read`). It differs from TokenEnv so a CLI
// admin token in a shell profile is never picked up by an agent's server.
func MCPTokenEnv(vendor string) string { return "HALO_MCP_ADMIN_" + strings.ToUpper(vendor) + "_TOKEN" }

// Clients returns the API client for each vendor in r that has one, keyed by
// vendor. A base URL that is not https (or loopback http) is an error.
func (r *Report) Clients(targets map[string]policy.VendorTarget, creds map[string]Cred) (map[string]*Client, error) {
	out := map[string]*Client{}
	for _, p := range r.Vendors {
		if !p.HasAPI() {
			continue
		}
		cr := creds[p.Vendor]
		if err := CheckBaseURL(cr.BaseURL); err != nil {
			return nil, fmt.Errorf("%s: %w", p.Vendor, err)
		}
		if c := NewClient(p.Vendor, cr.BaseURL, cr.Token, targets[p.Vendor]); c != nil {
			out[p.Vendor] = c
		}
	}
	return out, nil
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
// that cannot be read gets Plan.Error (never a credential in it). hint names
// where the credential comes from, for the error.
func (r *Report) ReadLive(ctx context.Context, clients map[string]*Client, hint func(vendor string) string) {
	for _, p := range r.Vendors {
		c := clients[p.Vendor]
		if c == nil {
			continue
		}
		if c.Token == "" {
			p.Error = "no credential: " + hint(p.Vendor)
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
