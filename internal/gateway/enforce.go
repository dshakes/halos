package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Gates the traffic plane applies per ring (policy Ring.Posture / Ring.VersionGate).
const (
	GatePosture = "posture"
	GateVersion = "version"
)

// Finding is a failed gate check under a ring whose mode is warn or enforce.
type Finding struct {
	Gate   string // GatePosture | GateVersion
	Mode   string // policy.GateWarn | policy.GateEnforce
	Reason string
}

// Message is what the developer's CLI shows on a refusal: what failed and what to run.
func (f *Finding) Message() string {
	if f.Gate == GatePosture {
		return "halos: device posture check failed (" + f.Reason + "). Run `halod status` on this machine, make sure halod is running and has applied your ring's release, then retry."
	}
	return "halos: CLI version check failed (" + f.Reason + "). Install the version your ring pins (`halod status` shows it; halod installs it on its next run), then retry."
}

// Reject is the 403 to answer in enforce mode, in the caller's wire format; nil in warn mode.
func (f *Finding) Reject(proto string) *Rejection {
	if f == nil || f.Mode != policy.GateEnforce {
		return nil
	}
	return &Rejection{Status: http.StatusForbidden, Protocol: proto, Message: f.Message(), Code: f.Gate + "_check_failed"}
}

func findRing(org *policy.Org, name string) *policy.Ring {
	if org == nil {
		return nil
	}
	for _, r := range org.Rings {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// RingGate is ring's mode for gate (GatePosture or GateVersion); off when the ring is unknown.
func RingGate(org *policy.Org, ring, gate string) string {
	r := findRing(org, ring)
	if r == nil {
		return policy.GateOff
	}
	if gate == GatePosture {
		return policy.GateMode(r.Posture)
	}
	return policy.GateMode(r.VersionGate)
}

var uaVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$`)

// ParseUA returns the harness and CLI version a User-Agent names. The formats
// (sources in docs/adr/0011-gateway-enforced-posture-and-version.md):
//
//	claude-cli/2.1.287 (external, sdk-cli)               Claude Code
//	codex_cli_rs/0.99.0 (Mac OS 15.1.0; arm64) iTerm.app  Codex (originator/version (os; arch) terminal)
//	GeminiCLI/0.26.0/gemini-2.5-pro (darwin; x64)        Gemini CLI (GeminiCLI[-client]/version/model (platform; arch[; surface]))
//
// The version is the token after the first '/', up to a space, '/', '(' or ';'.
// version is "" when the harness is known but no semver follows; harness is ""
// for an unrecognised UA (Copilot CLI's is not documented and has none).
func ParseUA(ua string) (harness, version string) {
	harness = HarnessFromUA(ua)
	if harness == "" {
		return "", ""
	}
	_, rest, ok := strings.Cut(ua, "/")
	if !ok {
		return harness, ""
	}
	if i := strings.IndexAny(rest, " /(;"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimPrefix(rest, "v")
	if !uaVersionRe.MatchString(rest) {
		return harness, ""
	}
	return harness, rest
}

// pinCache memoises ring -> harness -> pinned versions for the current policy
// snapshot (a snapshot reload is a new *Org).
var pinCache struct {
	mu   sync.Mutex
	org  *policy.Org
	pins map[string]map[string][]string
}

// RingPins returns the CLI versions ring r's devices may run per harness: the
// ring profile's pin plus the variant profiles of its running client-axis
// experiment (the gateway cannot tell which variant a device applied).
func RingPins(org *policy.Org, ring string) map[string][]string {
	pinCache.mu.Lock()
	defer pinCache.mu.Unlock()
	if pinCache.org != org {
		pinCache.org, pinCache.pins = org, map[string]map[string][]string{}
	}
	if p, ok := pinCache.pins[ring]; ok {
		return p
	}
	out := map[string][]string{}
	add := func(profile string) {
		p, err := org.ResolveProfile(profile)
		if err != nil {
			return
		}
		for h, spec := range p.Harnesses {
			if spec.Version != "" && !slices.Contains(out[h], spec.Version) {
				out[h] = append(out[h], spec.Version)
			}
		}
	}
	if r := findRing(org, ring); r != nil {
		add(r.Profile)
		for _, e := range org.ClientExperiments(ring) {
			for _, v := range e.Variants {
				if v.Profile != "" {
					add(v.Profile)
				}
			}
		}
	}
	for _, v := range out {
		sort.Strings(v)
	}
	pinCache.pins[ring] = out
	return out
}

// CheckVersion applies ring's versionGate to a request's User-Agent. nil = pass
// (or gate off). A ring that pins no version for the detected harness passes:
// there is nothing to compare against.
func CheckVersion(org *policy.Org, ring, ua string) *Finding {
	mode := RingGate(org, ring, GateVersion)
	if mode == policy.GateOff {
		return nil
	}
	h, ver := ParseUA(ua)
	if h == "" {
		return &Finding{Gate: GateVersion, Mode: mode, Reason: "unrecognised or missing User-Agent"}
	}
	pins := RingPins(org, ring)[h]
	if len(pins) == 0 {
		return nil
	}
	if ver == "" {
		return &Finding{Gate: GateVersion, Mode: mode, Reason: h + " User-Agent carries no version"}
	}
	if slices.Contains(pins, ver) {
		return nil
	}
	return &Finding{Gate: GateVersion, Mode: mode, Reason: fmt.Sprintf("%s %s; ring %s pins %s", h, ver, ring, strings.Join(pins, " or "))}
}

// PostureVerdict is halo-server's answer for one subject (GET /api/v1/gateway/posture).
type PostureVerdict struct {
	Compliant bool   `json:"compliant"`
	Reason    string `json:"reason,omitempty"`
}

// Posture defaults.
const (
	DefaultPostureTTL   = time.Minute      // a verdict is reused this long before halo-server is asked again
	DefaultPostureGrace = 15 * time.Minute // a cached verdict outlives an unreachable halo-server this long
	maxPostureEntries   = 100_000
	maxPostureBody      = 4 << 10
)

// PostureClient asks halo-server for a subject's device posture and caches the
// verdict. It fails closed only on a verdict halo-server returned: when the
// server cannot be reached, the last verdict serves for Grace, and after that
// the posture is unknown (callers let the request through and count it).
type PostureClient struct {
	URL, Token string
	TTL, Grace time.Duration
	Client     *http.Client
	Now        func() time.Time
	Log        *slog.Logger

	mu    sync.Mutex
	cache map[string]postureEntry
}

type postureEntry struct {
	v  PostureVerdict
	at time.Time
}

// NewPostureClient validates the config (https unless loopback or allowInsecureInCluster).
func NewPostureClient(url, token string, ttl, grace time.Duration, log *slog.Logger, allowInsecureInCluster bool) (*PostureClient, error) {
	if url == "" || token == "" {
		return nil, errors.New("gateway: posture needs url and token")
	}
	if err := checkKillURL(url, allowInsecureInCluster); err != nil {
		return nil, fmt.Errorf("gateway: posture url: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultPostureTTL
	}
	if grace <= 0 {
		grace = DefaultPostureGrace
	}
	return &PostureClient{URL: url, Token: token, TTL: ttl, Grace: grace, Log: log}, nil
}

func (c *PostureClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Check returns subject's verdict; known=false when halo-server could not be
// asked and no verdict younger than Grace is cached.
// ponytail: concurrent misses for one subject each call halo-server; add
// singleflight if a burst after TTL expiry shows up in the server's load.
func (c *PostureClient) Check(ctx context.Context, subject string) (v PostureVerdict, known bool) {
	now := c.now()
	c.mu.Lock()
	e, ok := c.cache[subject]
	c.mu.Unlock()
	if ok && now.Sub(e.at) < c.TTL {
		return e.v, true
	}
	got, err := c.fetch(ctx, subject)
	if err != nil {
		if c.Log != nil {
			c.Log.Warn("posture lookup failed", "err", err, "cached", ok && now.Sub(e.at) < c.Grace)
		}
		if ok && now.Sub(e.at) < c.Grace {
			return e.v, true
		}
		return PostureVerdict{}, false
	}
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]postureEntry{}
	}
	if len(c.cache) >= maxPostureEntries {
		for k, old := range c.cache { // ponytail: O(n) sweep when full; an LRU if 100k subjects is routine
			if now.Sub(old.at) >= c.Grace {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= maxPostureEntries {
			clear(c.cache)
		}
	}
	c.cache[subject] = postureEntry{v: got, at: now}
	c.mu.Unlock()
	return got, true
}

func (c *PostureClient) fetch(ctx context.Context, subject string) (PostureVerdict, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u := c.URL + "?" + url.Values{"subject": {subject}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return PostureVerdict{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	hc := c.Client
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return PostureVerdict{}, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response
	if resp.StatusCode != http.StatusOK {
		return PostureVerdict{}, fmt.Errorf("posture: HTTP %d", resp.StatusCode)
	}
	var v PostureVerdict
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPostureBody)).Decode(&v); err != nil {
		return PostureVerdict{}, fmt.Errorf("posture: decode: %w", err)
	}
	return v, nil
}

// CheckPosture applies ring's posture gate to a verified subject. unknown
// reports that the gate is on but no verdict was available (no client, an
// anonymous caller, or halo-server unreachable past the grace window): the
// request passes and callers count it.
func CheckPosture(ctx context.Context, c *PostureClient, org *policy.Org, ring string, sub *policy.Subject) (f *Finding, unknown bool) {
	mode := RingGate(org, ring, GatePosture)
	if mode == policy.GateOff || c == nil {
		return nil, false
	}
	if sub == nil || sub.ID == "" {
		return nil, true
	}
	v, known := c.Check(ctx, sub.ID)
	if !known {
		return nil, true
	}
	if v.Compliant {
		return nil, false
	}
	reason := v.Reason
	if reason == "" {
		reason = "non-compliant"
	}
	return &Finding{Gate: GatePosture, Mode: mode, Reason: reason}, false
}
