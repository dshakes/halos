package server

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// Portal is the self-service section of the server config (JSON file, --portal-config).
type Portal struct {
	// BaseURL is the externally visible URL of this server; baked into launch artifacts and enroll scripts.
	BaseURL string `json:"baseURL"`
	// Registry is the OCI repository halod pulls releases from.
	Registry string `json:"registry"`
	// RegistryPlainHTTP reads the registry over http (local/dev registries only).
	RegistryPlainHTTP bool `json:"registryPlainHTTP"`
	// PubKeyFile is the release-verification public key (PEM); served at /enroll/release.pub.
	PubKeyFile string `json:"pubKeyFile"`
	// DevcontainerFeature is the OCI ref of the halos Dev Container Feature.
	DevcontainerFeature string `json:"devcontainerFeature"`
	DevcontainerImage   string `json:"devcontainerImage"`
	// CodespacesURL / CoderURL are URL templates; {ring} and {user} are query-escaped.
	CodespacesURL string `json:"codespacesURL"`
	CoderURL      string `json:"coderURL"`
	// HalodURL is the halod download template with {os} and {arch}; HalodSHA256 pins each "<os>-<arch>" build.
	HalodURL    string            `json:"halodURL"`
	HalodSHA256 map[string]string `json:"halodSHA256"`
	// PolicyRepoDir is a dedicated git clone the PolicyWriter branches from (never the served policy dir).
	PolicyRepoDir string `json:"policyRepoDir"`
	PolicySubdir  string `json:"policySubdir"`
	PolicyBase    string `json:"policyBase"`
	// Secrets are referenced by file path so they never sit in the JSON itself.
	SessionKeyFile       string `json:"sessionKeyFile"`
	OIDCClientSecretFile string `json:"oidcClientSecretFile"`

	PubKeyPEM string `json:"-"` // loaded from PubKeyFile by the caller
}

var (
	shellSafe = regexp.MustCompile(`^[A-Za-z0-9:/._{}\-?=&%~+@]+$`)
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	osArch    = regexp.MustCompile(`^[a-z0-9]+-[a-z0-9]+$`)
)

// Validate rejects anything that could inject into the generated shell/PowerShell
// scripts, and a non-https baseURL (session cookies and device tokens would
// travel in clear) unless it is loopback or devInsecure.
func (p Portal) Validate(devInsecure bool) error {
	for name, v := range map[string]string{"baseURL": p.BaseURL, "halodURL": p.HalodURL} {
		if v != "" && !shellSafe.MatchString(v) {
			return fmt.Errorf("portal %s contains unsafe characters", name)
		}
	}
	if p.BaseURL != "" {
		u, err := url.Parse(p.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || (!devInsecure && !isLoopback(u.Hostname())))) {
			return fmt.Errorf("portal baseURL must be an https URL (http only for loopback or --dev-insecure-user)")
		}
	}
	for k, v := range p.HalodSHA256 {
		if !hex64.MatchString(v) || !osArch.MatchString(k) {
			return fmt.Errorf("portal halodSHA256[%q]: want <os>-<arch> -> 64 lowercase hex", k)
		}
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (s *Server) baseURL(r *http.Request) string {
	if b := strings.TrimRight(s.cfg.Portal.BaseURL, "/"); b != "" {
		return b
	}
	if s.cfg.DevUser != "" { // dev only: never trust the Host header for artifacts otherwise
		return "http://" + r.Host
	}
	return ""
}

// ---- policy-derived views ----

type profileSummary struct {
	Name         string            `json:"name"`
	Harnesses    map[string]string `json:"harnesses"` // adapter -> pinned version
	Models       []string          `json:"models"`
	DefaultModel string            `json:"defaultModel"`
	MCPServers   []string          `json:"mcpServers"`
	Sandbox      string            `json:"sandbox,omitempty"`
	// HarnessModels are the Models each harness can use: those whose route
	// answers the harness's wire (the check `halo validate` runs on start
	// models). Empty for a harness the gateway does not route.
	HarnessModels map[string][]string `json:"harnessModels"`
	// HarnessDefault is the model each harness starts on (harnesses.<h>.model, else models.default).
	HarnessDefault map[string]string `json:"harnessDefault"`
}

// Me is GET /api/v1/me.
type Me struct {
	Principal
	Ring        string          `json:"ring"`
	Release     string          `json:"release,omitempty"`
	Variants    []AssignmentRow `json:"variants"`
	Profile     *profileSummary `json:"profile,omitempty"`
	SelfService bool            `json:"selfService"`
	Launchers   []string        `json:"launchers"`
	Requestable []string        `json:"requestable"`
	OptInRings  []string        `json:"optInRings"` // rings the user may still ask to join
	DevInsecure bool            `json:"devInsecure,omitempty"`
}

func summarize(p *policy.Profile, gw *policy.Gateway) *profileSummary {
	ps := &profileSummary{Name: p.Name, Harnesses: map[string]string{}, DefaultModel: p.Models.Default, Sandbox: p.Permissions.Sandbox, Models: []string{}, MCPServers: []string{},
		HarnessModels: map[string][]string{}, HarnessDefault: map[string]string{}}
	ps.Models = append(ps.Models, p.Models.Allowed...)
	if len(ps.Models) == 0 && gw != nil {
		for a := range gw.Models {
			ps.Models = append(ps.Models, a)
		}
	}
	sort.Strings(ps.Models)
	for n, h := range p.Harnesses {
		ps.Harnesses[n] = h.Version
		ps.HarnessDefault[n] = cmp.Or(h.Model, p.Models.Default)
		if gw == nil { // nothing to check the wire against
			ps.HarnessModels[n] = ps.Models
			continue
		}
		usable := []string{}
		if wire := gw.HarnessWire(n); wire != "" {
			for _, m := range ps.Models {
				if fit, _ := gw.WireFit(m, wire); fit == policy.WireYes {
					usable = append(usable, m)
				}
			}
		}
		ps.HarnessModels[n] = usable
	}
	for _, m := range p.MCP.Servers {
		ps.MCPServers = append(ps.MCPServers, m.Name)
	}
	sort.Strings(ps.MCPServers)
	return ps
}

func assignments(org *policy.Org, sub policy.Subject, ring *policy.Ring) []AssignmentRow {
	rows := []AssignmentRow{}
	for _, e := range org.Experiments {
		row := AssignmentRow{Experiment: e.Name, Status: e.Status}
		if ring != nil {
			if v := e.ResolveVariant(sub, ring.Name); v != nil {
				row.Variant, row.Control = v.Name, v.Control
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// optInGroup is the legacy IdP group name for opt-ins; still hides already-opted-in rings for existing deployments.
func optInGroup(ring string) string { return ring + "-optin" }

func optInRings(org *policy.Org, ring *policy.Ring, user string, groups []string) []string {
	out := []string{}
	for _, r := range org.Rings {
		if r.Membership.OptIn && (ring == nil || r.Name != ring.Name) && !slices.Contains(groups, optInGroup(r.Name)) && !slices.Contains(r.Membership.Users, user) {
			out = append(out, r.Name)
		}
	}
	return out
}

func known(list []string) []string {
	out := []string{}
	for _, l := range list {
		if slices.Contains(allLaunchers, l) {
			out = append(out, l)
		}
	}
	return out
}

var allLaunchers = []string{"devcontainer", "codespaces", "coder", "laptop"}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, p Principal) {
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return
	}
	ring := org.ResolveRing(p.subject())
	if p.Groups == nil {
		p.Groups = []string{}
	}
	m := Me{Principal: p, Variants: assignments(org, p.subject(), ring), SelfService: org.SelfService.Enabled, Launchers: []string{}, Requestable: []string{}, OptInRings: []string{}, DevInsecure: s.cfg.DevUser != ""}
	if ring != nil {
		m.Ring, m.Release = ring.Name, ring.Release
		if prof, err := org.ResolveProfile(ring.Profile); err == nil {
			m.Profile = summarize(prof, org.Gateway)
		}
	}
	if org.SelfService.Enabled {
		m.Launchers = known(org.SelfService.Launchers)
		m.Requestable = append(m.Requestable, org.SelfService.Requestable...)
		if slices.Contains(m.Requestable, "ring-opt-in") {
			m.OptInRings = optInRings(org, ring, p.ID, p.Groups)
		}
	}
	writeJSON(w, http.StatusOK, m)
}

// selfService returns the org iff the kiosk is enabled, else writes the error and returns nil.
func (s *Server) selfService(w http.ResponseWriter) *policy.Org {
	org, _, err := s.pol.Get()
	switch {
	case org == nil:
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
	case !org.SelfService.Enabled:
		apiErr(w, http.StatusForbidden, "self-service is disabled")
	default:
		return org
	}
	return nil
}

// CatalogItem is something the user can request.
type CatalogItem struct {
	Kind string `json:"kind"`
	Item string `json:"item"`
	Desc string `json:"desc,omitempty"`
}

// HarnessPin is one harness at the version pinned by the user's ring profile.
type HarnessPin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Catalog is GET /api/v1/catalog.
type Catalog struct {
	Harnesses []HarnessPin  `json:"harnesses"`
	Launchers []string      `json:"launchers"`
	Items     []CatalogItem `json:"items"`
}

func (s *Server) catalog(w http.ResponseWriter, _ *http.Request, p Principal) {
	org := s.selfService(w)
	if org == nil {
		return
	}
	ring := org.ResolveRing(p.subject())
	cat := Catalog{Harnesses: []HarnessPin{}, Launchers: known(org.SelfService.Launchers), Items: []CatalogItem{}}
	var prof *policy.Profile
	if ring != nil {
		prof, _ = org.ResolveProfile(ring.Profile)
	}
	has := map[string]bool{}
	if prof != nil {
		for n, h := range prof.Harnesses {
			cat.Harnesses = append(cat.Harnesses, HarnessPin{n, h.Version})
			has["harness/"+n] = true
		}
		sort.Slice(cat.Harnesses, func(i, j int) bool { return cat.Harnesses[i].Name < cat.Harnesses[j].Name })
		for _, m := range prof.MCP.Servers {
			has["mcp-server/"+m.Name] = true
		}
		for _, m := range prof.Models.Allowed {
			has["model/"+m] = true
		}
	}
	for _, kind := range org.SelfService.Requestable {
		switch kind {
		case "mcp-server":
			for _, m := range org.SelfService.Catalog {
				if !has[kind+"/"+m.Name] {
					cat.Items = append(cat.Items, CatalogItem{kind, m.Name, m.URL}) // headers deliberately omitted
				}
			}
		case "ring-opt-in":
			for _, n := range optInRings(org, ring, p.ID, p.Groups) {
				cat.Items = append(cat.Items, CatalogItem{Kind: kind, Item: n})
			}
		case "model":
			if org.Gateway != nil && prof != nil && len(prof.Models.Allowed) > 0 { // no allowlist = everything already usable
				for a := range org.Gateway.Models {
					if !has[kind+"/"+a] {
						cat.Items = append(cat.Items, CatalogItem{Kind: kind, Item: a})
					}
				}
			}
		case "harness":
			for _, n := range requestableHarnesses() {
				if !has[kind+"/"+n] {
					cat.Items = append(cat.Items, CatalogItem{Kind: kind, Item: n})
				}
			}
		}
	}
	sort.Slice(cat.Items, func(i, j int) bool {
		return cat.Items[i].Kind+"/"+cat.Items[i].Item < cat.Items[j].Kind+"/"+cat.Items[j].Item
	})
	writeJSON(w, http.StatusOK, cat)
}

// requestableHarnesses are the registered harnesses with a verified installer.
func requestableHarnesses() []string {
	var out []string
	for _, n := range harness.Names() {
		if m, ok := harness.MetaOf(n); ok && m.Installer != "" {
			out = append(out, n)
		}
	}
	return out
}

// ---- launchers ----

// Launch is the POST /api/v1/launch/{launcher} response; fields depend on the launcher.
type Launch struct {
	Launcher   string     `json:"launcher"`
	Filename   string     `json:"filename,omitempty"` // devcontainer
	Snippet    string     `json:"snippet,omitempty"`  // devcontainer
	URL        string     `json:"url,omitempty"`      // codespaces, coder
	Token      string     `json:"token,omitempty"`    // laptop
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	TTLSeconds int        `json:"ttlSeconds,omitempty"`
	Bash       string     `json:"bash,omitempty"`
	PowerShell string     `json:"powershell,omitempty"`
}

func expand(tmpl string, kv map[string]string) string {
	for k, v := range kv {
		tmpl = strings.ReplaceAll(tmpl, "{"+k+"}", url.QueryEscape(v))
	}
	return tmpl
}

func (s *Server) launch(w http.ResponseWriter, r *http.Request, p Principal) {
	org := s.selfService(w)
	if org == nil {
		return
	}
	name := r.PathValue("launcher")
	if !slices.Contains(org.SelfService.Launchers, name) || !slices.Contains(allLaunchers, name) {
		apiErr(w, http.StatusNotFound, "launcher not available")
		return
	}
	ring := org.ResolveRing(p.subject())
	if ring == nil {
		apiErr(w, http.StatusConflict, "you are not assigned to any ring")
		return
	}
	pc := s.cfg.Portal
	out := Launch{Launcher: name}
	notConfigured := func(what string) { apiErr(w, http.StatusConflict, "launcher not configured: "+what) }
	switch name {
	case "devcontainer":
		// The feature refuses to install without org, halodUrl, halodSha256 and an
		// inline (or hash-pinned) key: emit all of them or nothing.
		var shas []string
		for _, arch := range []string{"amd64", "arm64"} {
			if h := pc.HalodSHA256["linux-"+arch]; h != "" {
				shas = append(shas, arch+"="+h)
			}
		}
		if pc.DevcontainerFeature == "" || pc.Registry == "" || pc.HalodURL == "" || len(shas) == 0 || pc.PubKeyPEM == "" {
			notConfigured("devcontainerFeature, registry, halodURL, linux halodSHA256 and pubKeyFile")
			return
		}
		opts := map[string]any{"registry": pc.Registry, "org": org.Name, "ring": ring.Name, "firewall": true,
			"halodUrl": pc.HalodURL, "halodSha256": strings.Join(shas, ","),
			"pubkeyPem": strings.ReplaceAll(strings.TrimSpace(pc.PubKeyPEM), "\n", `\n`)}
		if org.Gateway != nil {
			if u, err := url.Parse(org.Gateway.BaseURL); err == nil && u.Host != "" {
				opts["gatewayHost"] = u.Host
			}
		}
		img := pc.DevcontainerImage
		if img == "" {
			img = "mcr.microsoft.com/devcontainers/base:ubuntu"
		}
		b, _ := json.MarshalIndent(map[string]any{
			"name": org.Name + "-dev", "image": img,
			"features": map[string]any{pc.DevcontainerFeature: opts},
			"runArgs":  []string{"--cap-add=NET_ADMIN", "--cap-add=NET_RAW"},
		}, "", "  ")
		out.Filename, out.Snippet = ".devcontainer/devcontainer.json", string(b)
	case "codespaces", "coder":
		tmpl := pc.CodespacesURL
		if name == "coder" {
			tmpl = pc.CoderURL
		}
		if tmpl == "" {
			notConfigured(name + "URL")
			return
		}
		out.URL = expand(tmpl, map[string]string{"ring": ring.Name, "user": p.ID})
	case "laptop":
		base := s.baseURL(r)
		if base == "" || pc.HalodURL == "" || len(pc.HalodSHA256) == 0 || pc.Registry == "" || pc.PubKeyPEM == "" {
			notConfigured("baseURL, registry, pubKeyFile, halodURL and halodSHA256")
			return
		}
		ttl := time.Duration(org.SelfService.EnrollmentTTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 15 * time.Minute
		}
		tok, exp := s.enroll.issue(p, ttl, s.cfg.Now())
		out.Token, out.ExpiresAt, out.TTLSeconds = tok, &exp, int(ttl.Seconds())
		out.Bash = fmt.Sprintf("curl -fsSL %s/enroll.sh | sh -s -- %s", base, tok)
		out.PowerShell = fmt.Sprintf("& ([scriptblock]::Create((irm %s/enroll.ps1))) -Token %s", base, tok)
		s.cfg.Log.Info("enrollment token issued", "user", p.ID, "ttl", ttl) // never log the token
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// ---- enrollment tokens: random, stored only as SHA-256, single-use, short TTL ----

type enrollment struct {
	user Principal
	exp  time.Time
}

type enrollments struct {
	mu sync.Mutex
	m  map[[32]byte]enrollment
}

func hashTok(tok string) [32]byte { return sha256.Sum256([]byte(tok)) }

func (e *enrollments) issue(p Principal, ttl time.Duration, now time.Time) (string, time.Time) {
	tok := randB64(32) // 32 random bytes
	exp := now.Add(ttl)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.m == nil {
		e.m = map[[32]byte]enrollment{}
	}
	for h, v := range e.m { // sweep expired
		if now.After(v.exp) {
			delete(e.m, h)
		}
	}
	e.m[hashTok(tok)] = enrollment{p, exp}
	return tok, exp
}

// consume burns the token (even if expired) and returns the principal it was issued to.
func (e *enrollments) consume(tok string, now time.Time) (Principal, bool) {
	h := hashTok(tok)
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.m[h]
	if !ok {
		return Principal{}, false
	}
	delete(e.m, h)
	if now.After(v.exp) {
		return Principal{}, false
	}
	return v.user, true
}

func (s *Server) postEnroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
		OS    string `json:"os"` // selects the pubkey path halod will read; default unix
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Token == "" {
		apiErr(w, http.StatusBadRequest, "token required")
		return
	}
	p, ok := s.enroll.consume(body.Token, s.cfg.Now())
	if !ok {
		s.cfg.Log.Warn("enrollment rejected", "remote", r.RemoteAddr)
		apiErr(w, http.StatusUnauthorized, "invalid, expired or already used token")
		return
	}
	org, _, _ := s.pol.Get()
	var ring *policy.Ring
	if org != nil {
		ring = org.ResolveRing(p.subject())
	}
	if ring == nil {
		apiErr(w, http.StatusConflict, "no ring assigned")
		return
	}
	devTok, dev, err := s.devices.mint(p, s.cfg.Now())
	if err != nil {
		s.cfg.Log.Error("persist device", "user", p.ID, "err", err)
		apiErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	base := s.baseURL(r)
	// Marshalled, never formatted, and the user id stays out of the comment:
	// YAML treats U+0085/U+2028/U+2029 as line breaks, so an id in a comment
	// could inject keys such as allowShellInstall.
	hc := halodConfig{
		Registry: s.cfg.Portal.Registry, Org: org.Name, RingEndpoint: base + "/api/v1/fleet/ring", DeviceToken: devTok,
		PubKey: halodEtcPath(body.OS, "release.pub"), Interval: "15m", ReportURL: base + "/api/v1/fleet/report",
		PlainHTTP: s.cfg.Portal.RegistryPlainHTTP,
	}
	if s.cfg.KillKey != nil { // the enroll scripts fetch the key from /enroll/killswitch.pub
		hc.KillSwitch = &halodKillSwitch{URL: base + "/api/v1/fleet/killswitch", PubKey: halodEtcPath(body.OS, "killswitch.pub")}
	}
	cfgYAML, err := yaml.Marshal(hc)
	if err != nil {
		s.cfg.Log.Error("render halod.yaml", "err", err)
		apiErr(w, http.StatusInternalServerError, "render failed")
		return
	}
	yml := fmt.Sprintf("# enrolled at %s (device %s); contains a credential: keep mode 0600\n%s", s.cfg.Now().UTC().Format(time.RFC3339), dev.ID, cfgYAML)
	s.cfg.Log.Info("enrollment consumed", "user", p.ID, "ring", ring.Name, "device", dev.ID) // never log the device token
	// Fail closed: a device credential is not handed out without an audit record.
	if err := s.AuditStrict(r.Context(), p.ID, "device.enroll", dev.ID, map[string]string{"ring": ring.Name}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprint(w, yml)
}

// halodConfig is the halod.yaml an enrollment hands out (keys match cmd/halod's config).
type halodConfig struct {
	Registry     string `yaml:"registry"`
	Org          string `yaml:"org"`
	RingEndpoint string `yaml:"ringEndpoint"`
	DeviceToken  string `yaml:"deviceToken"`
	PubKey       string `yaml:"pubkey"`
	Interval     string `yaml:"interval"`
	ReportURL    string `yaml:"reportURL"`
	// PlainHTTP mirrors portal registryPlainHTTP: halod cannot reach an http (dev) registry without it.
	PlainHTTP bool `yaml:"plainHTTP,omitempty"`
	// KillSwitch is set only when the server signs a kill list.
	KillSwitch *halodKillSwitch `yaml:"killSwitch,omitempty"`
}

type halodKillSwitch struct {
	URL    string `yaml:"url"`
	PubKey string `yaml:"pubkey"`
}

// halodEtcPath is file in halod's per-OS etc dir (matches cmd/halod's layout and the enroll scripts).
func halodEtcPath(goos, file string) string {
	switch goos {
	case "darwin":
		return "/Library/Halos/etc/" + file
	case "windows":
		return `C:\Program Files\Halos\etc\` + file
	}
	return "/etc/halos/" + file
}

func (s *Server) releasePub(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Portal.PubKeyPEM == "" {
		apiErr(w, http.StatusNotFound, "no public key configured")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = fmt.Fprint(w, s.cfg.Portal.PubKeyPEM)
}
