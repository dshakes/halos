package release

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/harness"
)

// Verified install artifacts (replaces running installCommand via a root shell).
// `halo release build` resolves, over the network, the exact download URL and
// hash for every harness version and OS/arch; the hashes then sit inside the
// signed release, so halod only ever installs bytes the release key vouched for.

// ArtifactKind says how halod installs an artifact.
type ArtifactKind string

const (
	// KindBinary is a single self-contained executable, placed atomically in
	// halod's root-owned bin dir.
	KindBinary ArtifactKind = "binary"
	// KindNPMTgz is an npm package tarball installed with lifecycle scripts
	// disabled and no user/global npmrc.
	KindNPMTgz ArtifactKind = "npm-tgz"
)

// AnyPlatform keys an artifact that is the same on every OS/arch (npm).
const AnyPlatform = "any"

// Artifact is one downloadable, hash-pinned installer input.
type Artifact struct {
	URL       string       `json:"url"`
	SHA256    string       `json:"sha256,omitempty"`    // lowercase hex
	Integrity string       `json:"integrity,omitempty"` // SRI "sha512-<base64>" (npm dist.integrity)
	Size      int64        `json:"size,omitempty"`      // exact byte size when known
	Kind      ArtifactKind `json:"kind"`
	BinPath   string       `json:"binPath"`           // binary: installed file name; npm: bin command name
	Package   string       `json:"package,omitempty"` // npm package name
}

var (
	semverRe  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	hex64Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	binNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	npmPkgRe  = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
)

// Validate is what halod checks before downloading anything.
func (a Artifact) Validate() error {
	u, err := url.Parse(a.URL)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "":
		return fmt.Errorf("artifact url %q must be absolute https", a.URL)
	case a.SHA256 == "" && a.Integrity == "":
		return errors.New("artifact has no sha256 or integrity")
	case a.SHA256 != "" && !hex64Re.MatchString(a.SHA256):
		return fmt.Errorf("artifact sha256 %q malformed", a.SHA256)
	case !binNameRe.MatchString(a.BinPath):
		return fmt.Errorf("artifact binPath %q must be a plain file name", a.BinPath)
	case a.Size < 0:
		return errors.New("artifact size negative")
	}
	if a.Integrity != "" {
		b64, ok := strings.CutPrefix(a.Integrity, "sha512-")
		if raw, err := base64.StdEncoding.DecodeString(b64); !ok || err != nil || len(raw) != 64 {
			return fmt.Errorf("artifact integrity %q must be sha512-<base64>", a.Integrity)
		}
	}
	switch a.Kind {
	case KindBinary:
	case KindNPMTgz:
		if !npmPkgRe.MatchString(a.Package) {
			return fmt.Errorf("artifact npm package %q invalid", a.Package)
		}
	default:
		return fmt.Errorf("artifact kind %q unknown", a.Kind)
	}
	return nil
}

// ArtifactFor picks the artifact for goos/goarch, falling back to AnyPlatform.
func (h HarnessEntry) ArtifactFor(goos, goarch string) (Artifact, bool) {
	if a, ok := h.Artifacts[goos+"-"+goarch]; ok {
		return a, true
	}
	a, ok := h.Artifacts[AnyPlatform]
	return a, ok
}

// claudePlatforms maps Go os-arch to the platform keys in Anthropic's release
// manifest (https://downloads.claude.ai/claude-code-releases/<ver>/manifest.json,
// the same manifest https://claude.ai/install.sh verifies against).
// ponytail: glibc only on linux; add linux-*-musl keys when a musl fleet shows up.
var claudePlatforms = map[string]string{
	"darwin-arm64": "darwin-arm64", "darwin-amd64": "darwin-x64",
	"linux-amd64": "linux-x64", "linux-arm64": "linux-arm64",
	"windows-amd64": "win32-x64", "windows-arm64": "win32-arm64",
}

// ArtifactResolver fills HarnessEntry.Artifacts from the vendors' release metadata.
type ArtifactResolver struct {
	HTTP        *http.Client // default: 60s timeout
	ClaudeBase  string       // default https://downloads.claude.ai/claude-code-releases
	NPMRegistry string       // default https://registry.npmjs.org
}

// Resolve returns a copy of rel (re-packed, so the digest changes) with
// artifacts for every harness pinned to an exact version. Harnesses without a
// known source or with a non-exact version get a manifest warning instead.
func (r ArtifactResolver) Resolve(ctx context.Context, rel *Release) (*Release, error) {
	if r.HTTP == nil {
		r.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if r.ClaudeBase == "" {
		r.ClaudeBase = "https://downloads.claude.ai/claude-code-releases"
	}
	if r.NPMRegistry == "" {
		r.NPMRegistry = "https://registry.npmjs.org"
	}
	m := rel.Manifest
	m.Harnesses = make(map[string]HarnessEntry, len(rel.Manifest.Harnesses))
	m.Warnings = append([]string(nil), rel.Manifest.Warnings...)
	for name, he := range rel.Manifest.Harnesses {
		// Installer metadata comes from the registered adapters (harness.Meta);
		// callers import internal/harness/all.
		src, _ := harness.MetaOf(name)
		known := src.Installer == harness.InstallerNPM || src.Installer == harness.InstallerClaudeNative
		switch {
		case he.Version == "":
		case !known:
			m.Warnings = append(m.Warnings, fmt.Sprintf("%s: no verified installer source; halod will not install it", name))
		case !semverRe.MatchString(he.Version):
			m.Warnings = append(m.Warnings, fmt.Sprintf("%s: version %q is not exact; no verified installer resolved", name, he.Version))
		default:
			var arts map[string]Artifact
			var err error
			if src.Installer == harness.InstallerClaudeNative {
				arts, err = r.claude(ctx, he.Version)
			} else {
				arts, err = r.npm(ctx, src, he.Version)
			}
			if err != nil {
				return nil, fmt.Errorf("release: resolve %s@%s artifacts: %w", name, he.Version, err)
			}
			he.Artifacts = arts
		}
		m.Harnesses[name] = he
	}
	sort.Strings(m.Warnings)
	return pack(m, rel.Blobs)
}

func (r ArtifactResolver) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v); err != nil {
		return fmt.Errorf("GET %s: decode: %w", u, err)
	}
	return nil
}

func (r ArtifactResolver) claude(ctx context.Context, ver string) (map[string]Artifact, error) {
	base := strings.TrimRight(r.ClaudeBase, "/")
	var man struct {
		Version   string `json:"version"`
		Platforms map[string]struct {
			Binary   string `json:"binary"`
			Checksum string `json:"checksum"`
			Size     int64  `json:"size"`
		} `json:"platforms"`
	}
	// ponytail: manifest.json.sig (PGP) is not checked; the manifest is fetched
	// over HTTPS from Anthropic and its hashes are then covered by our signature.
	if err := r.getJSON(ctx, base+"/"+ver+"/manifest.json", &man); err != nil {
		return nil, err
	}
	if man.Version != ver {
		return nil, fmt.Errorf("claude manifest is for version %q, want %q", man.Version, ver)
	}
	out := map[string]Artifact{}
	for goPlat, plat := range claudePlatforms {
		p, ok := man.Platforms[plat]
		if !ok {
			continue
		}
		a := Artifact{URL: base + "/" + ver + "/" + plat + "/" + p.Binary, SHA256: p.Checksum, Size: p.Size, Kind: KindBinary, BinPath: p.Binary}
		if err := a.Validate(); err != nil {
			return nil, fmt.Errorf("claude %s: %w", plat, err)
		}
		out[goPlat] = a
	}
	if len(out) == 0 {
		return nil, errors.New("claude manifest lists no known platforms")
	}
	return out, nil
}

func (r ArtifactResolver) npm(ctx context.Context, src harness.Meta, ver string) (map[string]Artifact, error) {
	reg, err := url.Parse(strings.TrimRight(r.NPMRegistry, "/"))
	if err != nil {
		return nil, fmt.Errorf("npm registry: %w", err)
	}
	var doc struct {
		Name    string          `json:"name"`
		Version string          `json:"version"`
		Bin     json.RawMessage `json:"bin"`
		Dist    struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := r.getJSON(ctx, reg.String()+"/"+src.NPMPackage+"/"+ver, &doc); err != nil {
		return nil, err
	}
	if doc.Name != src.NPMPackage || doc.Version != ver {
		return nil, fmt.Errorf("npm returned %s@%s, want %s@%s", doc.Name, doc.Version, src.NPMPackage, ver)
	}
	if tu, err := url.Parse(doc.Dist.Tarball); err != nil || tu.Host != reg.Host {
		return nil, fmt.Errorf("npm tarball %q is not on registry host %s", doc.Dist.Tarball, reg.Host)
	}
	bins := map[string]string{}
	var single string
	if json.Unmarshal(doc.Bin, &single) == nil { // "bin": "path" means the unscoped package name
		bins[src.NPMPackage[strings.LastIndex(src.NPMPackage, "/")+1:]] = single
	} else {
		_ = json.Unmarshal(doc.Bin, &bins)
	}
	if bins[src.Binary] == "" {
		return nil, fmt.Errorf("npm %s@%s does not declare bin %q", src.NPMPackage, ver, src.Binary)
	}
	a := Artifact{URL: doc.Dist.Tarball, Integrity: doc.Dist.Integrity, Kind: KindNPMTgz, BinPath: src.Binary, Package: src.NPMPackage}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("npm %s: %w", src.NPMPackage, err)
	}
	return map[string]Artifact{AnyPlatform: a}, nil
}
