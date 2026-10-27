package release

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// AI-BOM and provenance (ADR-0028). Both describe a built release and name it
// by digest, so they travel beside the content-addressed tar, never inside it:
// a policy commit or a Halos upgrade must not change the release digest.
// bundle.Publish stores them as a signed OCI referrer of the release.

// Media and predicate types.
const (
	BOMMediaType        = "application/vnd.cyclonedx+json"
	ProvenanceMediaType = "application/vnd.in-toto+json"
	StatementType       = "https://in-toto.io/Statement/v1"
	SLSAProvenanceType  = "https://slsa.dev/provenance/v1"
	BuildType           = "https://github.com/dshakes/halos/release-build/v1"
)

// Attestations are a release's CycloneDX 1.6 AI-BOM and its in-toto
// Statement v1 with a SLSA provenance v1 predicate, as JSON.
type Attestations struct {
	BOM        []byte
	Provenance []byte
}

// AttestOptions are the build facts the release itself does not carry.
type AttestOptions struct {
	HalosVersion string // version of the halo that built it
	BuilderID    string // default https://github.com/dshakes/halos/cmd/halo@<HalosVersion>
	PolicyRepo   string // policy repo URL, if known
	PolicyCommit string // policy repo commit (git rev-parse HEAD), if known
	PolicyDirty  bool   // the working tree had uncommitted changes
}

// ---- CycloneDX 1.6 (the subset Halos writes) ----

type cdxBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components,omitempty"`
	Services     []cdxService    `json:"services,omitempty"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp  string        `json:"timestamp"`
	Tools      *cdxTools     `json:"tools,omitempty"`
	Component  cdxComponent  `json:"component"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type               string           `json:"type"`
	BOMRef             string           `json:"bom-ref,omitempty"`
	Name               string           `json:"name"`
	Version            string           `json:"version,omitempty"`
	Description        string           `json:"description,omitempty"`
	Purl               string           `json:"purl,omitempty"`
	Hashes             []cdxHash        `json:"hashes,omitempty"`
	ExternalReferences []cdxExternalRef `json:"externalReferences,omitempty"`
	Properties         []cdxProperty    `json:"properties,omitempty"`
	Components         []cdxComponent   `json:"components,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxExternalRef struct {
	Type   string    `json:"type"`
	URL    string    `json:"url"`
	Hashes []cdxHash `json:"hashes,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxService struct {
	BOMRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Endpoints  []string      `json:"endpoints,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// ---- in-toto Statement v1 / SLSA provenance v1 ----

type statement struct {
	Type          string     `json:"_type"`
	Subject       []resource `json:"subject"`
	PredicateType string     `json:"predicateType"`
	Predicate     slsa       `json:"predicate"`
}

type resource struct {
	Name      string            `json:"name,omitempty"`
	URI       string            `json:"uri,omitempty"`
	Digest    map[string]string `json:"digest,omitempty"`
	MediaType string            `json:"mediaType,omitempty"`
}

type slsa struct {
	BuildDefinition struct {
		BuildType            string            `json:"buildType"`
		ExternalParameters   map[string]string `json:"externalParameters"`
		InternalParameters   map[string]string `json:"internalParameters,omitempty"`
		ResolvedDependencies []resource        `json:"resolvedDependencies,omitempty"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID      string            `json:"id"`
			Version map[string]string `json:"version,omitempty"`
		} `json:"builder"`
		Metadata *struct {
			StartedOn string `json:"startedOn,omitempty"`
		} `json:"metadata,omitempty"`
		Byproducts []resource `json:"byproducts,omitempty"`
	} `json:"runDetails"`
}

// Attest builds rel's AI-BOM and provenance. org supplies the models and MCP
// servers rel's profile references (nil: only what the manifest holds). The
// output is deterministic for the same inputs.
func Attest(rel *Release, org *policy.Org, o AttestOptions) (*Attestations, error) {
	if o.BuilderID == "" {
		o.BuilderID = "https://github.com/dshakes/halos/cmd/halo@" + o.HalosVersion
	}
	m := rel.Manifest
	relHex := strings.TrimPrefix(rel.Digest, "sha256:")
	var prof *policy.Profile
	if org != nil && m.Profile != "" {
		p, err := org.ResolveProfile(m.Profile)
		if err != nil {
			return nil, fmt.Errorf("release: attest: resolve profile %q: %w", m.Profile, err)
		}
		prof = p
	}
	bom, err := buildBOM(rel, org, prof, o)
	if err != nil {
		return nil, err
	}
	bj, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("release: marshal BOM: %w", err)
	}
	st := statement{Type: StatementType, PredicateType: SLSAProvenanceType,
		Subject: []resource{{Name: releaseName(m), Digest: map[string]string{"sha256": relHex}}}}
	bd := &st.Predicate.BuildDefinition
	bd.BuildType = BuildType
	bd.ExternalParameters = map[string]string{"org": m.Org, "ring": m.Ring, "profile": m.Profile, "version": m.Version}
	if m.Experiment != "" {
		bd.ExternalParameters["experiment"], bd.ExternalParameters["variant"] = m.Experiment, m.Variant
	}
	bd.InternalParameters = map[string]string{"halosVersion": o.HalosVersion}
	if o.PolicyCommit != "" {
		uri := o.PolicyRepo
		if uri == "" {
			uri = "policy-repo"
		}
		bd.ResolvedDependencies = append(bd.ResolvedDependencies, resource{Name: "policy", URI: uri, Digest: map[string]string{"gitCommit": o.PolicyCommit}})
		if o.PolicyDirty {
			bd.InternalParameters["policyDirty"] = "true"
		}
	}
	for _, e := range m.SupplyChain {
		bd.ResolvedDependencies = append(bd.ResolvedDependencies, resource{Name: "artifact:" + e.Name, URI: e.Source, Digest: map[string]string{"sha256": strings.TrimPrefix(e.Digest, "sha256:")}})
	}
	for _, name := range sortedNames(m.Harnesses) {
		he := m.Harnesses[name]
		for _, plat := range sortedNames(he.Artifacts) {
			a := he.Artifacts[plat]
			bd.ResolvedDependencies = append(bd.ResolvedDependencies, resource{Name: "harness:" + name + ":" + plat, URI: a.URL, Digest: artifactDigests(a)})
		}
	}
	rd := &st.Predicate.RunDetails
	rd.Builder.ID = o.BuilderID
	rd.Builder.Version = map[string]string{"halo": o.HalosVersion}
	rd.Metadata = &struct {
		StartedOn string `json:"startedOn,omitempty"`
	}{StartedOn: m.CreatedAt.UTC().Format(time.RFC3339)}
	bsum := sha256.Sum256(bj)
	rd.Byproducts = []resource{{Name: "bom.cdx.json", MediaType: BOMMediaType, Digest: map[string]string{"sha256": hex.EncodeToString(bsum[:])}}}
	pj, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("release: marshal provenance: %w", err)
	}
	return &Attestations{BOM: bj, Provenance: pj}, nil
}

func releaseName(m Manifest) string {
	return fmt.Sprintf("halos-release:%s/%s@%s", m.Org, m.Ring, m.Version)
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func artifactDigests(a Artifact) map[string]string {
	d := map[string]string{}
	if a.SHA256 != "" {
		d["sha256"] = a.SHA256
	}
	if b64, ok := strings.CutPrefix(a.Integrity, "sha512-"); ok {
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
			d["sha512"] = hex.EncodeToString(raw)
		}
	}
	return d
}

func cdxHashes(d map[string]string) []cdxHash {
	var out []cdxHash
	if v := d["sha256"]; v != "" {
		out = append(out, cdxHash{"SHA-256", v})
	}
	if v := d["sha512"]; v != "" {
		out = append(out, cdxHash{"SHA-512", v})
	}
	return out
}

func fileRef(h, os, path string) string { return "file:" + h + ":" + os + ":" + path }

func buildBOM(rel *Release, org *policy.Org, prof *policy.Profile, o AttestOptions) (*cdxBOM, error) {
	m := rel.Manifest
	relHex := strings.TrimPrefix(rel.Digest, "sha256:")
	serial := sha256.Sum256([]byte(rel.Digest + "\x00" + o.PolicyCommit + "\x00" + o.HalosVersion))
	serial[6] = serial[6]&0x0f | 0x50 // RFC 4122 v5 layout over a SHA-256 name
	serial[8] = serial[8]&0x3f | 0x80
	b := &cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		SerialNumber: fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", serial[0:4], serial[4:6], serial[6:8], serial[8:10], serial[10:16])}
	md := &b.Metadata
	md.Timestamp = m.CreatedAt.UTC().Format(time.RFC3339)
	md.Tools = &cdxTools{Components: []cdxComponent{{Type: "application", Name: "halo", Version: o.HalosVersion,
		Purl: "pkg:golang/github.com/dshakes/halos@" + o.HalosVersion}}}
	md.Component = cdxComponent{Type: "application", BOMRef: "release", Name: m.Org + "/" + m.Ring, Version: m.Version,
		Description: "Halos release bundle", Hashes: []cdxHash{{"SHA-256", relHex}},
		Properties: []cdxProperty{{"halos:profile", m.Profile}}}
	if m.Experiment != "" {
		md.Component.Properties = append(md.Component.Properties, cdxProperty{"halos:experiment", m.Experiment}, cdxProperty{"halos:variant", m.Variant})
	}
	if o.PolicyCommit != "" {
		md.Properties = append(md.Properties, cdxProperty{"halos:policy-commit", o.PolicyCommit})
	}
	if o.PolicyRepo != "" {
		md.Properties = append(md.Properties, cdxProperty{"halos:policy-repo", o.PolicyRepo})
	}
	var refs []string
	for _, name := range sortedNames(m.Harnesses) {
		he := m.Harnesses[name]
		c := cdxComponent{Type: "application", BOMRef: "harness:" + name, Name: name, Version: he.Version}
		if meta, ok := harness.MetaOf(name); ok && meta.Installer == harness.InstallerNPM && he.Version != "" {
			c.Purl = npmPurl(meta.NPMPackage, he.Version)
		}
		for _, plat := range sortedNames(he.Artifacts) {
			a := he.Artifacts[plat]
			c.ExternalReferences = append(c.ExternalReferences, cdxExternalRef{Type: "distribution", URL: a.URL, Hashes: cdxHashes(artifactDigests(a))})
		}
		for _, os := range sortedNames(he.Files) {
			for _, f := range he.Files[os] {
				if f.Artifact != "" {
					continue // listed under its artifact
				}
				c.Components = append(c.Components, cdxComponent{Type: "file", BOMRef: fileRef(name, os, f.Path), Name: f.Path,
					Hashes: []cdxHash{{"SHA-256", f.SHA256}}, Properties: []cdxProperty{{"halos:os", os}}})
			}
		}
		b.Components = append(b.Components, c)
		refs = append(refs, c.BOMRef)
	}
	for _, e := range m.SupplyChain {
		c := cdxComponent{Type: "file", BOMRef: "artifact:" + e.Name, Name: e.Name, Version: e.Digest,
			Hashes: []cdxHash{{"SHA-256", strings.TrimPrefix(e.Digest, "sha256:")}},
			Properties: []cdxProperty{{"halos:artifact-kind", e.Kind}, {"halos:source", e.Source},
				{"halos:digest-method", "sha256 of the sorted sha256sum listing (ADR-0028)"}}}
		if e.Signer != "" {
			c.Properties = append(c.Properties, cdxProperty{"halos:signer", e.Signer})
		}
		for _, p := range sortedNames(e.Files) {
			c.Components = append(c.Components, cdxComponent{Type: "file", Name: p, Hashes: []cdxHash{{"SHA-256", e.Files[p]}}})
		}
		b.Components = append(b.Components, c)
		refs = append(refs, c.BOMRef)
	}
	if prof != nil {
		for _, c := range modelComponents(org, prof) {
			b.Components = append(b.Components, c)
			refs = append(refs, c.BOMRef)
		}
		for _, s := range prof.MCP.Servers {
			ref := "mcp:" + s.Name
			if s.URL != "" {
				b.Services = append(b.Services, cdxService{BOMRef: ref, Name: s.Name, Endpoints: []string{s.URL},
					Properties: []cdxProperty{{"halos:kind", "mcp-server"}}})
			} else {
				b.Components = append(b.Components, mcpComponent(ref, s))
			}
			refs = append(refs, ref)
		}
	}
	for _, ra := range m.RemoteAgents {
		ref := "a2a:" + ra.Name
		b.Services = append(b.Services, cdxService{BOMRef: ref, Name: ra.Name, Endpoints: []string{ra.CardURL},
			Properties: []cdxProperty{{"halos:kind", "a2a-agent"}, {"halos:card-digest", ra.Digest}}})
		refs = append(refs, ref)
	}
	b.Dependencies = []cdxDependency{{Ref: "release", DependsOn: refs}}
	return b, nil
}

// modelComponents lists the model aliases the profile can call, each with
// the provider targets the gateway routes it to.
func modelComponents(org *policy.Org, p *policy.Profile) []cdxComponent {
	aliases := append([]string{p.Models.Default}, p.Models.Allowed...)
	for _, h := range p.Harnesses {
		aliases = append(aliases, h.Model)
	}
	aliases = slices.DeleteFunc(aliases, func(s string) bool { return s == "" })
	sort.Strings(aliases)
	aliases = slices.Compact(aliases)
	var out []cdxComponent
	for _, a := range aliases {
		c := cdxComponent{Type: "machine-learning-model", BOMRef: "model:" + a, Name: a}
		if org != nil && org.Gateway != nil {
			if r, ok := org.Gateway.Models[a]; ok {
				for _, t := range r.Candidates() {
					v := t.Upstream + "/" + t.Model
					if u, ok := org.Gateway.Upstreams[t.Upstream]; ok && u.Kind != "" {
						v = u.Kind + ":" + v
					}
					c.Properties = append(c.Properties, cdxProperty{"halos:route-target", v})
				}
			}
		}
		out = append(out, c)
	}
	return out
}

var (
	exactVer = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
	ociPin   = regexp.MustCompile(`^([a-z0-9.:/_-]+)@sha256:([0-9a-f]{64})$`)
)

// mcpComponent describes a command MCP server and whether its package is
// pinned: npx/bunx name@x.y.z, uvx/pipx name==x.y.z, or an image @sha256.
func mcpComponent(ref string, s policy.MCPServer) cdxComponent {
	c := cdxComponent{Type: "application", BOMRef: ref, Name: s.Name,
		Properties: []cdxProperty{{"halos:kind", "mcp-server"}, {"halos:command", strings.Join(s.Command, " ")}}}
	c.Version, c.Purl = pinnedPackage(s.Command)
	c.Properties = append(c.Properties, cdxProperty{"halos:pinned", fmt.Sprint(c.Purl != "")})
	return c
}

// pinnedPackage finds an exactly pinned package in an MCP server command.
// ponytail: positional heuristics; a flag that takes a value can hide the
// package, which only ever reports unpinned, never a false pin.
func pinnedPackage(cmd []string) (version, purl string) {
	if len(cmd) == 0 {
		return "", ""
	}
	var args []string
	for _, a := range cmd[1:] {
		if !strings.HasPrefix(a, "-") {
			args = append(args, a)
		}
	}
	after := func(word string) string {
		if i := slices.Index(args, word); i >= 0 && i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	npm := func(spec string) (string, string) {
		if at := strings.LastIndex(spec, "@"); at > 0 && exactVer.MatchString(spec[at+1:]) {
			return spec[at+1:], npmPurl(spec[:at], spec[at+1:])
		}
		return "", ""
	}
	pypi := func(spec string) (string, string) {
		if n, v, ok := strings.Cut(spec, "=="); ok && exactVer.MatchString(v) {
			return v, "pkg:pypi/" + strings.ToLower(n) + "@" + v
		}
		return "", ""
	}
	first := func() string {
		if len(args) > 0 {
			return args[0]
		}
		return ""
	}
	switch tool := cmd[0][strings.LastIndexAny(cmd[0], `/\`)+1:]; tool {
	case "npx", "bunx":
		return npm(first())
	case "pnpm", "yarn":
		return npm(after("dlx"))
	case "uvx":
		return pypi(first())
	case "pipx", "uv":
		return pypi(after("run"))
	case "docker", "podman":
		for _, a := range args {
			if mm := ociPin.FindStringSubmatch(a); mm != nil {
				return "sha256:" + mm[2], "pkg:oci/" + mm[1][strings.LastIndex(mm[1], "/")+1:] + "@sha256%3A" + mm[2] + "?repository_url=" + mm[1]
			}
		}
	}
	return "", ""
}

func npmPurl(pkg, ver string) string {
	return "pkg:npm/" + strings.Replace(pkg, "@", "%40", 1) + "@" + ver
}

// VerifyAttestations checks that bom and prov describe rel: both name rel's
// digest, every rendered file, artifact and install artifact in the manifest
// is in the BOM with the same hash and nothing else is, the provenance's
// artifact and install dependencies match the manifest, and its BOM
// byproduct digest is bom's. Signatures are checked by internal/bundle.
func VerifyAttestations(rel *Release, bom, prov []byte) error {
	m := rel.Manifest
	relHex := strings.TrimPrefix(rel.Digest, "sha256:")
	var b cdxBOM
	if err := json.Unmarshal(bom, &b); err != nil {
		return fmt.Errorf("bom: %w", err)
	}
	if b.BOMFormat != "CycloneDX" || b.SpecVersion != "1.6" {
		return fmt.Errorf("bom: %s %s, want CycloneDX 1.6", b.BOMFormat, b.SpecVersion)
	}
	if !slices.Contains(b.Metadata.Component.Hashes, cdxHash{"SHA-256", relHex}) {
		return fmt.Errorf("bom: describes a release other than %s", rel.Digest)
	}
	want := map[string]string{}
	for name, he := range m.Harnesses {
		for os, fs := range he.Files {
			for _, f := range fs {
				if f.Artifact == "" {
					want[fileRef(name, os, f.Path)] = f.SHA256
				}
			}
		}
	}
	for _, e := range m.SupplyChain {
		want["artifact:"+e.Name] = strings.TrimPrefix(e.Digest, "sha256:")
	}
	got := map[string]string{}
	var walk func([]cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			if strings.HasPrefix(c.BOMRef, "file:") || strings.HasPrefix(c.BOMRef, "artifact:") {
				for _, h := range c.Hashes {
					if h.Alg == "SHA-256" {
						got[c.BOMRef] = h.Content
					}
				}
			}
			walk(c.Components)
		}
	}
	walk(b.Components)
	for ref, h := range want {
		if got[ref] != h {
			return fmt.Errorf("bom: %s has sha256 %q, the release has %s", ref, got[ref], h)
		}
	}
	for ref := range got {
		if _, ok := want[ref]; !ok {
			return fmt.Errorf("bom: lists %s, which the release does not contain", ref)
		}
	}
	var st statement
	if err := json.Unmarshal(prov, &st); err != nil {
		return fmt.Errorf("provenance: %w", err)
	}
	if st.Type != StatementType || st.PredicateType != SLSAProvenanceType {
		return fmt.Errorf("provenance: %s / %s, want in-toto Statement v1 with SLSA provenance v1", st.Type, st.PredicateType)
	}
	if len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] != relHex {
		return fmt.Errorf("provenance: subject is not release %s", rel.Digest)
	}
	deps := map[string]map[string]string{}
	for _, d := range st.Predicate.BuildDefinition.ResolvedDependencies {
		deps[d.Name] = d.Digest
	}
	for _, e := range m.SupplyChain {
		if deps["artifact:"+e.Name]["sha256"] != strings.TrimPrefix(e.Digest, "sha256:") {
			return fmt.Errorf("provenance: artifact %s is not pinned to %s", e.Name, e.Digest)
		}
	}
	for name, he := range m.Harnesses {
		for plat, a := range he.Artifacts {
			d := deps["harness:"+name+":"+plat]
			for alg, v := range artifactDigests(a) {
				if d[alg] != v {
					return fmt.Errorf("provenance: install artifact %s/%s %s is not %s", name, plat, alg, v)
				}
			}
		}
	}
	bsum := sha256.Sum256(bom)
	bp := st.Predicate.RunDetails.Byproducts
	if len(bp) != 1 || bp[0].Digest["sha256"] != hex.EncodeToString(bsum[:]) {
		return errors.New("provenance: its BOM byproduct digest does not match this BOM")
	}
	return nil
}
