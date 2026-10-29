package policy

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/supplychain"
)

// Artifact kinds for SupplyChain.Artifacts (ADR-0028).
const (
	ArtifactSkill   = "skill"   // a directory holding SKILL.md
	ArtifactPlugin  = "plugin"  // a plugin directory (.claude-plugin/plugin.json, ...)
	ArtifactHook    = "hook"    // hook scripts a hooks.items command runs
	ArtifactCommand = "command" // a slash command: one Markdown file
	ArtifactAgent   = "agent"   // a subagent definition: one Markdown file
)

// Scan modes for SupplyChain.Scan.
const (
	ScanOff     = "off"
	ScanWarn    = "warn"
	ScanEnforce = "enforce"
)

var (
	artifactKinds  = []string{ArtifactSkill, ArtifactPlugin, ArtifactHook, ArtifactCommand, ArtifactAgent}
	scanModes      = []string{ScanOff, ScanWarn, ScanEnforce}
	artifactNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	sha256DigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// SupplyChain is the agent supply chain (ADR-0028): the skills, plugins,
// hooks, slash commands and agent definitions releases deliver, each pinned
// by a content digest, statically scanned, and optionally signature-checked.
type SupplyChain struct {
	// Scan: off | warn (default) | enforce. enforce turns scan findings into
	// errors (as does `--strict`).
	Scan string `yaml:"scan,omitempty" json:"scan,omitempty"`
	// RequireSignatures refuses an artifact from outside the policy repo
	// (git or oci) unless it carries a signature by a trusted identity.
	RequireSignatures bool              `yaml:"requireSignatures,omitempty" json:"requireSignatures,omitempty"`
	Artifacts         []Artifact        `yaml:"artifacts,omitempty" json:"artifacts,omitempty"`
	TrustedIdentities []TrustedIdentity `yaml:"trustedIdentities,omitempty" json:"trustedIdentities,omitempty"`
	AllowFindings     []AllowFinding    `yaml:"allowFindings,omitempty" json:"allowFindings,omitempty"`
}

// Artifact is one extension artifact. Exactly one source is set.
type Artifact struct {
	Name string `yaml:"name" json:"name"`
	Kind string `yaml:"kind" json:"kind"`
	// Path is a file or directory in the policy repo, relative to its root.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Git is a repository pinned to a full commit id.
	Git *GitSource `yaml:"git,omitempty" json:"git,omitempty"`
	// OCI is a digest-pinned reference, host/repo@sha256:<hex>; each layer is
	// one file named by its org.opencontainers.image.title annotation.
	OCI string `yaml:"oci,omitempty" json:"oci,omitempty"`
	// Digest is the artifact digest (supplychain.DigestOf). Required for git
	// and oci; for a path it is computed and, when set, checked.
	Digest    string             `yaml:"digest,omitempty" json:"digest,omitempty"`
	Signature *ArtifactSignature `yaml:"signature,omitempty" json:"signature,omitempty"`
}

// GitSource is a git repository at an exact commit.
type GitSource struct {
	URL    string `yaml:"url" json:"url"`
	Commit string `yaml:"commit" json:"commit"`
	// Path within the repository ("" = its root).
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

// ArtifactSignature names who signed the artifact digest and where the
// signature is (a file in the policy repo: base64 ed25519, or cosign's
// sign-blob output).
type ArtifactSignature struct {
	Identity string `yaml:"identity" json:"identity"`
	File     string `yaml:"file" json:"file"`
}

// TrustedIdentity is a key artifact signatures may be made with. Exactly one
// of PublicKey (an ed25519 PEM file in the policy repo) and CosignKey (a
// cosign public key reference: file or KMS URI) is set.
type TrustedIdentity struct {
	Name      string `yaml:"name" json:"name"`
	PublicKey string `yaml:"publicKey,omitempty" json:"publicKey,omitempty"`
	CosignKey string `yaml:"cosignKey,omitempty" json:"cosignKey,omitempty"`
}

// AllowFinding suppresses scan findings by digest, so changed content is
// scanned afresh: Digest is either the artifact digest (any of its files) or
// one file's sha256 (that file only). Path ("" = any file) narrows it.
type AllowFinding struct {
	Digest string `yaml:"digest" json:"digest"`
	Rule   string `yaml:"rule" json:"rule"`
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	Reason string `yaml:"reason" json:"reason"`
}

// ArtifactContent is an artifact's resolved content: read from the policy
// repo by Load, or fetched and signature-checked by `halo release build`.
type ArtifactContent struct {
	Files  supplychain.Tree
	Err    string // why it could not be read
	Signer string // trusted identity whose signature verified, if any
}

// ResolvedArtifact is an artifact a resolved profile delivers. Files is nil
// when the content was not resolved (a remote source outside a release build).
type ResolvedArtifact struct {
	Name, Kind, Source, Digest, Signer string
	Files                              supplychain.Tree
}

// Remote reports whether a's content comes from outside the policy repo.
func (a Artifact) Remote() bool { return a.Git != nil || a.OCI != "" }

// Source is a's source as one string, for manifests and BOMs.
func (a Artifact) Source() string {
	switch {
	case a.Git != nil:
		s := "git+" + a.Git.URL + "@" + a.Git.Commit
		if a.Git.Path != "" {
			s += "#" + a.Git.Path
		}
		return s
	case a.OCI != "":
		return "oci://" + a.OCI
	}
	return "path:" + a.Path
}

// FindArtifact returns the artifact declared under name.
func (o *Org) FindArtifact(name string) (Artifact, bool) {
	if o.SupplyChain == nil {
		return Artifact{}, false
	}
	i := slices.IndexFunc(o.SupplyChain.Artifacts, func(a Artifact) bool { return a.Name == name })
	if i < 0 {
		return Artifact{}, false
	}
	return o.SupplyChain.Artifacts[i], true
}

// resolveArtifacts fills p.Resolved from p.Extensions.Artifacts.
func (o *Org) resolveArtifacts(p *Profile) {
	p.Resolved = nil
	for _, n := range p.Extensions.Artifacts {
		a, ok := o.FindArtifact(n)
		if !ok {
			continue // Validate reports it
		}
		r := ResolvedArtifact{Name: a.Name, Kind: a.Kind, Source: a.Source(), Digest: a.Digest}
		if c := o.ArtifactContent[a.Name]; c != nil && c.Files != nil {
			r.Files, r.Signer = c.Files, c.Signer
			if r.Digest == "" {
				r.Digest = c.Files.Digest()
			}
		}
		p.Resolved = append(p.Resolved, r)
	}
}

// loadLocalArtifacts reads every path-sourced artifact under dir. A failure
// is kept for Validate rather than failing Load, so halo-server still loads a
// policy whose artifact is broken (the release build is the gate).
func (o *Org) loadLocalArtifacts(dir string) {
	if o.SupplyChain == nil {
		return
	}
	o.ArtifactContent = map[string]*ArtifactContent{}
	for _, a := range o.SupplyChain.Artifacts {
		if a.Remote() || a.Path == "" {
			continue
		}
		if err := supplychain.CheckPath(a.Path); err != nil {
			o.ArtifactContent[a.Name] = &ArtifactContent{Err: err.Error()}
			continue
		}
		t, err := supplychain.ReadPath(filepath.Join(dir, filepath.FromSlash(a.Path)))
		if err != nil {
			o.ArtifactContent[a.Name] = &ArtifactContent{Err: err.Error()}
			continue
		}
		o.ArtifactContent[a.Name] = &ArtifactContent{Files: t}
	}
}

// artifactDirs are the repo-relative artifact paths Load must not parse as
// policy documents (a skill may well ship a YAML file).
func artifactDirs(root *Root) []string {
	if root.SupplyChain == nil {
		return nil
	}
	var out []string
	for _, a := range root.SupplyChain.Artifacts {
		if a.Path != "" && supplychain.CheckPath(a.Path) == nil {
			out = append(out, a.Path)
		}
	}
	return out
}

func underAny(rel string, dirs []string) bool {
	return slices.ContainsFunc(dirs, func(d string) bool { return rel == d || strings.HasPrefix(rel, d+"/") })
}

func (v *validator) supplyChain() {
	sc := v.org.SupplyChain
	for name, p := range v.org.Profiles {
		for i, n := range p.Extensions.Artifacts {
			if _, ok := v.org.FindArtifact(n); !ok {
				v.errf(fmt.Sprintf("profiles[%s].extensions.artifacts[%d]", name, i), "unknown artifact %q; declare it in halos.yaml supplyChain.artifacts", n)
			}
		}
	}
	if sc == nil {
		return
	}
	if sc.Scan != "" {
		v.oneOf("supplyChain.scan", "scan", sc.Scan, scanModes)
	}
	ids := map[string]bool{}
	for i, id := range sc.TrustedIdentities {
		path := fmt.Sprintf("supplyChain.trustedIdentities[%d]", i)
		if !artifactNameRe.MatchString(id.Name) {
			v.errf(path+".name", "%q must match %s", id.Name, artifactNameRe)
		}
		if ids[id.Name] {
			v.errf(path+".name", "duplicate identity %q", id.Name)
		}
		ids[id.Name] = true
		if (id.PublicKey == "") == (id.CosignKey == "") {
			v.errf(path, "set exactly one of publicKey and cosignKey")
		}
		if id.PublicKey != "" {
			if err := supplychain.CheckPath(id.PublicKey); err != nil {
				v.errf(path+".publicKey", "%v", err)
			}
		}
	}
	seen := map[string]bool{}
	for i, a := range sc.Artifacts {
		v.artifact(fmt.Sprintf("supplyChain.artifacts[%s]", a.Name), i, a, ids, seen)
	}
	for i, al := range sc.AllowFindings {
		path := fmt.Sprintf("supplyChain.allowFindings[%d]", i)
		if !sha256DigestRe.MatchString(al.Digest) {
			v.errf(path+".digest", "%q must be sha256:<64 hex>", al.Digest)
		}
		if !slices.ContainsFunc(supplychain.Rules, func(r supplychain.Rule) bool { return r.ID == al.Rule }) {
			v.errf(path+".rule", "unknown scan rule %q", al.Rule)
		}
		if strings.TrimSpace(al.Reason) == "" {
			v.errf(path+".reason", "a suppression needs a reason")
		}
	}
	v.scanArtifacts()
}

func (v *validator) artifact(path string, i int, a Artifact, ids, seen map[string]bool) {
	if !artifactNameRe.MatchString(a.Name) {
		path = fmt.Sprintf("supplyChain.artifacts[%d]", i)
		v.errf(path+".name", "%q must match %s", a.Name, artifactNameRe)
	}
	if seen[a.Name] {
		v.errf(path, "duplicate artifact %q", a.Name)
	}
	seen[a.Name] = true
	v.oneOf(path+".kind", "kind", a.Kind, artifactKinds)
	n := 0
	for _, set := range []bool{a.Path != "", a.Git != nil, a.OCI != ""} {
		if set {
			n++
		}
	}
	if n != 1 {
		v.errf(path, "set exactly one source: path, git or oci")
	}
	if a.Digest != "" && !sha256DigestRe.MatchString(a.Digest) {
		v.errf(path+".digest", "%q must be sha256:<64 hex>", a.Digest)
	}
	if a.Remote() && a.Digest == "" {
		v.errf(path+".digest", "an artifact from git or oci must be pinned by digest (halo release build prints it on a mismatch)")
	}
	if g := a.Git; g != nil {
		if u, err := url.Parse(g.URL); err != nil || (u.Scheme != "https" && u.Scheme != "ssh" && u.Scheme != "file") || (u.Scheme != "file" && u.Host == "") {
			v.errf(path+".git.url", "%q must be an https://, ssh:// or file:// URL", g.URL)
		}
		if !supplychain.CommitRe.MatchString(g.Commit) {
			v.errf(path+".git.commit", "%q is not a full commit id: an unpinned source (branch or tag) is refused", g.Commit)
		}
		if g.Path != "" {
			if err := supplychain.CheckPath(g.Path); err != nil {
				v.errf(path+".git.path", "%v", err)
			}
		}
	}
	if a.OCI != "" {
		if _, _, err := supplychain.SplitOCIRef(a.OCI); err != nil {
			v.errf(path+".oci", "%v", err)
		}
	}
	if s := a.Signature; s != nil {
		if !ids[s.Identity] {
			v.errf(path+".signature.identity", "unknown trusted identity %q", s.Identity)
		}
		if err := supplychain.CheckPath(s.File); err != nil {
			v.errf(path+".signature.file", "%v", err)
		}
	} else if a.Remote() && v.org.SupplyChain.RequireSignatures {
		v.errf(path+".signature", "supplyChain.requireSignatures: an artifact from git or oci must be signed by a trusted identity")
	}
	c := v.org.ArtifactContent[a.Name]
	switch {
	case c == nil:
	case c.Err != "":
		v.errf(path, "read %s: %s", a.Source(), c.Err)
	case a.Digest != "" && c.Files.Digest() != a.Digest:
		v.errf(path+".digest", "content of %s has digest %s, policy pins %s", a.Source(), c.Files.Digest(), a.Digest)
	}
	if c != nil && c.Err == "" && !a.Remote() {
		if crlf := supplychain.CRLFFiles(c.Files); len(crlf) > 0 {
			v.warnf(path, "%s", supplychain.CRLFWarning(crlf))
		}
	}
}

// scanArtifacts runs the static scan over every artifact with content.
// Findings warn, or are errors under scan: enforce; allowFindings entries
// suppress them by digest, and an entry that suppresses nothing warns.
func (v *validator) scanArtifacts() {
	sc := v.org.SupplyChain
	if sc.Scan == ScanOff {
		return
	}
	used := make([]bool, len(sc.AllowFindings))
	for _, a := range sc.Artifacts {
		c := v.org.ArtifactContent[a.Name]
		if c == nil || c.Files == nil {
			continue
		}
		d, sums := c.Files.Digest(), c.Files.Sums()
		for _, f := range supplychain.Scan(c.Files) {
			i := slices.IndexFunc(sc.AllowFindings, func(al AllowFinding) bool {
				return (al.Digest == d || al.Digest == "sha256:"+sums[f.Path]) && al.Rule == f.Rule && (al.Path == "" || al.Path == f.Path)
			})
			if i >= 0 {
				used[i] = true
				continue
			}
			path := fmt.Sprintf("supplyChain.artifacts[%s]", a.Name)
			msg := "scan " + f.String() + fmt.Sprintf(" (suppress with allowFindings: {digest: sha256:%s, rule: %s, path: %s, reason: ...})", sums[f.Path], f.Rule, f.Path)
			if sc.Scan == ScanEnforce {
				v.errf(path, "%s", msg)
			} else {
				v.warnf(path, "%s", msg)
			}
		}
	}
	for i, u := range used {
		al := sc.AllowFindings[i]
		if !u && !v.remoteUnfetched() {
			v.warnf(fmt.Sprintf("supplyChain.allowFindings[%d]", i), "suppresses nothing (digest %s, rule %s): remove it", al.Digest, al.Rule)
		}
	}
}

// remoteUnfetched reports a remote artifact whose content is not loaded, so
// an allowFindings entry for it cannot be judged unused.
func (v *validator) remoteUnfetched() bool {
	return slices.ContainsFunc(v.org.SupplyChain.Artifacts, func(a Artifact) bool {
		c := v.org.ArtifactContent[a.Name]
		return a.Remote() && (c == nil || c.Files == nil)
	})
}
