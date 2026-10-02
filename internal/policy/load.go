package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RootFile is the policy repo's root document.
const RootFile = "halos.yaml"

// Root is the halos.yaml document.
type Root struct {
	APIVersion string `yaml:"apiVersion,omitempty" json:"apiVersion,omitempty"`
	Kind       string `yaml:"kind,omitempty" json:"kind,omitempty"`
	Org        string `yaml:"org" json:"org"`
	// Identity configures OIDC for the portal, halo-proxy and enrollment (any IdP).
	Identity Identity `yaml:"identity,omitempty" json:"identity,omitempty"`
	// SelfService configures the developer portal (kiosk).
	SelfService SelfService `yaml:"selfService,omitempty" json:"selfService,omitempty"`
	// Simple mode fields (tools, provider, models, ...): see simple.go.
	Simple `yaml:",inline"`
}

// ReadRoot strictly decodes dir's halos.yaml.
func ReadRoot(dir string) (*Root, error) {
	rootPath := filepath.Join(dir, RootFile)
	rb, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", rootPath, err)
	}
	var root Root
	if err := strictDecode(rb, &root); err != nil {
		return nil, fmt.Errorf("policy: %s: %w", rootPath, err)
	}
	if root.Org == "" {
		return nil, fmt.Errorf("policy: %s: org is required", rootPath)
	}
	if root.APIVersion != "" { // optional on the root document
		if _, err := checkAPIVersion(root.APIVersion); err != nil {
			return nil, fmt.Errorf("policy: %s: %w", rootPath, err)
		}
	}
	return &root, nil
}

// checkAPIVersion accepts APIVersion and the deprecated APIVersionV1Alpha1
// (reporting deprecated=true); anything else is an error.
func checkAPIVersion(v string) (deprecated bool, err error) {
	switch v {
	case APIVersion:
		return false, nil
	case APIVersionV1Alpha1:
		return true, nil
	}
	return false, fmt.Errorf("apiVersion %q not supported (want %q)", v, APIVersion)
}

// deprecation is the warning for a file that still uses APIVersionV1Alpha1.
func deprecation(dir, path string) Issue {
	if rel, err := filepath.Rel(dir, path); err == nil {
		path = filepath.ToSlash(rel)
	}
	return Issue{SeverityWarning, path, fmt.Sprintf("apiVersion %s is deprecated; it reads as %s with identical semantics until halos.dev/v2. Run `halo migrate --policy-dir %s`", APIVersionV1Alpha1, APIVersion, dir)}
}

// Load reads every *.yaml/*.yml under dir (multi-document files supported),
// dispatches by kind, and returns the assembled Org. Decoding is strict:
// unknown fields are errors, reported with the yaml line ("line N") and file.
func Load(dir string) (*Org, error) {
	rootPath := filepath.Join(dir, RootFile)
	root, err := ReadRoot(dir)
	if err != nil {
		return nil, err
	}

	org := &Org{Name: root.Org, Identity: root.Identity, SelfService: root.SelfService, Profiles: map[string]*Profile{}}
	if root.APIVersion == APIVersionV1Alpha1 {
		org.Deprecations = append(org.Deprecations, deprecation(dir, rootPath))
	}
	var files []string
	// WalkDir does not descend into a symlinked root, and git-sync (the Helm chart's
	// --policy-dir=/policy/current) serves the repo through exactly that: walk the
	// target, but keep reporting paths under dir.
	walkRoot := dir
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		walkRoot = r
	}
	err = filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != walkRoot && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if rel, err := filepath.Rel(walkRoot, p); err == nil {
			p = filepath.Join(dir, rel)
		}
		if p == rootPath {
			return nil
		}
		if ext := filepath.Ext(p); ext == ".yaml" || ext == ".yml" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("policy: walk %s: %w", dir, err)
	}
	sort.Strings(files) // deterministic order

	for _, f := range files {
		deprecated, err := loadFile(org, f)
		if err != nil {
			return nil, err
		}
		if deprecated {
			org.Deprecations = append(org.Deprecations, deprecation(dir, f))
		}
	}
	if root.Enabled() {
		if err := overlaySimple(root, org); err != nil {
			return nil, fmt.Errorf("policy: %s: %w", rootPath, err)
		}
	}
	sort.SliceStable(org.Rings, func(i, j int) bool { return org.Rings[i].Order < org.Rings[j].Order })
	return org, nil
}

func strictDecode(b []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

// loadFile decodes each document of a file. Pass 1 (yaml.Node) finds each
// document's kind; pass 2 decodes strictly into the matching type. Line
// numbers in pass-2 errors are relative to the file since it is one stream.
// deprecated reports whether any document used APIVersionV1Alpha1.
func loadFile(org *Org, path string) (deprecated bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("policy: read %s: %w", path, err)
	}
	var kinds []Kind
	nd := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var n yaml.Node
		if err := nd.Decode(&n); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return false, fmt.Errorf("policy: %s: %w", path, err)
		}
		k, err := nodeKind(&n)
		if err != nil {
			return false, fmt.Errorf("policy: %s:%d: %w", path, n.Line, err)
		}
		kinds = append(kinds, k)
	}

	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	for i, k := range kinds {
		var target any
		switch k {
		case "":
			target = new(any) // empty document
		case KindProfile:
			target = new(Profile)
		case KindRing:
			target = new(Ring)
		case KindExperiment:
			target = new(Experiment)
		case KindGateway:
			target = new(Gateway)
		case KindToggle:
			target = new(Toggle)
		case KindRollout:
			target = new(Rollout)
		default:
			return false, fmt.Errorf("policy: %s: document %d: unknown kind %q", path, i+1, k)
		}
		if err := dec.Decode(target); err != nil {
			return false, fmt.Errorf("policy: %s: document %d (%s): %w", path, i+1, k, err)
		}
		dep, err := org.add(target)
		if err != nil {
			return false, fmt.Errorf("policy: %s: document %d (%s): %w", path, i+1, k, err)
		}
		deprecated = deprecated || dep
	}
	return deprecated, nil
}

func nodeKind(n *yaml.Node) (Kind, error) {
	if n.Kind != yaml.DocumentNode || len(n.Content) != 1 {
		return "", nil
	}
	m := n.Content[0]
	if m.Kind == yaml.ScalarNode && m.Tag == "!!null" {
		return "", nil
	}
	if m.Kind != yaml.MappingNode {
		return "", errors.New("document must be a mapping")
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "kind" {
			return Kind(m.Content[i+1].Value), nil
		}
	}
	return "", errors.New("document has no kind")
}

// add appends a decoded document. A v1alpha1 document is normalised to
// APIVersion (same semantics, same snapshot bytes) and reported deprecated.
func (o *Org) add(v any) (deprecated bool, err error) {
	check := func(m *Meta) error {
		dep, err := checkAPIVersion(m.APIVersion)
		if err != nil {
			return err
		}
		if m.Name == "" {
			return errors.New("name is required")
		}
		m.APIVersion, deprecated = APIVersion, dep
		return nil
	}
	switch t := v.(type) {
	case *Profile:
		if err := check(&t.Meta); err != nil {
			return false, err
		}
		if _, dup := o.Profiles[t.Name]; dup {
			return false, fmt.Errorf("duplicate profile %q", t.Name)
		}
		o.Profiles[t.Name] = t
	case *Ring:
		if err := check(&t.Meta); err != nil {
			return false, err
		}
		o.Rings = append(o.Rings, t)
	case *Experiment:
		if err := check(&t.Meta); err != nil {
			return false, err
		}
		o.Experiments = append(o.Experiments, t)
	case *Toggle:
		if err := check(&t.Meta); err != nil {
			return false, err
		}
		if slices.ContainsFunc(o.Toggles, func(e *Toggle) bool { return e.Name == t.Name }) {
			return false, fmt.Errorf("duplicate toggle %q", t.Name)
		}
		o.Toggles = append(o.Toggles, t)
	case *Rollout:
		if err := check(&t.Meta); err != nil {
			return false, err
		}
		o.Rollouts = append(o.Rollouts, t)
	case *Gateway:
		if err := check(&t.Meta); err != nil {
			return false, err
		}
		if o.Gateway != nil {
			return false, fmt.Errorf("multiple Gateway documents (%q and %q)", o.Gateway.Name, t.Name)
		}
		o.Gateway = t
	}
	return deprecated, nil
}
