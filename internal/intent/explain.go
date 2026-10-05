package intent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/yamledit"
)

// Doc is one low-level policy document and the file it belongs in.
type Doc struct {
	Kind policy.Kind
	Name string
	Path string // canonical repo-relative path
	v    any
}

// Docs lists every document of the loaded (expanded and overlaid) policy in
// a stable order: gateway, profiles, rings, experiments, toggles, rollouts.
func Docs(org *policy.Org) []Doc {
	var out []Doc
	if g := org.Gateway; g != nil {
		out = append(out, Doc{policy.KindGateway, g.Name, "gateway.yaml", g})
	}
	for _, n := range sortedKeys(org.Profiles) {
		out = append(out, Doc{policy.KindProfile, n, "profiles/" + n + ".yaml", org.Profiles[n]})
	}
	for _, r := range org.Rings {
		out = append(out, Doc{policy.KindRing, r.Name, "rings/" + r.Name + ".yaml", r})
	}
	for _, e := range org.Experiments {
		out = append(out, Doc{policy.KindExperiment, e.Name, "experiments/" + e.Name + ".yaml", e})
	}
	for _, t := range org.Toggles {
		out = append(out, Doc{policy.KindToggle, t.Name, "toggles/" + t.Name + ".yaml", t})
	}
	for _, r := range org.Rollouts {
		out = append(out, Doc{policy.KindRollout, r.Name, "rollouts/" + r.Name + ".yaml", r})
	}
	return out
}

// YAML marshals the document.
func (d Doc) YAML() ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(d.v); err != nil {
		return nil, fmt.Errorf("intent: marshal %s %s: %w", d.Kind, d.Name, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("intent: marshal %s %s: %w", d.Kind, d.Name, err)
	}
	return b.Bytes(), nil
}

// Generated reports which kind/name documents simple mode expands halos.yaml
// into (before any explicit overlay).
func (r *Repo) Generated() (map[string]bool, error) {
	out := map[string]bool{}
	if !r.Simple() {
		return out, nil
	}
	gen, err := r.Root.Expand()
	if err != nil {
		return nil, err
	}
	for _, d := range Docs(gen) {
		out[string(d.Kind)+"/"+d.Name] = true
	}
	return out, nil
}

// Explained is one document as `halo explain` shows it.
type Explained struct {
	Kind   policy.Kind `json:"kind"`
	Name   string      `json:"name"`
	Source string      `json:"source"`
	YAML   string      `json:"yaml"`
}

// Explain lists the effective policy, optionally only kind (case-insensitive).
// Generated documents show their merged form; explicit ones their source text.
func (r *Repo) Explain(kind string) ([]Explained, error) {
	gen, err := r.Generated()
	if err != nil {
		return nil, err
	}
	var out []Explained
	for _, d := range Docs(r.Org) {
		if kind != "" && !strings.EqualFold(kind, string(d.Kind)) {
			continue
		}
		f, ferr := yamledit.Find(r.Dir, d.Kind, d.Name)
		var b []byte
		src := ""
		switch {
		case gen[string(d.Kind)+"/"+d.Name]:
			src = policy.RootFile + " (simple mode)"
			if ferr == nil {
				src += ", overlaid by " + f.Rel
			}
			b, err = d.YAML()
		case ferr == nil:
			src = f.Rel
			b, err = yaml.Marshal(f.Mapping)
		default:
			b, err = d.YAML()
		}
		if err != nil {
			return nil, fmt.Errorf("intent: explain %s %s: %w", d.Kind, d.Name, err)
		}
		out = append(out, Explained{d.Kind, d.Name, src, string(b)})
	}
	return out, nil
}

// simpleKeys are the halos.yaml keys eject removes.
var simpleKeys = []string{"tools", "provider", "models", "gateway", "telemetry", "team", "safety", "rollout"}

// Eject writes the documents simple mode generates, merged with any explicit
// overlay, as ordinary files, and strips the simple keys from halos.yaml.
// The policy it leaves loads to the same Org. An overlay document is replaced
// in place when it is alone in its file; a file holding other documents, or
// an unrelated file at the canonical path, is an error (nothing is clobbered).
func (r *Repo) Eject() (*Change, error) {
	if !r.Simple() {
		return nil, fmt.Errorf("intent: %s has no simple-mode keys: nothing to eject", policy.RootFile)
	}
	gen, err := r.Generated()
	if err != nil {
		return nil, err
	}
	c := newChange(r.Dir)
	for _, d := range Docs(r.Org) {
		if !gen[string(d.Kind)+"/"+d.Name] {
			continue
		}
		b, err := d.YAML()
		if err != nil {
			return nil, err
		}
		path := d.Path
		if f, err := yamledit.Find(r.Dir, d.Kind, d.Name); err == nil {
			if n, err := countDocs(f.Data); err != nil || n != 1 {
				return nil, fmt.Errorf("intent: %s holds other documents besides %s %s; move it to its own file first", f.Rel, d.Kind, d.Name)
			}
			path = f.Rel
		} else if _, err := os.Stat(filepath.Join(r.Dir, filepath.FromSlash(path))); err == nil {
			return nil, fmt.Errorf("intent: %s exists and does not hold %s %s; refusing to overwrite", path, d.Kind, d.Name)
		}
		c.Files[path] = append([]byte(fmt.Sprintf("# Ejected from %s simple mode by `halo eject`.\n", policy.RootFile)), b...)
	}
	root, err := stripRoot(r.Dir)
	if err != nil {
		return nil, err
	}
	c.Files[policy.RootFile] = root
	return c, nil
}

func countDocs(b []byte) (int, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	n := 0
	for {
		var v yaml.Node
		if err := dec.Decode(&v); errors.Is(err, io.EOF) {
			return n, nil
		} else if err != nil {
			return n, err
		}
		if len(v.Content) > 0 && (v.Content[0].Kind != yaml.ScalarNode || v.Content[0].Tag != "!!null") {
			n++
		}
	}
}

// stripRoot returns halos.yaml without its simple-mode keys (comments on
// the remaining keys are kept).
func stripRoot(dir string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, policy.RootFile))
	if err != nil {
		return nil, fmt.Errorf("intent: %w", err)
	}
	var n yaml.Node
	if err := yaml.Unmarshal(b, &n); err != nil || len(n.Content) != 1 {
		return nil, fmt.Errorf("intent: parse %s: %v", policy.RootFile, err)
	}
	m := n.Content[0]
	var kept []*yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		if !slices.Contains(simpleKeys, m.Content[i].Value) {
			kept = append(kept, m.Content[i], m.Content[i+1])
		}
	}
	m.Content = kept
	// The init header describes simple mode; keep only the schema hint.
	head := "# Ejected by `halo eject`: the low-level documents are now the whole policy."
	first := m
	if len(m.Content) > 0 {
		first = m.Content[0] // yaml.v3 hangs a leading comment on the first key
	}
	for _, c := range []string{n.HeadComment, m.HeadComment, first.HeadComment} {
		for _, l := range strings.Split(c, "\n") {
			if strings.HasPrefix(l, "# yaml-language-server:") {
				head = l + "\n" + head
			}
		}
	}
	n.HeadComment, m.HeadComment, first.HeadComment = head, "", ""
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&n); err != nil {
		return nil, fmt.Errorf("intent: write %s: %w", policy.RootFile, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("intent: write %s: %w", policy.RootFile, err)
	}
	return out.Bytes(), nil
}

// InitOptions shape a new simple-mode halos.yaml.
type InitOptions struct {
	Org      string
	Tools    map[string]string // tool -> version
	Provider string
	Project  string            // Google Cloud project, provider vertex
	Models   map[string]string // alias -> model id
	// ToolModels maps a tool to the alias it starts on instead of default (set by Complete).
	ToolModels map[string]string
	Gateway    string
	// GatewayEngine: "" (halo-proxy), kong, or external (your own API gateway).
	GatewayEngine string
	Issuer        string
	ClientID      string   // OIDC client id (portal login); optional
	Admins        []string // identity.adminGroups (ring0 team and portal admins); optional
	Safety        string
	Rollout       string
}

// Complete fills what init must not leave to the user: the default alias's
// model for the provider and, for each tool whose wire the default model's
// provider cannot answer (codex needs OpenAI Responses, gemini-cli Gemini), a
// model alias named after the tool on its vendor's provider. A --model
// <tool>=<id> the user gave wins (an unprefixed id runs on the tool's
// vendor); ask, if set, is offered the default and may change it. It returns
// one note per alias it added.
func (o *InitOptions) Complete(ask func(question, def string) (string, error)) ([]string, error) {
	if o.Provider == "vertex" && o.Project == "" {
		return nil, fmt.Errorf("intent: provider vertex needs a Google Cloud project (--project)")
	}
	if o.Models == nil {
		o.Models = map[string]string{}
	}
	if o.Models["default"] == "" {
		o.Models["default"] = policy.DefaultModelFor(o.Provider)
	}
	o.ToolModels = map[string]string{}
	var notes []string
	for _, t := range sortedKeys(o.Tools) {
		vendor, need := policy.ToolModelFor(t, o.Provider, o.Models["default"])
		id, gave := o.Models[t]
		if !gave && !need {
			continue
		}
		if !gave {
			id = vendor
			if ask != nil {
				a, err := ask(fmt.Sprintf("Model for %s (%s cannot serve it; provider/model)", t, o.Provider), vendor)
				if err != nil {
					return nil, err
				}
				id = a
			}
		}
		// An unprefixed id runs on the tool's vendor when the default provider cannot serve it.
		if p, _ := policy.SplitModel(id, ""); p == "" && need {
			id = vendor[:strings.Index(vendor, "/")+1] + id
		}
		o.Models[t], o.ToolModels[t] = id, t
		if !gave {
			notes = append(notes, fmt.Sprintf("%s: added model alias %s = %s (the default model's provider cannot serve %s; change it with --model %s=<id>)", t, t, id, t, t))
		}
	}
	return notes, nil
}

// InitFile renders a simple-mode halos.yaml. It is validated by the caller
// (Load + Validate on the written repo) like any other change.
func InitFile(o InitOptions) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# yaml-language-server: $schema=https://halos.dev/schemas/halos.schema.json\n")
	fmt.Fprintf(&b, "# Simple mode: this file is the whole policy. `halo explain` prints what it\n")
	fmt.Fprintf(&b, "# expands to; `halo eject` writes that out when you need full control.\n")
	fmt.Fprintf(&b, "apiVersion: %s\nkind: Halos\norg: %s\ntools:\n", policy.APIVersion, o.Org)
	for _, t := range sortedKeys(o.Tools) {
		if m := o.ToolModels[t]; m != "" {
			fmt.Fprintf(&b, "  %s: {version: %s, model: %s}\n", t, o.Tools[t], m)
		} else {
			fmt.Fprintf(&b, "  %s: %s\n", t, o.Tools[t])
		}
	}
	prov := o.Provider
	if o.Project != "" {
		prov = fmt.Sprintf("{name: %s, project: %s}", o.Provider, o.Project)
	}
	fmt.Fprintf(&b, "provider: %s   # anthropic | bedrock | vertex | openai | gemini | multi\nmodels:\n", prov)
	keys := sortedKeys(o.Models)
	sort.SliceStable(keys, func(i, j int) bool { return keys[i] == "default" && keys[j] != "default" }) // default first
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s: %s\n", k, yamledit.Quote(o.Models[k], 0))
	}
	fmt.Fprintf(&b, "gateway: %s\n", o.Gateway)
	if o.GatewayEngine != "" {
		fmt.Fprintf(&b, "gatewayEngine: %s   # halo-proxy | kong | external (your own API gateway)\n", o.GatewayEngine)
	}
	if o.Issuer != "" {
		fmt.Fprintf(&b, "identity: {issuer: %s", o.Issuer)
		if o.ClientID != "" {
			fmt.Fprintf(&b, ", clientID: %s", yamledit.Quote(o.ClientID, 0))
		}
		fmt.Fprint(&b, ", audience: halos")
		if len(o.Admins) > 0 {
			q := make([]string, len(o.Admins))
			for i, g := range o.Admins {
				q[i] = yamledit.Quote(g, 0)
			}
			fmt.Fprintf(&b, ", adminGroups: [%s]", strings.Join(q, ", "))
		}
		fmt.Fprint(&b, "}\n")
	}
	fmt.Fprintf(&b, "safety: %s   # strict | standard | relaxed\n", o.Safety)
	fmt.Fprintf(&b, "rollout: %s   # fast | standard | careful\n", o.Rollout)
	return []byte(b.String())
}
