package promote

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/yamledit"
)

// ErrToggleChange marks a toggle change that cannot be applied or would make
// the policy invalid (as opposed to an infrastructure failure).
var ErrToggleChange = errors.New("invalid toggle change")

// ToggleChange is a console-requested edit of one Toggle document: its default
// state, expiry, and one rule's rollout percent or ring/group/user lists. Zero
// fields change nothing.
type ToggleChange struct {
	Default *bool    `json:"default,omitempty"`
	Expires string   `json:"expires,omitempty"`
	Rule    string   `json:"rule,omitempty"` // rule name or index; required with the fields below
	Percent *float64 `json:"percent,omitempty"`
	// Add*/Remove* edit the rule's rings, groups and users.
	AddRings     []string `json:"addRings,omitempty"`
	RemoveRings  []string `json:"removeRings,omitempty"`
	AddGroups    []string `json:"addGroups,omitempty"`
	RemoveGroups []string `json:"removeGroups,omitempty"`
	AddUsers     []string `json:"addUsers,omitempty"`
	RemoveUsers  []string `json:"removeUsers,omitempty"`
}

func (c ToggleChange) ruleEdit() bool {
	return c.Percent != nil || len(c.AddRings)+len(c.RemoveRings)+len(c.AddGroups)+len(c.RemoveGroups)+len(c.AddUsers)+len(c.RemoveUsers) > 0
}

// Summary is a one-line description for a PR title.
func (c ToggleChange) Summary() string {
	var p []string
	if c.Default != nil {
		p = append(p, "default "+strconv.FormatBool(*c.Default))
	}
	if c.Percent != nil {
		p = append(p, fmt.Sprintf("rule %s to %s%%", c.Rule, strconv.FormatFloat(*c.Percent, 'f', -1, 64)))
	} else if c.ruleEdit() {
		p = append(p, "targeting of rule "+c.Rule)
	}
	if c.Expires != "" {
		p = append(p, "expiry "+c.Expires)
	}
	return strings.Join(p, ", ")
}

// Check rejects a change that cannot be applied, before any file is touched.
func (c ToggleChange) Check() error {
	switch {
	case c.Default == nil && c.Expires == "" && !c.ruleEdit():
		return errors.New("nothing to change: set default, expires, or a rule edit")
	case c.ruleEdit() && c.Rule == "":
		return errors.New("rule (name or index) is required to edit percent, rings, groups or users")
	case !c.ruleEdit() && c.Rule != "":
		return errors.New("rule is set but there is nothing to change in it")
	case c.Percent != nil && (*c.Percent < 0 || *c.Percent > 100):
		return fmt.Errorf("percent %v must be within 0-100", *c.Percent)
	}
	if c.Expires != "" {
		if d, err := time.Parse(policy.ToggleDateLayout, c.Expires); err != nil || d.Format(policy.ToggleDateLayout) != c.Expires {
			return fmt.Errorf("expires %q must be YYYY-MM-DD", c.Expires)
		}
	}
	for _, l := range [][]string{c.AddRings, c.RemoveRings, c.AddGroups, c.RemoveGroups, c.AddUsers, c.RemoveUsers} {
		for _, v := range l {
			if strings.TrimSpace(v) == "" || len(v) > 256 || strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("invalid list entry %q", v)
			}
		}
	}
	return nil
}

// PlanToggle builds the policy-repo change that applies c to toggle name. dir
// is the policy repo. The result is validated with the full guardrails (a
// copy of the policy with the edit applied must load and have no error-severity
// issue) before it is returned; nothing in dir is written. Comments and the
// other documents of the file are kept; the edited file is re-encoded by
// yaml.v3 (2-space indent), so unusual formatting in it may be normalised.
func PlanToggle(dir string, name string, c ToggleChange) (*Change, error) {
	if err := c.Check(); err != nil {
		return nil, fmt.Errorf("toggle %s: %w: %w", name, ErrToggleChange, err)
	}
	ref, err := yamledit.Find(dir, policy.KindToggle, name)
	if err != nil {
		return nil, fmt.Errorf("toggle %s: %w", name, err)
	}
	apply := func(read ReadFunc) (map[string][]byte, error) {
		b, err := read(ref.Rel)
		if err != nil {
			return nil, fmt.Errorf("toggle %s: read %s: %w", name, ref.Rel, err)
		}
		nb, err := editToggleDoc(b, name, c)
		if err != nil {
			return nil, fmt.Errorf("toggle %s: %w: %w", name, ErrToggleChange, err)
		}
		return map[string][]byte{ref.Rel: nb}, nil
	}
	files, err := apply(func(f string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, filepath.FromSlash(f))) })
	if err != nil {
		return nil, err
	}
	// Only errors the change introduces count: a policy that was already invalid
	// elsewhere must not block an unrelated toggle edit.
	before, err := errorIssues(dir, nil)
	if err != nil {
		return nil, fmt.Errorf("toggle %s: load policy: %w", name, err)
	}
	after, err := errorIssues(dir, files)
	if err != nil {
		return nil, fmt.Errorf("toggle %s: %w: change would make the policy unloadable: %w", name, ErrToggleChange, err)
	}
	var added []string
	for _, m := range after {
		if !slices.Contains(before, m) {
			added = append(added, m)
		}
	}
	if len(added) > 0 {
		return nil, fmt.Errorf("toggle %s: %w: change would make the policy invalid: %s", name, ErrToggleChange, strings.Join(added, "; "))
	}
	ch := &Change{Files: map[string][]byte{}, Edit: apply}
	for f, nb := range files {
		if d := UnifiedDiff(f, string(ref.Data), string(nb)); d != "" {
			ch.Files[f], ch.Patch = nb, ch.Patch+d
		}
	}
	if ch.Patch == "" {
		return nil, fmt.Errorf("toggle %s: %w: the policy already has this change", name, ErrToggleChange)
	}
	return ch, nil
}

// errorIssues loads a copy of the policy under dir (YAML files only) with
// files overlaid and returns its error-severity validation issues.
func errorIssues(dir string, files map[string][]byte) ([]string, error) {
	tmp, err := os.MkdirTemp("", "halos-toggle-validate-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); !d.Type().IsRegular() || (ext != ".yaml" && ext != ".yml") { // symlinks are never followed
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p) //nolint:gosec // walks the operator-owned policy clone; regular files only
		if err != nil {
			return err
		}
		if nb, ok := files[filepath.ToSlash(rel)]; ok {
			b = nb
		}
		dst := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600) //nolint:gosec // dst is under our own temp dir; rel comes from walking dir
	})
	if err != nil {
		return nil, err
	}
	org, err := policy.Load(tmp)
	if err != nil {
		return nil, err
	}
	var msgs []string
	for _, i := range org.Validate() {
		if i.Severity == policy.SeverityError {
			msgs = append(msgs, i.String())
		}
	}
	return msgs, nil
}

// editToggleDoc applies c to the Toggle document called name in data (a
// possibly multi-document YAML file) and re-encodes the file.
func editToggleDoc(data []byte, name string, c ToggleChange) ([]byte, error) {
	var docs []*yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var target *yaml.Node
	for {
		var n yaml.Node
		if err := dec.Decode(&n); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parse yaml: %w", err)
		}
		docs = append(docs, &n)
		if len(n.Content) == 1 && n.Content[0].Kind == yaml.MappingNode {
			_, k := yamledit.Scalar(n.Content[0], "kind")
			_, nm := yamledit.Scalar(n.Content[0], "name")
			if k != nil && nm != nil && k.Value == string(policy.KindToggle) && nm.Value == name {
				target = n.Content[0]
			}
		}
	}
	if target == nil {
		return nil, fmt.Errorf("no Toggle document named %q", name)
	}
	if c.Default != nil {
		setScalar(target, "default", strconv.FormatBool(*c.Default), "!!bool")
	}
	if c.Expires != "" {
		setScalar(target, "expires", c.Expires, "!!str")
	}
	if c.ruleEdit() {
		rule, err := findRule(target, c.Rule)
		if err != nil {
			return nil, err
		}
		if c.Percent != nil {
			v, tag := strconv.FormatFloat(*c.Percent, 'f', -1, 64), "!!int" // the tag the encoder would infer, so none is printed
			if strings.Contains(v, ".") {
				tag = "!!float"
			}
			setScalar(rule, "percent", v, tag)
		}
		for _, e := range []struct {
			key         string
			add, remove []string
		}{{"rings", c.AddRings, c.RemoveRings}, {"groups", c.AddGroups, c.RemoveGroups}, {"users", c.AddUsers, c.RemoveUsers}} {
			if err := editList(rule, e.key, e.add, e.remove); err != nil {
				return nil, err
			}
		}
	}
	var out bytes.Buffer
	for i, d := range docs {
		if i > 0 {
			out.WriteString("---\n")
		}
		enc := yaml.NewEncoder(&out)
		enc.SetIndent(2)
		if err := enc.Encode(d); err != nil {
			return nil, fmt.Errorf("encode yaml: %w", err)
		}
		if err := enc.Close(); err != nil {
			return nil, fmt.Errorf("encode yaml: %w", err)
		}
	}
	return out.Bytes(), nil
}

// setScalar sets key in mapping m to a scalar, adding the key when absent and
// keeping an existing node's comments and quote style.
func setScalar(m *yaml.Node, key, val, tag string) {
	if _, v := yamledit.Scalar(m, key); v != nil {
		v.Kind, v.Value, v.Tag = yaml.ScalarNode, val, tag
		v.Content, v.Alias = nil, nil
		if tag != "!!str" {
			v.Style = 0
		} else if v.Style == 0 {
			v.Style = yaml.DoubleQuotedStyle
		}
		return
	}
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: val}
	if tag == "!!str" {
		n.Style = yaml.DoubleQuotedStyle
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, n)
}

func findRule(toggle *yaml.Node, ref string) (*yaml.Node, error) {
	_, rules := yamledit.Scalar(toggle, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return nil, errors.New("toggle has no rules")
	}
	for i, r := range rules.Content {
		if r.Kind != yaml.MappingNode {
			continue
		}
		if _, n := yamledit.Scalar(r, "name"); (n != nil && n.Value == ref) || strconv.Itoa(i) == ref {
			return r, nil
		}
	}
	return nil, fmt.Errorf("rule %q not found (use its name or index)", ref)
}

// editList adds and removes scalar entries of the rule's list key, creating it
// when needed; it refuses to empty the list.
func editList(rule *yaml.Node, key string, add, remove []string) error {
	if len(add)+len(remove) == 0 {
		return nil
	}
	_, seq := yamledit.Scalar(rule, key)
	if seq == nil {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		rule.Content = append(rule.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, seq)
	}
	if seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("rule %s is not a list", key)
	}
	has := func(v string) int {
		return slices.IndexFunc(seq.Content, func(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Value == v })
	}
	for _, v := range remove {
		i := has(v)
		if i < 0 {
			return fmt.Errorf("%s %q is not in the rule", key, v)
		}
		seq.Content = slices.Delete(seq.Content, i, i+1)
	}
	for _, v := range add {
		if has(v) < 0 {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
		}
	}
	if len(seq.Content) == 0 {
		// An empty list is no condition at all: the rule would match more users, not fewer.
		return fmt.Errorf("cannot remove every %s from the rule: that widens it to everyone; lower its percent or turn the toggle off instead", key)
	}
	return nil
}
