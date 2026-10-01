package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/toggle"
	"github.com/dshakes/halos/internal/yamledit"
)

type toggleRow struct {
	Name        string `json:"name"`
	Axis        string `json:"axis"`
	Description string `json:"description,omitempty"`
	Owner       string `json:"owner"`
	Default     bool   `json:"default"`
	Rules       int    `json:"rules"`
	Expires     string `json:"expires,omitempty"`
	Stale       bool   `json:"stale"`
}

type listTogglesOut struct {
	Toggles []toggleRow `json:"toggles"`
}

type evalToggleIn struct {
	User   string   `json:"user" jsonschema:"user id"`
	Groups []string `json:"groups,omitempty" jsonschema:"IdP groups"`
	Ring   string   `json:"ring,omitempty" jsonschema:"ring (default: resolved from the user and groups)"`
	Name   string   `json:"name,omitempty" jsonschema:"toggle name (default: all toggles)"`
	Killed []string `json:"killed,omitempty" jsonschema:"toggle names to treat as killed (what-if)"`
}

type evalToggleOut struct {
	Subject   toggle.Subject    `json:"subject"`
	Decisions []toggle.Decision `json:"decisions"`
}

type toggleChangeIn struct {
	Name    string   `json:"name" jsonschema:"toggle name"`
	Reason  string   `json:"reason" jsonschema:"why; recorded in the commit message"`
	Default *bool    `json:"default,omitempty" jsonschema:"new default state"`
	Rule    string   `json:"rule,omitempty" jsonschema:"rule name or index whose percent to change (with percent)"`
	Percent *float64 `json:"percent,omitempty" jsonschema:"new rollout percent 0-100 for rule; 0 matches nobody (ramp-down), never everyone"`
	Expires string   `json:"expires,omitempty" jsonschema:"new expiry date YYYY-MM-DD"`
	DryRun  *bool    `json:"dry_run,omitempty" jsonschema:"default true: return the diff and change nothing"`
}

func (s *srv) addToggleReadTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "list_toggles", Description: "List feature toggles with owner, default, rule count and staleness.", Annotations: readOnly}, s.listToggles)
	mcp.AddTool(m, &mcp.Tool{Name: "evaluate_toggle", Description: "Evaluate feature toggles for a user (ring, groups): on/off with the rule trace.", Annotations: readOnly}, s.evaluateToggle)
}

func (s *srv) addToggleWriteTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "propose_toggle_change", Annotations: &mcp.ToolAnnotations{DestructiveHint: boolp(false)},
		Description: "Change a toggle's default, a rule's rollout percent or its expiry in policy YAML. dry_run (default true) returns the diff; otherwise commits it to a new local branch. Never pushes or merges; a kill is a separate, signed halo-server action."}, s.proposeToggleChange)
}

func (s *srv) listToggles(_ context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, listTogglesOut, error) {
	org, err := s.load()
	if err != nil {
		return nil, listTogglesOut{}, err
	}
	out := listTogglesOut{Toggles: []toggleRow{}}
	for _, t := range org.Toggles {
		out.Toggles = append(out.Toggles, toggleRow{t.Name, string(t.Axis), t.Description, t.Owner, t.Default, len(t.Rules), t.Expires, t.Expired(time.Now())})
	}
	return nil, out, nil
}

func (s *srv) evaluateToggle(_ context.Context, _ *mcp.CallToolRequest, in evalToggleIn) (*mcp.CallToolResult, evalToggleOut, error) {
	if in.User == "" {
		return nil, evalToggleOut{}, errors.New("user is required")
	}
	org, err := s.load()
	if err != nil {
		return nil, evalToggleOut{}, err
	}
	sub := toggle.Subject{ID: in.User, Groups: in.Groups, Ring: in.Ring}
	if sub.Ring == "" {
		if r := org.ResolveRing(policy.Subject{ID: in.User, Groups: in.Groups}); r != nil {
			sub.Ring = r.Name
		}
	} else if _, err := findRing(org, in.Ring); err != nil {
		return nil, evalToggleOut{}, err
	}
	out := evalToggleOut{Subject: sub, Decisions: []toggle.Decision{}}
	for _, d := range toggle.EvalAll(org, sub, in.Killed) {
		if in.Name == "" || d.Name == in.Name {
			out.Decisions = append(out.Decisions, d)
		}
	}
	if in.Name != "" && len(out.Decisions) == 0 {
		return nil, evalToggleOut{}, fmt.Errorf("unknown toggle %q", in.Name)
	}
	return nil, out, nil
}

func (s *srv) proposeToggleChange(ctx context.Context, _ *mcp.CallToolRequest, in toggleChangeIn) (*mcp.CallToolResult, writeOut, error) {
	reason, err := need(in.Reason)
	if err != nil {
		return nil, writeOut{}, err
	}
	if in.Default == nil && in.Percent == nil && in.Expires == "" {
		return nil, writeOut{}, errors.New("nothing to change: set default, percent (with rule) or expires")
	}
	if (in.Percent == nil) != (in.Rule == "") {
		return nil, writeOut{}, errors.New("rule and percent go together")
	}
	if in.Percent != nil && (*in.Percent < 0 || *in.Percent > 100) {
		return nil, writeOut{}, fmt.Errorf("percent %v must be within 0-100", *in.Percent)
	}
	if in.Expires != "" {
		if d, err := time.Parse(policy.ToggleDateLayout, in.Expires); err != nil || d.Format(policy.ToggleDateLayout) != in.Expires {
			return nil, writeOut{}, fmt.Errorf("expires %q must be YYYY-MM-DD", in.Expires)
		}
	}
	if _, err := s.loadValid(); err != nil {
		return nil, writeOut{}, err
	}
	ref, err := yamledit.Find(s.dir, policy.KindToggle, in.Name)
	if err != nil {
		return nil, writeOut{}, err
	}
	data, err := editToggle(ref, in)
	if err != nil {
		return nil, writeOut{}, err
	}
	// As for experiments: preview from the working tree, commit re-applies the
	// same edit to HEAD's file so uncommitted changes are never committed.
	edit := func(read promote.ReadFunc) (map[string][]byte, error) {
		b, err := read(ref.Rel)
		if err != nil {
			return nil, err
		}
		m, err := yamledit.Parse(b, policy.KindToggle, in.Name)
		if err != nil {
			return nil, fmt.Errorf("parse committed %s: %w", ref.Rel, err)
		}
		if m == nil {
			return nil, fmt.Errorf("toggle %q not found in committed %s", in.Name, ref.Rel)
		}
		nd, err := editToggle(&yamledit.Doc{Path: ref.Rel, Rel: ref.Rel, Data: b, Mapping: m}, in)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{ref.Rel: nd}, nil
	}
	out, err := s.finish(ctx, isDry(in.DryRun), map[string][]byte{ref.Rel: data}, edit, "halos/toggle-"+in.Name,
		"halo: change toggle "+in.Name, reason)
	return nil, out, err
}

// editToggle applies in to d one scalar splice at a time (each edit re-parses,
// since a splice shifts later offsets). A key the YAML does not set yet is an
// error: edit those by hand, where review can see the structure.
func editToggle(d *yamledit.Doc, in toggleChangeIn) ([]byte, error) {
	step := func(find func(*yamledit.Doc) (*yaml.Node, error), set func(*yamledit.Doc, *yaml.Node) ([]byte, error)) error {
		n, err := find(d)
		if err != nil {
			return err
		}
		data, err := set(d, n)
		if err != nil {
			return err
		}
		m, err := yamledit.Parse(data, policy.KindToggle, in.Name)
		if err != nil || m == nil {
			return fmt.Errorf("edit left %s unparsable: %v", d.Rel, err)
		}
		*d = yamledit.Doc{Path: d.Path, Rel: d.Rel, Data: data, Mapping: m}
		return nil
	}
	key := func(k string) func(*yamledit.Doc) (*yaml.Node, error) {
		return func(d *yamledit.Doc) (*yaml.Node, error) {
			if n := d.Get(k); n != nil {
				return n, nil
			}
			return nil, fmt.Errorf("%s has no %q to edit; add it by hand", d.Rel, k)
		}
	}
	raw := func(v string) func(*yamledit.Doc, *yaml.Node) ([]byte, error) {
		return func(d *yamledit.Doc, n *yaml.Node) ([]byte, error) { return d.SetRaw(n, v) }
	}
	if in.Default != nil {
		if err := step(key("default"), raw(strconv.FormatBool(*in.Default))); err != nil {
			return nil, err
		}
	}
	if in.Expires != "" {
		quoted := func(d *yamledit.Doc, _ *yaml.Node) ([]byte, error) { return d.SetField("expires", in.Expires) } // keeps the quote style
		if err := step(key("expires"), quoted); err != nil {
			return nil, err
		}
	}
	if in.Percent != nil {
		find := func(d *yamledit.Doc) (*yaml.Node, error) {
			rules := d.Get("rules")
			if rules == nil || rules.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%s has no rules", d.Rel)
			}
			for i, r := range rules.Content {
				_, nm := yamledit.Scalar(r, "name")
				if (nm != nil && nm.Value == in.Rule) || strconv.Itoa(i) == in.Rule {
					if _, p := yamledit.Scalar(r, "percent"); p != nil {
						return p, nil
					}
					return nil, fmt.Errorf("rule %q has no percent to edit; add it by hand", in.Rule)
				}
			}
			return nil, fmt.Errorf("rule %q not found (names or indexes)", in.Rule)
		}
		if err := step(find, raw(strings.TrimRight(strings.TrimRight(strconv.FormatFloat(*in.Percent, 'f', 4, 64), "0"), "."))); err != nil {
			return nil, err
		}
	}
	return d.Data, nil
}
