package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/policy"
)

func (a *app) cmdUnits() *cobra.Command {
	c := &cobra.Command{Use: "units", Short: "Org hierarchy: business units and teams with delegated owners (ADR-0018)"}
	var defaults []string
	co := &cobra.Command{
		Use:         "codeowners",
		Annotations: policyDirAnno,
		Short:       "Print a CODEOWNERS file that gives each unit's owners its directory in the policy repo",
		Long: "Each Unit's directory goes to its owners and its ancestors' owners; --owner sets the catch-all line " +
			"(the central team keeps halos.yaml, profiles and rings) and is required when there is a top-level unit: a top-level " +
			"unit's own file goes to those root owners alone, because its members selector draws from the whole org. Paths are relative to the git repository root " +
			"containing the policy dir. Pair it with branch protection that requires code-owner review and `halo validate`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.loadValid(dir)
			if err != nil {
				return err
			}
			prefix, err := repoPrefix(dir)
			if err != nil {
				return err
			}
			b, err := org.CodeOwners(prefix, defaults)
			if err != nil {
				return err
			}
			return a.emit(map[string]string{"codeowners": string(b)}, func() { fmt.Fprint(a.out, string(b)) })
		},
	}
	co.Flags().StringSliceVar(&defaults, "owner", nil, "owner of everything outside unit directories (repeatable), e.g. @acme/ai-platform")
	c.AddCommand(co)
	return c
}

// repoPrefix is dir relative to the root of the git repository containing it
// ("" when dir is the root or not inside a repository), slash-separated.
func repoPrefix(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", dir, err)
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	for root := abs; ; {
		if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
			rel, err := filepath.Rel(root, abs)
			if err != nil {
				return "", fmt.Errorf("resolve %s: %w", dir, err)
			}
			return strings.TrimPrefix(filepath.ToSlash(rel), "."), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("find git root of %s: %w", dir, err)
		}
		parent := filepath.Dir(root)
		if parent == root {
			return "", nil
		}
		root = parent
	}
}

// explained is `halo explain --user`: where a user lands and their effective
// config, field by field, with the layer that set each value.
type explained struct {
	User       string               `json:"user"`
	Groups     []string             `json:"groups"`
	Ring       string               `json:"ring"`
	Release    string               `json:"pinnedRelease,omitempty"`
	Profile    string               `json:"profile"`
	Experiment string               `json:"experiment,omitempty"`
	Variant    string               `json:"variant,omitempty"`
	Units      []string             `json:"units"` // root first; the user's unit last
	Fields     []policy.FieldSource `json:"fields"`
}

// explainUser resolves user the way the fleet does: ring by internal/assign
// (ResolveRing), the first running client-axis experiment variant enrolling
// it (its profile replaces the ring's), then the unit (MatchUnit).
func explainUser(org *policy.Org, user string, groups []string) (*explained, error) {
	sub := policy.Subject{ID: user, Groups: groups}
	ring := org.ResolveRing(sub)
	if ring == nil {
		return nil, fmt.Errorf("no ring matches user %q", user)
	}
	res := &explained{User: user, Groups: groups, Ring: ring.Name, Release: ring.Release, Profile: ring.Profile, Units: []string{}}
	if res.Groups == nil {
		res.Groups = []string{}
	}
	for _, e := range org.ClientExperiments(ring.Name) {
		if v := e.ResolveVariant(sub, ring.Name); v != nil {
			res.Profile, res.Experiment, res.Variant = v.Profile, e.Name, v.Name
			break
		}
	}
	unit := ""
	if u := org.ResolveUnit(sub); u != nil {
		unit = u.Name
		chain, err := org.UnitChain(unit)
		if err != nil {
			return nil, err
		}
		for _, c := range chain {
			res.Units = append(res.Units, c.Name)
		}
	}
	_, fields, err := org.ExplainEffective(res.Profile, unit)
	if err != nil {
		return nil, err
	}
	res.Fields = fields
	return res, nil
}

func (a *app) printExplained(r *explained) {
	fmt.Fprintf(a.out, "user     %s\nring     %s\nprofile  %s\n", r.User, a.bold(r.Ring), r.Profile)
	if r.Release != "" {
		fmt.Fprintf(a.out, "note     ring is pinned to release %s; devices run that release, not this profile\n", r.Release)
	}
	if r.Variant != "" {
		fmt.Fprintf(a.out, "variant  %s = %s (its profile replaces the ring's)\n", r.Experiment, r.Variant)
	}
	unit := "(none)"
	if len(r.Units) > 0 {
		unit = strings.Join(r.Units, " > ")
	}
	fmt.Fprintf(a.out, "unit     %s\n\n", unit)
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "FIELD\tVALUE\tSET BY")
	for _, f := range r.Fields {
		v, more, _ := strings.Cut(f.Value, "\n")
		if more != "" {
			v += " ..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", f.Path, v, f.Source)
	}
	tw.Flush()
}
