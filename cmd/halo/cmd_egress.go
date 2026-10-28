package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// egressBy names the native mechanism each harness enforces egress with
// (ADR-0032); a harness missing here does not enforce it.
var egressBy = map[string]string{
	"claude-code": "sandbox.network allowedDomains/deniedDomains for Bash, WebFetch(domain:...) deny rules for the fetch tool",
	"codex":       "requirements.toml [experimental_network] for sandboxed commands",
	"copilot-cli": "managed sandbox.userPolicy.network for sandboxed commands",
	"opencode":    "the webfetch permission only (one action for every URL; bash is not sandboxed)",
}

type egressHarness struct {
	Name     string   `json:"name"`
	Enforced bool     `json:"enforced"`
	By       string   `json:"by,omitempty"`
	Caveats  []string `json:"caveats,omitempty"`
}

type egressResult struct {
	Target    string             `json:"target"`
	Host      string             `json:"host"`
	Ring      string             `json:"ring"`
	Profile   string             `json:"profile"`
	Unit      string             `json:"unit,omitempty"`
	Allowed   bool               `json:"allowed"`
	Rule      string             `json:"rule"`
	Rules     policy.EgressRules `json:"rules"`
	Harnesses []egressHarness    `json:"harnesses"`
}

func (a *app) cmdEgress() *cobra.Command {
	c := &cobra.Command{
		Use:   "egress",
		Short: "Explain the sandbox egress policy (ADR-0032)",
	}
	var ring, unit, osName string
	t := &cobra.Command{
		Use:         "test <url|host>",
		Annotations: policyDirAnno,
		Short:       "Say whether a ring's policy allows a host, by which rule, and which harness enforces it",
		Long: "Resolves the ring's profile (and --unit's overlays), decides the host against egress\n" +
			"(deny rules win, then the allowlist and presets, then the default) and lists, per harness the\n" +
			"profile enables, the native mechanism that enforces the decision and what it cannot hold.\n" +
			"Exits 1 when the host is denied.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host, err := egressHost(args[0])
			if err != nil {
				return err
			}
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.loadValid(dir)
			if err != nil {
				return err
			}
			r, err := findRing(org, ring)
			if err != nil {
				return err
			}
			base, err := org.ResolveProfile(r.Profile)
			if err != nil {
				return fmt.Errorf("ring %s: %w", ring, err)
			}
			p, err := org.EffectiveProfile(base, unit)
			if err != nil {
				return err
			}
			res := egressResult{Target: args[0], Host: host, Ring: r.Name, Profile: r.Profile, Unit: unit, Rules: p.Egress.Rules()}
			res.Allowed, res.Rule = res.Rules.Decide(host)
			if !p.Egress.Restricted() {
				res.Rule = "no egress policy (unrestricted)"
			}
			res.Harnesses, err = egressHarnesses(p, org.Gateway, ring, harness.OS(osName))
			if err != nil {
				return err
			}
			if err := a.emit(res, func() {
				verdict := a.green("ALLOW")
				if !res.Allowed {
					verdict = a.red("DENY")
				}
				fmt.Fprintf(a.out, "%s %s  (ring %s, profile %s%s)\nrule   %s\n", verdict, a.bold(host), r.Name, r.Profile, unitSuffix(unit), res.Rule)
				for _, h := range res.Harnesses {
					st := a.green("enforced")
					if !h.Enforced {
						st = a.yellow("not enforced")
					}
					fmt.Fprintf(a.out, "  %-13s %s", h.Name, st)
					if h.By != "" {
						fmt.Fprintf(a.out, ": %s", h.By)
					}
					fmt.Fprintln(a.out)
					for _, c := range h.Caveats {
						fmt.Fprintf(a.out, "  %-13s   - %s\n", "", c)
					}
				}
			}); err != nil {
				return err
			}
			if !res.Allowed {
				return &exitErr{code: exitError}
			}
			return nil
		},
	}
	t.Flags().StringVar(&ring, "ring", "", "ring whose profile decides (required)")
	t.Flags().StringVar(&unit, "unit", "", "org unit whose overlays apply (ADR-0018)")
	t.Flags().StringVar(&osName, "os", runtime.GOOS, "target OS for the per-harness rendering: darwin|linux|windows")
	_ = t.MarkFlagRequired("ring")
	c.AddCommand(t)
	return c
}

func unitSuffix(u string) string {
	if u == "" {
		return ""
	}
	return ", unit " + u
}

// egressHost takes a URL or a bare host[:port] and returns the lower-case host.
func egressHost(s string) (string, error) {
	h := s
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("parse %q: %w", s, err)
		}
		h = u.Hostname()
	} else if hp, _, err := net.SplitHostPort(s); err == nil {
		h = hp
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || strings.ContainsAny(h, "/ ") {
		return "", errors.New("want a URL or a host name, got " + fmt.Sprintf("%q", s))
	}
	return h, nil
}

// egressHarnesses renders each enabled harness (all, when the profile names
// none) and reports how it enforces egress: its native mechanism, unless a
// render warning says the egress settings were not rendered, plus every
// egress warning as a caveat.
func egressHarnesses(p *policy.Profile, g *policy.Gateway, ring string, os harness.OS) ([]egressHarness, error) {
	names := harness.Names()
	if len(p.Harnesses) > 0 {
		names = names[:0:0]
		for n := range p.Harnesses {
			names = append(names, n)
		}
		sort.Strings(names)
	}
	var out []egressHarness
	for _, n := range names {
		ad, ok := harness.Get(n)
		if !ok {
			continue
		}
		_, warns, err := ad.Render(p, harness.Context{Gateway: g, Ring: ring, OS: os})
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", n, err)
		}
		h := egressHarness{Name: n, By: egressBy[n], Enforced: egressBy[n] != "" && p.Egress.Restricted()}
		for _, w := range warns {
			if !strings.Contains(w, "egress") {
				continue
			}
			h.Caveats = append(h.Caveats, w)
			if strings.Contains(w, "not rendered") || strings.Contains(w, "not enforced") {
				h.Enforced = false
			}
		}
		out = append(out, h)
	}
	return out, nil
}
