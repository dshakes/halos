package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/a2a"
	"github.com/dshakes/halos/internal/policy"
)

// cardFetcher is swapped in tests (TLS roots of a local test server).
var cardFetcher = func(timeout time.Duration, allowPrivate bool) a2a.Fetcher {
	return a2a.Fetcher{Timeout: timeout, AllowPrivate: allowPrivate}
}

// agentVerifyReport is `halo agents verify` output.
type agentVerifyReport struct {
	URL      string     `json:"url"`
	Policy   string     `json:"policy,omitempty"` // agents.remote name the URL matched
	Result   a2a.Result `json:"result"`
	Pinned   string     `json:"pinned,omitempty"`
	Missing  []string   `json:"missingSkills,omitempty"`
	Problems []string   `json:"problems,omitempty"`
}

func (a *app) cmdAgents() *cobra.Command {
	c := &cobra.Command{Use: "agents", Short: "Delegated and remote (A2A) agents (ADR-0024)"}
	var digest, pubkeyFile, jwksURL string
	var allowPrivate bool
	var timeout time.Duration
	v := &cobra.Command{
		Use:         "verify <card-url>",
		Annotations: policyDirAnno,
		Short:       "Fetch an A2A AgentCard, verify its signature and pinned digest, and print the digest to pin",
		Long: "Fetches the AgentCard over https (no redirect off-host, at most 256KB, --timeout), refusing loopback, private and " +
			"link-local destinations unless --allow-private. With --pubkey or --jwks-url the card's JWS signature must verify " +
			"(A2A spec section 8.4); with --digest the card must match it. With --policy-dir, an agents.remote entry whose " +
			"cardURL is the URL supplies digest, publicKey, jwksURL and skills (flags override). Exit 1 when anything fails.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cardURL := args[0]
			rep := agentVerifyReport{URL: cardURL}
			exp := a2a.Expect{Digest: digest, JWKSURL: jwksURL}
			var skills []string
			if f := cmd.Flags().Lookup("policy-dir"); f != nil && f.Changed {
				dir, err := policyDir(cmd, nil)
				if err != nil {
					return err
				}
				org, err := a.load(dir)
				if err != nil {
					return err
				}
				ra := remoteByURL(org, cardURL)
				if ra == nil {
					return fmt.Errorf("no agents.remote entry in %s has cardURL %s", dir, cardURL)
				}
				rep.Policy, skills = ra.Name, ra.Skills
				exp.Digest = firstSet(digest, ra.Digest)
				exp.PublicKey = ra.PublicKey
				exp.JWKSURL = firstSet(jwksURL, ra.JWKSURL)
			}
			if pubkeyFile != "" {
				b, err := os.ReadFile(pubkeyFile) //nolint:gosec // operator-supplied path is the point
				if err != nil {
					return fmt.Errorf("read --pubkey: %w", err)
				}
				exp.PublicKey = string(b)
			}
			rep.Pinned = exp.Digest
			res, err := cardFetcher(timeout, allowPrivate).Verify(cmd.Context(), cardURL, exp)
			rep.Result = res
			if err != nil {
				rep.Problems = append(rep.Problems, err.Error())
			}
			if res.Digest != "" {
				for _, s := range skills {
					if !slices.Contains(res.Card.SkillIDs(), s) {
						rep.Missing = append(rep.Missing, s)
					}
				}
				if len(rep.Missing) > 0 {
					rep.Problems = append(rep.Problems, fmt.Sprintf("allowed skills %v are not on the card", rep.Missing))
				}
			}
			if err := a.emit(rep, func() { a.printAgentVerify(rep) }); err != nil {
				return err
			}
			if len(rep.Problems) > 0 {
				return &exitErr{code: exitError, err: errors.New(termSafe(strings.Join(rep.Problems, "; ")))}
			}
			return nil
		},
	}
	v.Flags().StringVar(&digest, "digest", "", "expected card digest (sha256:<hex>)")
	v.Flags().StringVar(&pubkeyFile, "pubkey", "", "PEM public key the card must be signed with")
	v.Flags().StringVar(&jwksURL, "jwks-url", "", "https JWKS whose key must have signed the card")
	v.Flags().BoolVar(&allowPrivate, "allow-private", false, "allow loopback, private and link-local destinations (an internal agent)")
	v.Flags().DurationVar(&timeout, "timeout", a2a.DefaultTimeout, "fetch timeout")
	c.AddCommand(v, a.cmdAgentsRevoke(), a.cmdAgentsRevocations())
	return c
}

func firstSet(flag, pinned string) string {
	if flag != "" {
		return flag
	}
	return pinned
}

func remoteByURL(org *policy.Org, u string) *policy.RemoteAgent {
	if org.Agents == nil {
		return nil
	}
	for i := range org.Agents.Remote {
		if org.Agents.Remote[i].CardURL == u {
			return &org.Agents.Remote[i]
		}
	}
	return nil
}

// termSafe escapes control and format characters (ANSI escapes, carriage
// returns, bidi overrides) and invalid UTF-8 in remote text before it reaches
// a terminal: an AgentCard is served by whoever controls the URL.
func termSafe(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == utf8.RuneError && !strings.HasPrefix(s[i:], "\uFFFD"):
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func termSafeAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = termSafe(s)
	}
	return out
}

func (a *app) printAgentVerify(r agentVerifyReport) {
	c := r.Result.Card
	if r.Result.Digest == "" {
		fmt.Fprintf(a.out, "%s %s\n", a.red("FAIL"), termSafe(r.URL))
		for _, p := range r.Problems {
			fmt.Fprintln(a.out, "  "+termSafe(p))
		}
		return
	}
	status := a.green("OK")
	if len(r.Problems) > 0 {
		status = a.red("FAIL")
	}
	fmt.Fprintf(a.out, "%s %s (%s %s)\n", status, termSafe(r.URL), termSafe(c.Name), termSafe(c.Version))
	if r.Policy != "" {
		fmt.Fprintf(a.out, "  policy:     agents.remote[%s]\n", r.Policy)
	}
	fmt.Fprintf(a.out, "  digest:     %s\n", r.Result.Digest)
	sig := "unsigned"
	switch {
	case r.Result.Verified:
		sig = "verified"
	case r.Result.Signed:
		sig = "signed, not verified (no --pubkey/--jwks-url or policy key)"
	}
	fmt.Fprintf(a.out, "  signature:  %s\n", sig)
	for _, i := range c.SupportedInterfaces {
		fmt.Fprintf(a.out, "  interface:  %s %s %s\n", termSafe(i.ProtocolBinding), termSafe(i.ProtocolVersion), termSafe(i.URL))
	}
	if len(c.SecuritySchemes) > 0 {
		names := make([]string, 0, len(c.SecuritySchemes))
		for n := range c.SecuritySchemes {
			names = append(names, n)
		}
		slices.Sort(names)
		fmt.Fprintf(a.out, "  auth:       %s\n", strings.Join(termSafeAll(names), ", "))
	}
	fmt.Fprintf(a.out, "  skills:     %s\n", strings.Join(termSafeAll(c.SkillIDs()), ", "))
	for _, p := range r.Problems {
		fmt.Fprintln(a.out, "  "+a.red(termSafe(p)))
	}
	if r.Pinned == "" {
		fmt.Fprintf(a.out, "Pin it in halos.yaml agents.remote[].digest: %s\n", r.Result.Digest)
	}
}
