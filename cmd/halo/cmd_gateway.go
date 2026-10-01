package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/gateway/kong"
	"github.com/dshakes/halos/internal/policy"
)

// emitBytes writes b to out ("-" or "" = stdout), atomically for files.
func (a *app) emitBytes(out string, b []byte) error {
	if out == "" || out == "-" {
		_, err := a.out.Write(b)
		return err
	}
	if err := fsutil.WriteAtomic(out, b, fsutil.ExistingPerm(out, 0o644)); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Fprintf(a.errw, "wrote %s (%d bytes)\n", out, len(b))
	return nil
}

func dash(ok bool, s string) string {
	if ok {
		return s
	}
	return "-"
}

func (a *app) cmdGateway() *cobra.Command {
	gw := &cobra.Command{Use: "gateway", Short: "Compile gateway artifacts from the policy repo"}

	var out string
	compile := &cobra.Command{
		Use: "compile", Annotations: policyDirAnno, Short: "Compile the policy snapshot (policy.json) the gateway loads", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { // positional [dir] is a deprecated alias
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			org, err := a.loadValid(dir)
			if err != nil {
				return err
			}
			b, err := policy.Compile(org)
			if err != nil {
				return err
			}
			return a.emitBytes(out, b)
		},
	}
	compile.Flags().StringVarP(&out, "out", "o", "-", "output file ('-' = stdout)")

	var dout string
	var opts kong.Options
	deck := &cobra.Command{
		Use: "deck", Annotations: policyDirAnno, Short: "Generate the decK declarative config (kong.yml) for Kong + halo-kong", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { // positional [dir] is a deprecated alias
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			org, err := a.loadValid(dir)
			if err != nil {
				return err
			}
			b, err := kong.Generate(org, opts)
			if err != nil {
				return err
			}
			return a.emitBytes(dout, b)
		},
	}
	f := deck.Flags()
	f.StringVarP(&dout, "out", "o", "-", "output file ('-' = stdout)")
	f.StringVar(&opts.PolicyPath, "policy-path", "", "snapshot path inside the Kong container")
	f.StringVar(&opts.ShadowURL, "halo-shadow-url", "", "halo-shadow URL for shadow traffic")
	f.StringVar(&opts.ShadowToken, "halo-shadow-token", "", "halo-shadow auth token")
	f.StringVar(&opts.KillswitchURL, "killswitch-url", "", "halo-server kill-switch URL; token and pubkey are emitted as {vault://env/halo-killswitch-*} refs")
	f.BoolVar(&opts.RejectUnverified, "reject-unverified", false, "answer model calls without a verified identity with 401 (default: anonymous default routing; for when Kong is the only thing in front of the upstreams)")
	f.BoolVar(&opts.StripClientCredentials, "strip-client-credentials", false, "drop the caller's Authorization/x-api-key/api-key/x-goog-api-key before the upstream (default: forwarded, for an auth gateway behind Kong)")
	f.BoolVar(&opts.KillswitchAllowInsecure, "killswitch-allow-insecure-in-cluster", false, "allow a plain-http --killswitch-url on a trusted pod network (in-cluster halo-server Service)")
	f.StringVar(&opts.GroupsHeader, "groups-header", "", "header carrying IdP groups")
	f.StringVar(&opts.IdentityHeader, "identity-header", "", "identity header (default: org gateway.auth.identityHeader)")

	var user, session string
	var groups []string
	routes := &cobra.Command{
		Use: "routes", Annotations: policyDirAnno, Short: "Print the effective model route table and the target a user/session would hit", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.loadValid(dir)
			if err != nil {
				return err
			}
			rows := gateway.RouteTable(org, gateway.RequestInfo{UserID: user, Groups: groups, SessionID: session})
			return a.emit(rows, func() {
				who := "anonymous (policy order; weights need --user or --session)"
				if user != "" || session != "" {
					who = fmt.Sprintf("user %q session %q", user, session)
				}
				fmt.Fprintf(a.out, "Routes for %s\n", who)
				tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "ALIAS\tORDER\tUPSTREAM\tKIND\tMODEL\tWEIGHT\tPRIORITY\tTIMEOUT\tNOTES")
				for _, r := range rows {
					for _, t := range r.Targets {
						var notes []string
						if t.Selected {
							notes = append(notes, "<- hit when healthy")
						}
						if r.Experiment != "" {
							notes = append(notes, fmt.Sprintf("experiment %s/%s", r.Experiment, r.Variant))
						}
						if len(t.SkippedBy) > 0 {
							notes = append(notes, "skipped by "+strings.Join(t.SkippedBy, ","))
						}
						fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", r.Alias, t.Order, t.Upstream, t.Kind, t.Model,
							dash(t.Weight > 0, fmt.Sprint(t.Weight)), t.Priority, dash(t.TimeoutSeconds > 0, fmt.Sprintf("%ds", t.TimeoutSeconds)), strings.Join(notes, "; "))
					}
				}
				_ = tw.Flush()
			})
		},
	}
	rf := routes.Flags()
	rf.StringVar(&user, "user", "", "verified user id (e.g. alice@acme.com): selects ring, experiment variant and the sticky weighted pick")
	rf.StringVar(&session, "session", "", "harness session id (weighted picks are sticky per user+session)")
	rf.StringSliceVar(&groups, "group", nil, "IdP group of the user (repeatable); ring membership may depend on it")

	gw.AddCommand(compile, deck, routes)
	return gw
}
