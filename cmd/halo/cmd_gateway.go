package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/fsutil"
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
	f.StringVar(&opts.GroupsHeader, "groups-header", "", "header carrying IdP groups")
	f.StringVar(&opts.IdentityHeader, "identity-header", "", "identity header (default: org gateway.auth.identityHeader)")

	gw.AddCommand(compile, deck)
	return gw
}
