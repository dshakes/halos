package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/policytest"
)

// cmdTest is `halo test`, the offline tier of testing a policy change.
func (a *app) cmdTest() *cobra.Command {
	var opt policytest.Options
	var output string
	c := &cobra.Command{
		Use:         "test",
		Annotations: policyDirAnno,
		Short:       "Test a policy change offline in seconds: validate, render, release, invariants, impact, policy tests, rollouts",
		Long: "The fast, credential-free confidence signal before `halo eval run` (Docker, provider keys, minutes) and\n" +
			"experiments (hours). Nothing here touches the network or a credential. It runs:\n\n" +
			"  validate    the policy loads and validates (as `halo validate`)\n" +
			"  render      every ring x harness x OS renders through the adapters; adapter warnings are surfaced\n" +
			"  release     each ring's release builds into a temp dir, its manifest is consistent and a rebuild\n" +
			"              reproduces the digest\n" +
			"  invariants  no bypassPermissions, danger-full-access or other permission-bypass token in any\n" +
			"              rendered file or manifest (AGENTS.md invariant 1)\n" +
			"  impact      with --against REF: who changes ring, variant or settings against the policy at REF,\n" +
			"              failing when more than --max-impact percent of the sampled users of all users or of any\n" +
			"              ring change (a policy-only estimate, as `halo plan --diff` without a server)\n" +
			"  cases       the PolicyTest documents under tests/ (schemas/policytest.schema.json): given an identity,\n" +
			"              expect its ring, experiment variants and rendered setting values per harness\n" +
			"  rollout     every rollout is simulated on healthy evidence and must complete\n\n" +
			"Remote (git, oci) supply-chain artifacts need the network: rings that use them are skipped here and\n" +
			"covered by `halo release build`.\n\n" +
			"Exit codes: 0 every check passed (skips do not fail), 1 the run could not happen (no policy repo,\n" +
			"unknown ring, unreadable --against ref, bad flag), 2 one or more checks failed.\n" +
			"-o json is for agents (it carries next_steps), -o junit for CI test reports.",
		Example: "  halo test --policy-dir examples/acme-corp\n" +
			"  halo test --policy-dir examples/acme-corp --against main --max-impact 10\n" +
			"  halo test --strict -o junit > halo-test.xml",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch output {
			case "text", "json", "junit":
			default:
				return fmt.Errorf("-o/--output must be text, json or junit, got %q", output)
			}
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			opt.Dir = dir
			rep, err := policytest.Run(cmd.Context(), opt)
			if err != nil {
				return err
			}
			switch output {
			case "junit":
				if err := rep.JUnit(a.out); err != nil {
					return err
				}
			case "json":
				enc := json.NewEncoder(a.out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			default:
				rep.Text(a.out, policytest.Painter{Green: a.green, Red: a.red, Yellow: a.yellow, Bold: a.bold})
			}
			if !rep.OK {
				return &exitErr{code: exitValidation, err: errors.New(failSummary(rep))}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&opt.Ring, "ring", "", "limit the render, release and invariant checks to this ring (default: every ring)")
	f.StringVar(&opt.Against, "against", "", "git ref of the policy to compare with (e.g. main): adds the impact check")
	f.Float64Var(&opt.MaxImpact, "max-impact", policytest.DefaultMaxImpact, "impact check: fail when more than this percent (0-100) of the sampled users of all users or of any ring change")
	f.BoolVar(&opt.Strict, "strict", false, "fail on warnings too: policy validation warnings and adapter warnings in the release manifest")
	f.StringVar(&opt.Version, "release-version", policytest.DefaultVersion, "release version label the test builds use")
	// Shadows the persistent --output (text|json) with the junit format added.
	f.StringVarP(&output, "output", "o", "text", "output format: text|json|junit")
	return c
}

func failSummary(r *policytest.Report) string {
	return fmt.Sprintf("%d of %d checks failed", r.Failed, r.Passed+r.Failed+r.Skipped)
}
