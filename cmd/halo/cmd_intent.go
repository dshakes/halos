package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/cmd/halo/scaffold"
	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/intent"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// Intent commands: the simple front door. Each generating command validates
// the policy it would produce, then writes it (or, with --dry-run, prints the
// diff) and lists every file it created or changed. None merges or moves a
// ring pointer; `halo upgrade start` may publish a pointerless candidate release.

// applyChange validates c as applied, then writes it unless dry. before, if
// set, runs after validation and before anything is written (not when dry).
func (a *app) applyChange(c *intent.Change, dry bool, before ...func() error) error {
	issues, err := c.Validate()
	if err != nil {
		return err
	}
	for _, i := range issues {
		if i.Severity == policy.SeverityError || !dry {
			fmt.Fprintln(a.errw, i.String())
		}
	}
	if policy.HasErrors(issues) {
		return &exitErr{code: exitValidation, err: errors.New("the generated policy does not validate; nothing written")}
	}
	created, changed := c.Paths()
	patch := ""
	if dry {
		patch = c.Patch()
	} else {
		for _, f := range before {
			if err := f(); err != nil {
				return err
			}
		}
		if err := c.Apply(); err != nil {
			return err
		}
	}
	res := map[string]any{"dryRun": dry, "created": orEmpty(created), "changed": orEmpty(changed), "notes": orEmpty(c.Notes), "done": orEmpty(c.Done)}
	if dry {
		res["patch"] = patch
	}
	return a.emit(res, func() {
		fmt.Fprint(a.out, patch)
		for _, d := range c.Done {
			fmt.Fprintln(a.out, a.green("ok"), d)
		}
		verb := map[bool][2]string{false: {"create", "update"}, true: {"would create", "would update"}}[dry]
		for _, p := range created {
			fmt.Fprintln(a.out, a.green(verb[0]), filepath.Join(c.Dir, filepath.FromSlash(p)))
		}
		for _, p := range changed {
			fmt.Fprintln(a.out, a.yellow(verb[1]), filepath.Join(c.Dir, filepath.FromSlash(p)))
		}
		for _, n := range c.Notes {
			fmt.Fprintln(a.out, a.bold("next:"), n)
		}
		if dry {
			fmt.Fprintln(a.out, "dry run: nothing written")
		}
	})
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a *app) openRepo(cmd *cobra.Command) (*intent.Repo, error) {
	dir, err := policyDir(cmd, nil)
	if err != nil {
		return nil, err
	}
	r, err := intent.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("load policy %s: %w", dir, err)
	}
	return r, nil
}

func (a *app) cmdInit() *cobra.Command {
	var o intent.InitOptions
	var tools, models []string
	var full, interactive bool
	c := &cobra.Command{
		Use:         "init",
		Annotations: policyDirAnno,
		Short:       "Create a policy repo: one simple halos.yaml (--full for the multi-file scaffold)",
		Long: "Writes a simple-mode halos.yaml: tools, provider, models, gateway, safety and rollout presets.\n" +
			"Load expands it into the Gateway, Profile and Rings; `halo explain` shows them, `halo eject` writes them out.",
		Example: "  halo init --org acme --tools claude-code@2.1.280,codex@0.99.0 --provider bedrock \\\n" +
			"    --model default=claude-sonnet-4-5 --model strong=claude-opus-4-1 --gateway https://ai.acme.com",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(dir, policy.RootFile)); err == nil {
				return fmt.Errorf("%s already exists in %s; refusing to overwrite", policy.RootFile, dir)
			}
			if full {
				return a.initFull(dir, o.Org)
			}
			var ask func(q, def string) (string, error)
			if interactive {
				if ask, err = promptInit(cmd.InOrStdin(), a.out, &o, &tools, &models); err != nil {
					return err
				}
			}
			if o.Tools, err = splitKV(tools, "@", "--tools"); err != nil {
				return err
			}
			if o.Models, err = splitKV(models, "=", "--model"); err != nil {
				return err
			}
			notes, err := o.Complete(ask)
			if err != nil {
				return err
			}
			for _, n := range notes { // stderr: --output json stays parseable
				fmt.Fprintln(a.errw, a.yellow("note:"), n)
			}
			if o.Gateway == "" {
				o.Gateway = "https://ai." + o.Org + ".example"
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			ch := &intent.Change{Dir: dir, Files: map[string][]byte{policy.RootFile: intent.InitFile(o)},
				Notes: []string{"halo explain --policy-dir " + dir + "   (the full policy this expands to)", "halo validate --policy-dir " + dir}}
			return a.applyChange(ch, false)
		},
	}
	f := c.Flags()
	f.StringVar(&o.Org, "org", "my-org", "organization name")
	f.StringSliceVar(&tools, "tools", []string{"claude-code@2.1.280"}, "harnesses as name@version (claude-code, codex, gemini-cli, copilot-cli)")
	f.StringVar(&o.Provider, "provider", "anthropic", "anthropic | bedrock | vertex | openai | gemini | multi")
	f.StringArrayVar(&models, "model", nil, "model alias=provider model id, repeatable (default: the provider's current model;\n"+
		"tools whose wire the provider cannot serve get an alias named after the tool, e.g. --model codex=gpt-5-codex)")
	f.StringVar(&o.Project, "project", "", "Google Cloud project (provider vertex)")
	f.StringVar(&o.Gateway, "gateway", "", "gateway base URL clients use (default https://ai.<org>.example)")
	f.StringVar(&o.Issuer, "issuer", "", "OIDC issuer URL (any IdP)")
	f.StringVar(&o.Safety, "safety", "standard", "safety preset: strict | standard | relaxed")
	f.StringVar(&o.Rollout, "rollout", "standard", "rollout preset: fast | standard | careful")
	f.BoolVarP(&interactive, "interactive", "i", false, "prompt for each setting")
	f.BoolVar(&full, "full", false, "write the multi-file scaffold (gateway, profile, rings) instead of simple mode")
	return c
}

// initFull is the pre-simple-mode scaffold.
func (a *app) initFull(dir, org string) error {
	files, err := scaffold.Files(org)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n, data := range files {
		names = append(names, n)
		if err := writeFile(filepath.Join(dir, n), data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", n, err)
		}
	}
	sort.Strings(names)
	return a.emit(map[string]any{"dir": dir, "files": names}, func() {
		for _, n := range names {
			fmt.Fprintln(a.out, a.green("create"), filepath.Join(dir, n))
		}
		fmt.Fprintf(a.out, "next: halo validate %s\n", dir)
	})
}

func splitKV(items []string, sep, flag string) (map[string]string, error) {
	out := map[string]string{}
	for _, it := range items {
		k, v, ok := strings.Cut(strings.TrimSpace(it), sep)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("%s %q: want name%svalue", flag, it, sep)
		}
		out[k] = v
	}
	return out, nil
}

// promptInit asks for each setting, showing the flag value as the default.
// It returns the asker for follow-up questions (Complete's per-tool models).
func promptInit(in io.Reader, out io.Writer, o *intent.InitOptions, tools, models *[]string) (func(q, def string) (string, error), error) {
	sc := bufio.NewScanner(in)
	ask := func(q, def string) (string, error) {
		fmt.Fprintf(out, "%s [%s]: ", q, def)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return "", fmt.Errorf("read answer: %w", err)
			}
			return "", errors.New("init: input ended before every question was answered")
		}
		if s := strings.TrimSpace(sc.Text()); s != "" {
			return s, nil
		}
		return def, nil
	}
	t, m := strings.Join(*tools, ","), strings.Join(*models, ",")
	for _, q := range []struct {
		q string
		v *string
	}{{"Organization", &o.Org}, {"Tools (name@version, comma-separated)", &t}, {"Provider (anthropic|bedrock|vertex|openai|gemini|multi)", &o.Provider},
		{"Models (alias=id, comma-separated; empty = the provider's default)", &m}, {"Gateway URL (empty = https://ai.<org>.example)", &o.Gateway},
		{"OIDC issuer (optional)", &o.Issuer}, {"Safety (strict|standard|relaxed)", &o.Safety}, {"Rollout (fast|standard|careful)", &o.Rollout}} {
		v, err := ask(q.q, *q.v)
		if err != nil {
			return nil, err
		}
		*q.v = v
	}
	if o.Provider == "vertex" && o.Project == "" {
		v, err := ask("Google Cloud project (vertex)", "")
		if err != nil {
			return nil, err
		}
		o.Project = v
	}
	*tools, *models = splitList(t), splitList(m)
	return ask, nil
}

// regFromEnv fills --registry and --key from HALO_REGISTRY / HALO_KEY.
func regFromEnv(rf *regFlags) {
	if rf.registry == "" {
		rf.registry = os.Getenv("HALO_REGISTRY")
	}
	if rf.key == "" {
		rf.key = os.Getenv("HALO_KEY")
	}
}

// buildCandidate builds c's release (and its treatment variant release, when
// it has an experiment) exactly as `halo upgrade publish` will rebuild it, so
// the digest written into the rollout is reproducible.
func (a *app) buildCandidate(ctx context.Context, org *policy.Org, c intent.Candidate, noArt bool) (rel, variant *release.Release, err error) {
	if rel, err = release.Build(org, c.Profile, c.Ring, release.Options{Version: c.Label}); err != nil {
		return nil, nil, fmt.Errorf("build candidate %s: %w", c.Label, err)
	}
	if rel, err = a.resolveArtifacts(ctx, rel, noArt); err != nil {
		return nil, nil, err
	}
	if c.Experiment == "" {
		return rel, nil, nil
	}
	o := release.Options{Version: release.VariantVersion(c.Label, c.ExperimentRing, c.Experiment, c.Variant), Experiment: c.Experiment, Variant: c.Variant}
	if variant, err = release.Build(org, c.Profile, c.ExperimentRing, o); err != nil {
		return nil, nil, fmt.Errorf("build candidate variant %s: %w", o.Version, err)
	}
	if !noArt { // --no-artifacts: warned once above
		if variant, err = a.resolveArtifacts(ctx, variant, false); err != nil {
			return nil, nil, err
		}
	}
	return rel, variant, nil
}

// pushCandidate pushes and signs rel (tag v<label>) with no pointer, and the
// variant on its experiment channel. No ring pointer moves.
func (a *app) pushCandidate(ctx context.Context, rf *regFlags, pf *ptrFlags, rel, variant *release.Release) ([]string, error) {
	s, err := rf.signer()
	if err != nil {
		return nil, err
	}
	t, err := rf.target()
	if err != nil {
		return nil, err
	}
	already, err := bundle.Stage(ctx, t, rel, s)
	if err != nil {
		return nil, fmt.Errorf("publish candidate %s: %w", rel.Manifest.Version, err)
	}
	verb := "published"
	if already {
		verb = "already published"
	}
	out := []string{fmt.Sprintf("%s %s %s (%s); no ring pointer moved", verb, rf.registry, bundle.VersionTag(rel.Manifest.Version), rel.Digest)}
	if variant == nil {
		return out, nil
	}
	o, _, err := a.pointerOptions(rf, pf)
	if err != nil {
		return nil, err
	}
	ch, err := bundle.PublishChannel(ctx, t, variant, s, o)
	if err != nil {
		return nil, fmt.Errorf("publish candidate channel: %w", err)
	}
	return append(out, fmt.Sprintf("published channel %s (%s): reached only once the experiment runs", ch, variant.Digest)), nil
}

func (a *app) cmdUpgradeStart() *cobra.Command {
	var u intent.Upgrade
	var dry, noPublish, noArt bool
	var rf regFlags
	var pf ptrFlags
	c := &cobra.Command{
		Use:   "start <tool> <version>",
		Short: "Roll a CLI version out: build and publish the candidate (no ring moves) and write its phased rollout",
		Long: "Writes rollouts/<tool>-<version>.yaml from the rollout preset (ring0, a guardrailed canary ramp,\n" +
			"then ring by ring to GA), its client-axis experiment and treatment profile. It builds the candidate\n" +
			"release (the treatment profile for the GA ring), pushes and signs it as v<tool>-<version> with no\n" +
			"pointer, publishes the treatment on its experiment channel, and fills change.release with its\n" +
			"digest and baseline.release with the digest the GA ring serves. Nothing reaches a device until\n" +
			"a human merges the rollout and advances it. --no-publish computes the same digest offline and\n" +
			"prints the `halo upgrade publish` command to push it later. --registry/--key default to\n" +
			"HALO_REGISTRY / HALO_KEY.",
		Args: cobra.ExactArgs(2), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.openRepo(cmd)
			if err != nil {
				return err
			}
			regFromEnv(&rf)
			u.Tool, u.Version = args[0], args[1]
			plan, err := r.PlanUpgrade(u)
			if err != nil {
				return err
			}
			publish := !noPublish && !dry && u.Release == ""
			if publish && (rf.registry == "" || rf.key == "") {
				return errors.New("set --registry and --key (or HALO_REGISTRY / HALO_KEY) to publish the candidate, or pass --no-publish")
			}
			cand, baseline := u.Release, u.Baseline
			var rel, variant *release.Release
			if cand == "" {
				org, err := plan.Change.Load()
				if err != nil {
					return err
				}
				if rel, variant, err = a.buildCandidate(cmd.Context(), org, plan.Candidate, noArt); err != nil {
					return err
				}
				cand = rel.Digest
			}
			if baseline == "" {
				if baseline, err = a.servedBaseline(cmd.Context(), r.Org, plan.Candidate.Ring, &rf); err != nil {
					return err
				}
			}
			ch, err := plan.Finish(cand, baseline)
			if err != nil {
				return err
			}
			if !publish && rel != nil {
				ch.Notes = append(ch.Notes, fmt.Sprintf("push the candidate (v%s, %s; moves no ring pointer): halo upgrade publish %s --registry <repo> --key <key>", plan.Candidate.Label, cand, plan.Name))
			}
			return a.applyChange(ch, dry, func() error {
				if !publish {
					return nil
				}
				var err error
				ch.Done, err = a.pushCandidate(cmd.Context(), &rf, &pf, rel, variant)
				return err
			})
		},
	}
	f := c.Flags()
	rf.add(c, true, false)
	pf.add(c, "")
	f.StringVar(&u.Release, "release", "", "override: digest of an already published candidate release (skips build and publish)")
	f.StringVar(&u.Baseline, "baseline", "", "override: rollback digest (default: the release the GA ring's signed pointer serves)")
	f.StringVar(&u.Label, "release-version", "", "candidate release version label (default <tool>-<version>)")
	f.BoolVar(&noPublish, "no-publish", false, "write the files with the locally computed digest; push later with `halo upgrade publish`")
	f.BoolVar(&noArt, "no-artifacts", false, noArtHelp)
	f.BoolVar(&dry, "dry-run", false, "print the diff instead of writing (nothing is published)")
	return c
}

// servedBaseline is the rollback target: the GA ring's pinned release, else
// the digest its signed pointer serves in the registry.
func (a *app) servedBaseline(ctx context.Context, org *policy.Org, ga string, rf *regFlags) (string, error) {
	ring, err := findRing(org, ga)
	if err != nil {
		return "", err
	}
	if ring.Release != "" {
		return ring.Release, nil
	}
	if rf.registry == "" || rf.key == "" {
		return "", fmt.Errorf("need the release ring %s serves as the rollback baseline: pass --baseline, or --registry and --key (or HALO_REGISTRY / HALO_KEY) to read its signed pointer", ga)
	}
	s, err := rf.signer()
	if err != nil {
		return "", err
	}
	t, err := rf.target()
	if err != nil {
		return "", err
	}
	p, found, err := bundle.ServedPointer(ctx, t, s, ga)
	if err != nil {
		return "", fmt.Errorf("read ring %s pointer: %w", ga, err)
	}
	if !found {
		return "", fmt.Errorf("ring %s has never been published to %s, so there is nothing to roll back to: halo release publish --ring %s --release-version <v> first", ga, rf.registry, ga)
	}
	return p.Digest, nil
}

func (a *app) cmdUpgradePublish() *cobra.Command {
	var noArt bool
	var rf regFlags
	var pf ptrFlags
	c := &cobra.Command{
		Use:   "publish <rollout>",
		Short: "Rebuild and push the candidate release a `halo upgrade start` rollout names (no ring pointer moves)",
		Long: "For rollouts written with --no-publish (e.g. from a laptop; run this in CI after merge). The rebuilt\n" +
			"release must have exactly the rollout's change.release digest, else nothing is pushed.",
		Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.openRepo(cmd)
			if err != nil {
				return err
			}
			regFromEnv(&rf)
			ro, err := findRollout(r.Org, args[0])
			if err != nil {
				return err
			}
			cand, err := r.CandidateOf(ro)
			if err != nil {
				return err
			}
			rel, variant, err := a.buildCandidate(cmd.Context(), r.Org, cand, noArt)
			if err != nil {
				return err
			}
			if rel.Digest != ro.Change.Release {
				return fmt.Errorf("rollout %s names release %s but the policy now builds %s (the profile, gateway, toggles or --no-artifacts differ); nothing pushed: rerun `halo upgrade start` or fix change.release in a PR", ro.Name, ro.Change.Release, rel.Digest)
			}
			done, err := a.pushCandidate(cmd.Context(), &rf, &pf, rel, variant)
			if err != nil {
				return err
			}
			return a.emit(map[string]any{"rollout": ro.Name, "release": rel.Digest, "published": done}, func() {
				for _, d := range done {
					fmt.Fprintln(a.out, a.green("ok"), d)
				}
			})
		},
	}
	rf.add(c, true, false)
	pf.add(c, "")
	c.Flags().BoolVar(&noArt, "no-artifacts", false, noArtHelp)
	return c
}

func (a *app) cmdModel() *cobra.Command {
	c := &cobra.Command{Use: "model", Short: "Change which model an alias routes to"}
	var m intent.ModelSwitch
	var dry bool
	sw := &cobra.Command{
		Use:   "switch <alias> <model>",
		Short: "Point an alias at a model: in place, or with --canary as a guardrailed traffic rollout",
		Long: "<model> is a provider model id, optionally prefixed <provider>/ (e.g. bedrock/anthropic.claude-opus-4-1).\n" +
			"Without --canary the route is edited in place (halos.yaml models.<alias> in simple mode).\n" +
			"With --canary it writes a traffic-axis Rollout from the rollout preset plus its experiment.",
		Args: cobra.ExactArgs(2), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.openRepo(cmd)
			if err != nil {
				return err
			}
			m.Alias, m.Model = args[0], args[1]
			ch, err := r.SwitchModel(m)
			if err != nil {
				return err
			}
			return a.applyChange(ch, dry)
		},
	}
	sw.Flags().BoolVar(&m.Canary, "canary", false, "roll out as a guardrailed canary instead of switching at once")
	sw.Flags().BoolVar(&dry, "dry-run", false, "print the diff instead of writing")
	c.AddCommand(sw)
	return c
}

func (a *app) cmdEnable() *cobra.Command {
	c := &cobra.Command{Use: "enable", Short: "Enable an MCP server or hook for everyone (profile) or a cohort (toggle)"}
	var e intent.Enable
	var dry bool
	var url, command, event, matcher string
	var headers []string
	run := func(cmd *cobra.Command) error {
		r, err := a.openRepo(cmd)
		if err != nil {
			return err
		}
		e.Now = time.Now()
		ch, err := r.Enable(e)
		if err != nil {
			return err
		}
		return a.applyChange(ch, dry)
	}
	mcp := &cobra.Command{
		Use: "mcp <name>", Short: "Enable an MCP server (--url or --command)", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &policy.MCPServer{Name: args[0], URL: url}
			if command != "" {
				s.Command = strings.Fields(command)
			}
			h, err := splitKV(headers, "=", "--header")
			if err != nil {
				return err
			}
			if len(h) > 0 {
				s.Headers = h
			}
			e.MCP = s
			return run(cmd)
		},
	}
	mcp.Flags().StringVar(&url, "url", "", "https URL of a remote server")
	mcp.Flags().StringVar(&command, "command", "", "command line of a local (stdio) server")
	mcp.Flags().StringArrayVar(&headers, "header", nil, "request header Name=value (use ${VAR} for secrets; repeatable)")
	hook := &cobra.Command{
		Use: "hook <name>", Short: "Enable a hook (--event and --command)", Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			if event == "" || command == "" {
				return errors.New("--event and --command are required")
			}
			e.Name, e.Hook = args[0], &policy.Hook{Event: event, Matcher: matcher, Command: command}
			return run(cmd)
		},
	}
	hook.Flags().StringVar(&event, "event", "", "PreToolUse | PostToolUse | SessionStart | Stop | UserPromptSubmit")
	hook.Flags().StringVar(&matcher, "matcher", "", "tool matcher, e.g. Edit|Write")
	hook.Flags().StringVar(&command, "command", "", "command to run")
	for _, sub := range []*cobra.Command{mcp, hook} {
		sub.Flags().StringVar(&e.For, "for", "all", "all (profile change) | <ring> | N% | group:<name> | user:<id> (a toggle)")
		sub.Flags().StringVar(&e.Owner, "owner", "", "toggle owner (default: first identity.adminGroups entry)")
		sub.Flags().StringVar(&e.Expires, "expires", "", "toggle expiry YYYY-MM-DD (default: 90 days)")
		sub.Flags().BoolVar(&dry, "dry-run", false, "print the diff instead of writing")
	}
	c.AddCommand(mcp, hook)
	return c
}

// cmdKill kills whatever the name is: an experiment or toggle via
// halo-server's signed kill list, or a rollout via its backing experiment.
func (a *app) cmdKill() *cobra.Command {
	var server, reason, kind string
	var unkill bool
	c := &cobra.Command{
		Use:   "kill <name>",
		Short: "Kill an experiment, toggle or rollout fleet-wide via halo-server (effective at the next poll)",
		Long: "Resolves <name> in the policy repo. Experiments and toggles go on halo-server's signed kill list;\n" +
			"a rollout kills its backing experiment (then open the abort PR: halo rollout rollback <name> --reason ...).\n" +
			"The admin session comes from HALO_SESSION, never a flag.",
		Args: cobra.ExactArgs(1), Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !unkill && strings.TrimSpace(reason) == "" {
				return errors.New("--reason is required to kill")
			}
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			name := args[0]
			var kinds []string
			if slices.ContainsFunc(org.Experiments, func(e *policy.Experiment) bool { return e.Name == name }) {
				kinds = append(kinds, "experiment")
			}
			if slices.ContainsFunc(org.Toggles, func(t *policy.Toggle) bool { return t.Name == name }) {
				kinds = append(kinds, "toggle")
			}
			if slices.ContainsFunc(org.Rollouts, func(r *policy.Rollout) bool { return r.Name == name }) {
				kinds = append(kinds, "rollout")
			}
			if kind != "" {
				if !slices.Contains(kinds, kind) {
					return fmt.Errorf("no %s named %q in %s", kind, name, dir)
				}
				kinds = []string{kind}
			}
			switch len(kinds) {
			case 0:
				return fmt.Errorf("no experiment, toggle or rollout named %q in %s", name, dir)
			case 1:
			default:
				return fmt.Errorf("%q names a %s; pick one with --kind", name, strings.Join(kinds, " and a "))
			}
			target, hint := name, ""
			if kinds[0] == "rollout" {
				r, _ := findRollout(org, name)
				if r.Experiment == "" {
					return fmt.Errorf("rollout %s has no backing experiment to kill (ring-wide steps only); abort it with `halo rollout rollback %s --reason <why>`", name, name)
				}
				target, hint = r.Experiment, "halo rollout rollback "+name+" --reason ...   (opens the PR that aborts it and re-points rings)"
				kinds[0] = "experiment"
			}
			if server == "" {
				server = os.Getenv("HALO_SERVER")
			}
			session := os.Getenv("HALO_SESSION")
			if server == "" || session == "" {
				return errors.New("set --server (or HALO_SERVER) and HALO_SESSION (an admin halo_session cookie value)")
			}
			verb := "kill"
			if unkill {
				verb = "unkill"
			}
			res, err := postKill(cmd.Context(), http.DefaultClient, server, session, kinds[0], target, verb, reason)
			if err != nil {
				return err
			}
			res["kind"], res["name"] = kinds[0], target
			if hint != "" {
				res["next"] = hint
			}
			return a.emit(res, func() {
				fmt.Fprintf(a.out, "%s %s: killed=%v changed=%v\n", kinds[0], target, res["killed"], res["changed"])
				if hint != "" {
					fmt.Fprintln(a.out, a.bold("next:"), hint)
				}
			})
		},
	}
	c.Flags().StringVar(&server, "server", "", "halo-server base URL (or HALO_SERVER)")
	c.Flags().StringVar(&reason, "reason", "", "why; recorded in the audit log (required to kill)")
	c.Flags().StringVar(&kind, "kind", "", "experiment | toggle | rollout, when the name is ambiguous")
	c.Flags().BoolVar(&unkill, "unkill", false, "clear the kill instead")
	return c
}

func (a *app) cmdStatus() *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "One screen: rings, rollouts, live experiments, toggles and policy health", Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.openRepo(cmd)
			if err != nil {
				return err
			}
			org := r.Org
			issues := org.Validate()
			errs := 0
			for _, i := range issues {
				if i.Severity == policy.SeverityError {
					errs++
				}
			}
			type ringRow struct{ Name, Cohort, Profile, Release string }
			var rings []ringRow
			for _, g := range org.Rings {
				rings = append(rings, ringRow{g.Name, cohort(g.Membership), g.Profile, orDash(g.Release)})
			}
			var running []*policy.Experiment
			for _, e := range org.Experiments {
				if e.Status == "running" {
					running = append(running, e)
				}
			}
			mode := "full"
			if r.Simple() {
				s := r.Root.Simple
				mode = fmt.Sprintf("simple (safety %s, rollout %s)", cmpOr(s.Safety, "standard"), cmpOr(s.Rollout, "standard"))
			}
			res := map[string]any{"org": org.Name, "mode": mode, "errors": errs, "warnings": len(issues) - errs,
				"rings": rings, "rollouts": orEmptyR(org.Rollouts), "experiments": running, "toggles": toggleRows(org)}
			return a.emit(res, func() {
				health := a.green("OK")
				if errs > 0 {
					health = a.red(fmt.Sprintf("%d errors", errs))
				}
				fmt.Fprintf(a.out, "%s  %s  policy %s, %d warnings (halo validate for details)\n\n", a.bold(org.Name), mode, health, len(issues)-errs)
				tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "RING\tCOHORT\tPROFILE\tRELEASE")
				for _, g := range rings {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", g.Name, g.Cohort, g.Profile, g.Release)
				}
				fmt.Fprintln(tw)
				fmt.Fprintln(tw, "ROLLOUT\tAXIS\tSTATUS\tSTEP")
				for _, ro := range org.Rollouts {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", ro.Name, ro.Axis, ro.EffectiveStatus(), stepOf(ro))
				}
				if len(org.Rollouts) == 0 {
					fmt.Fprintln(tw, "-\t\t\t")
				}
				fmt.Fprintln(tw)
				fmt.Fprintln(tw, "EXPERIMENT\tAXIS\tTYPE\tRINGS")
				for _, e := range running {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Name, e.Axis, e.Type, strings.Join(e.Rings, ","))
				}
				if len(running) == 0 {
					fmt.Fprintln(tw, "-\t\t\t")
				}
				fmt.Fprintln(tw)
				fmt.Fprintln(tw, "TOGGLE\tAXIS\tOWNER\tEXPIRES")
				for _, t := range toggleRows(org) {
					exp := t.Expires
					if t.Stale {
						exp += " " + a.yellow("STALE")
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Name, t.Axis, t.Owner, exp)
				}
				if len(org.Toggles) == 0 {
					fmt.Fprintln(tw, "-\t\t\t")
				}
				tw.Flush()
			})
		},
	}
}

func orEmptyR(rs []*policy.Rollout) []*policy.Rollout {
	if rs == nil {
		return []*policy.Rollout{}
	}
	return rs
}

func stepOf(r *policy.Rollout) string {
	if i := r.StepIndex(r.Step); i >= 0 {
		return fmt.Sprintf("%s (%d/%d)", r.Step, i+1, len(r.Steps))
	}
	return fmt.Sprintf("(not started, %d steps)", len(r.Steps))
}

func cohort(m policy.Membership) string {
	var p []string
	if m.Default {
		p = append(p, "everyone else")
	}
	if m.Percent > 0 {
		p = append(p, fmt.Sprintf("%g%%", m.Percent))
	}
	if len(m.Groups) > 0 {
		p = append(p, "groups "+strings.Join(m.Groups, ","))
	}
	if len(m.Users) > 0 {
		p = append(p, fmt.Sprintf("%d users", len(m.Users)))
	}
	return orDash(strings.Join(p, " + "))
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (a *app) cmdExplain() *cobra.Command {
	var kind string
	c := &cobra.Command{
		Use: "explain", Short: "Print the full low-level policy halos.yaml expands to (the hidden layer)", Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.openRepo(cmd)
			if err != nil {
				return err
			}
			docs, err := r.Explain(kind)
			if err != nil {
				return err
			}
			return a.emit(docs, func() {
				for i, d := range docs {
					if i > 0 {
						fmt.Fprintln(a.out, "---")
					}
					fmt.Fprintf(a.out, "# source: %s\n%s", d.Source, d.YAML)
				}
			})
		},
	}
	c.Flags().StringVar(&kind, "kind", "", "only this kind (Gateway, Profile, Ring, Experiment, Toggle, Rollout)")
	return c
}

func (a *app) cmdEject() *cobra.Command {
	var dry bool
	c := &cobra.Command{
		Use:   "eject",
		Short: "Write simple mode's generated Gateway, Profile and Rings out as files and drop the simple keys from halos.yaml",
		Long:  "The policy loads to exactly the same thing afterwards; from then on you edit the low-level files.",
		Args:  cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.openRepo(cmd)
			if err != nil {
				return err
			}
			ch, err := r.Eject()
			if err != nil {
				return err
			}
			return a.applyChange(ch, dry)
		},
	}
	c.Flags().BoolVar(&dry, "dry-run", false, "print the diff instead of writing")
	return c
}

func (a *app) cmdMigrate() *cobra.Command {
	var dry bool
	c := &cobra.Command{
		Use:   "migrate",
		Short: "Rewrite policy documents from apiVersion " + policy.APIVersionV1Alpha1 + " to " + policy.APIVersion,
		Long: "Only the apiVersion value changes: comments, formatting and every other byte stay as they are. " +
			"Semantics are identical, so the policy loads to the same thing afterwards. Running it again is a no-op.",
		Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			ch, err := intent.Migrate(dir)
			if err != nil {
				return err
			}
			if len(ch.Files) == 0 {
				return a.emit(map[string]any{"dryRun": dry, "created": []string{}, "changed": []string{}}, func() {
					fmt.Fprintln(a.out, a.green("OK")+": every document already uses "+policy.APIVersion)
				})
			}
			return a.applyChange(ch, dry)
		},
	}
	c.Flags().BoolVar(&dry, "dry-run", false, "print the diff instead of writing")
	return c
}
