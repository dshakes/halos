package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/onboard"
)

// Onboarding: the deterministic steps the halos-onboard skill (and the MCP
// tools of the same names) drive. Every writing step is a dry run unless
// --apply; none publishes, enrolls, pushes or merges.

func (a *app) cmdDoctor() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check this machine and the policy repo; print the exact fix for each problem",
		Long: "Detects the AI CLIs on PATH and their versions, the tools onboarding uses, which credential\n" +
			"variables are set (never their values), whether the policy validates, whether the pinned CLI\n" +
			"versions match, and whether the gateway answers. Exits 1 when a check fails.",
		Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			r := onboard.Doctor(cmd.Context(), onboard.System(), dir)
			if err := a.emit(r, func() {
				for _, c := range r.Checks {
					st := a.green("ok  ")
					switch c.Status {
					case onboard.StatusWarn:
						st = a.yellow("warn")
					case onboard.StatusFail:
						st = a.red("FAIL")
					}
					fmt.Fprintf(a.out, "%s %-24s %s\n", st, c.ID, c.Detail)
					if c.Fix != "" {
						fmt.Fprintf(a.out, "     %-24s %s %s\n", "", a.bold("fix:"), c.Fix)
					}
				}
				set := []string{}
				for _, c := range r.Credentials {
					if c.Present {
						set = append(set, c.Env)
					}
				}
				fmt.Fprintf(a.out, "credentials set (values never shown): %s\n", orDash(strings.Join(set, ", ")))
			}); err != nil {
				return err
			}
			if !r.OK {
				return &exitErr{code: exitError}
			}
			return nil
		},
	}
}

func (a *app) cmdOnboard() *cobra.Command {
	c := &cobra.Command{
		Use:   "onboard",
		Short: "Agent-friendly onboarding steps: detect, local, install, proxy, verify, company (dry run unless --apply)",
		Long: "The deterministic core of onboarding. Each step is idempotent, supports --output json and writes\n" +
			"nothing without --apply. Start with `halo doctor`; see the Start here docs page for the three paths.",
	}
	c.AddCommand(a.cmdOnboardDetect(), a.cmdOnboardLocal(), a.cmdOnboardInstall(), a.cmdOnboardProxy(),
		a.cmdOnboardVerify(), a.cmdOnboardCompany())
	return c
}

func (a *app) cmdOnboardDetect() *cobra.Command {
	return &cobra.Command{
		Use: "detect", Short: "List the AI CLIs on PATH with versions, and which credential variables are set (never values)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e := onboard.System()
			hs, creds := onboard.Detect(cmd.Context(), e), onboard.Credentials(e)
			return a.emit(map[string]any{"harnesses": hs, "credentials": creds, "suggestedProvider": onboard.SuggestProvider(e)}, func() {
				tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "HARNESS\tBINARY\tVERSION\tPATH")
				for _, h := range hs {
					v := h.Version
					if !h.Installed {
						v = "-"
					} else if v == "" {
						v = "? (" + h.Error + ")"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", h.Name, h.Binary, v, orDash(h.Path))
				}
				fmt.Fprintln(tw)
				fmt.Fprintln(tw, "CREDENTIAL\tFOR\tSET")
				for _, c := range creds {
					fmt.Fprintf(tw, "%s\t%s\t%t\n", c.Env, c.For, c.Present)
				}
				_ = tw.Flush()
			})
		},
	}
}

func (a *app) cmdOnboardLocal() *cobra.Command {
	var o onboard.LocalOptions
	var tools, models []string
	c := &cobra.Command{
		Use:   "local",
		Short: "My machine: create (or keep) halos.yaml, validate it and plan the managed-config install",
		Long: "Defaults come from this machine: --tools pins every CLI on PATH at its installed version, --provider\n" +
			"is the one whose key is exported, and the gateway is a local halo-proxy on http://127.0.0.1:8088.\n" +
			"An existing halos.yaml is never overwritten. --apply writes halos.yaml only; managed config is\n" +
			"written by `halo onboard install --apply`.",
		Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			e := onboard.System()
			o.Dir, o.GOOS = dir, runtime.GOOS
			if o.Init.Tools, err = splitKV(tools, "@", "--tools"); err != nil {
				return err
			}
			if len(o.Init.Tools) == 0 {
				if o.Init.Tools = onboard.SuggestTools(onboard.Detect(cmd.Context(), e)); len(o.Init.Tools) == 0 {
					o.Init.Tools = onboard.FallbackTools
				}
			}
			if o.Init.Models, err = splitKV(models, "=", "--model"); err != nil {
				return err
			}
			if o.Init.Provider == "" {
				o.Init.Provider = onboard.SuggestProvider(e)
			}
			r, err := onboard.Local(o)
			if err != nil {
				return err
			}
			if err := a.emit(r, func() { a.printLocal(r) }); err != nil {
				return err
			}
			if !r.Valid {
				return &exitErr{code: exitValidation}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&o.Init.Org, "org", "local", "organization name")
	f.StringSliceVar(&tools, "tools", nil, "harnesses as name@version (default: every CLI on PATH at its installed version)")
	f.StringVar(&o.Init.Provider, "provider", "", "anthropic | bedrock | vertex | openai | gemini | multi (default: from the exported key)")
	f.StringArrayVar(&models, "model", nil, "model alias=provider model id, repeatable")
	f.StringVar(&o.Init.Project, "project", "", "Google Cloud project (provider vertex)")
	f.StringVar(&o.Init.Gateway, "gateway", "", "gateway base URL the CLIs call (default: local halo-proxy http://"+onboard.DefaultLocalProxy+")")
	f.StringVar(&o.Init.Safety, "safety", "standard", "strict | standard | relaxed")
	f.StringVar(&o.Init.Rollout, "rollout", "standard", "fast | standard | careful")
	f.StringVar(&o.Ring, "ring", "", "ring this machine follows (default: the GA ring)")
	f.StringVar(&o.Root, "root", "", "plan the install under this directory instead of the real paths")
	f.BoolVar(&o.Apply, "apply", false, "write halos.yaml (default: dry run)")
	return c
}

func (a *app) printLocal(r *onboard.LocalResult) {
	verb := map[string]string{onboard.PolicyCreate: "create", onboard.PolicyUnchanged: "unchanged", onboard.PolicyKept: "kept"}[r.Policy.Action]
	if r.DryRun && r.Policy.Action == onboard.PolicyCreate {
		verb = "would create"
		fmt.Fprint(a.out, r.Policy.Content)
	}
	fmt.Fprintln(a.out, a.green(verb), r.Policy.Path)
	for _, n := range r.Policy.Notes {
		fmt.Fprintln(a.out, a.yellow("note:"), n)
	}
	for _, i := range r.Issues {
		fmt.Fprintln(a.out, i)
	}
	if !r.Valid {
		fmt.Fprintln(a.out, a.red("policy does not validate"))
		return
	}
	fmt.Fprintln(a.out, a.green("OK")+": policy valid")
	a.printInstall(r.Install, true)
	for _, n := range r.Next {
		fmt.Fprintln(a.out, a.bold("next:"), n)
	}
}

func (a *app) printInstall(p *onboard.InstallPlan, dry bool) {
	fmt.Fprintf(a.out, "install plan: ring %s, %s, gateway %s\n", p.Ring, p.OS, orDash(p.Gateway))
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	for _, f := range p.Files {
		act := f.Action
		if dry && act != onboard.ActionUnchanged {
			act = "would " + act
		}
		line := fmt.Sprintf("  %s\t%s\t%s", act, f.Harness, f.Dest)
		if f.Backup != "" {
			line += "\t(original kept at " + f.Backup + ")"
		}
		fmt.Fprintln(tw, line)
	}
	_ = tw.Flush()
	var hs []string
	for h := range p.Versions {
		hs = append(hs, h)
	}
	sort.Strings(hs)
	for _, h := range hs {
		fmt.Fprintf(a.out, "  pin %s %s\n", h, orDash(p.Versions[h]))
	}
	for _, w := range p.Warnings {
		fmt.Fprintln(a.out, a.yellow("warning:"), w)
	}
}

func (a *app) cmdOnboardInstall() *cobra.Command {
	var ring, root string
	var apply, show bool
	c := &cobra.Command{
		Use:   "install",
		Short: "Render a ring's managed config for this OS and show exactly what lands where; --apply writes it",
		Long: "Managed config lives in admin-owned paths (e.g. /Library/Application Support/ClaudeCode on macOS,\n" +
			"/etc on Linux), so --apply usually needs sudo; --root DIR stages the same tree under DIR. A file that\n" +
			"differs is backed up once to <file>.halos-backup. Idempotent: a second --apply writes nothing.",
		Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			p, written, err := onboard.Install(dir, ring, runtime.GOOS, root, apply)
			if err != nil {
				return err
			}
			if !show {
				for i := range p.Files {
					p.Files[i].Content = ""
				}
			}
			return a.emit(map[string]any{"dryRun": !apply, "plan": p, "written": written}, func() {
				if show {
					for _, f := range p.Files {
						fmt.Fprintf(a.out, "--- %s\n%s\n", f.Dest, f.Content)
					}
				}
				a.printInstall(p, !apply)
				for _, w := range written {
					fmt.Fprintln(a.out, a.green("wrote"), w)
				}
				if !apply {
					fmt.Fprintln(a.out, "dry run: nothing written (--show prints the contents; --apply writes)")
				}
			})
		},
	}
	c.Flags().StringVar(&ring, "ring", "", "ring to install (default: the GA ring)")
	c.Flags().StringVar(&root, "root", "", "write under this directory instead of the real paths")
	c.Flags().BoolVar(&apply, "apply", false, "write the files (default: dry run)")
	c.Flags().BoolVar(&show, "show", false, "include each file's contents")
	return c
}

func (a *app) cmdOnboardProxy() *cobra.Command {
	var listen string
	var apply bool
	c := &cobra.Command{
		Use:   "proxy",
		Short: "Write a single-developer halo-proxy config (loopback, keys from your env) into .halos/local",
		Args:  cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			r, err := onboard.Proxy(onboard.System(), dir, listen, apply)
			if err != nil {
				return err
			}
			return a.emit(r, func() {
				var ps []string
				for p := range r.Files {
					ps = append(ps, p)
				}
				sort.Strings(ps)
				for _, p := range ps {
					act := r.Files[p]
					if r.DryRun && act != onboard.ActionUnchanged {
						act = "would " + act
					}
					fmt.Fprintln(a.out, a.green(act), p)
				}
				for _, n := range r.Notes {
					fmt.Fprintln(a.out, a.bold("next:"), n)
				}
				if r.DryRun {
					fmt.Fprintln(a.out, "dry run: nothing written")
				}
			})
		},
	}
	c.Flags().StringVar(&listen, "listen", onboard.DefaultLocalProxy, "loopback address halo-proxy listens on")
	c.Flags().BoolVar(&apply, "apply", false, "write the files (default: dry run)")
	return c
}

func (a *app) cmdOnboardVerify() *cobra.Command {
	var assume, dry bool
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "verify [harness...]",
		Short: "Run each installed CLI headless (claude -p, codex exec, gemini -p, copilot -p) and check the reply",
		Long: "One short model call per CLI, through whatever endpoint its config points at. Skipped when the CLI\n" +
			"is missing or no credential variable is set; a CLI that is logged in (OAuth, keychain) needs\n" +
			"--assume-auth because halo cannot see that. Output is redacted.",
		Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, args []string) error {
			e := onboard.System()
			if len(args) == 0 {
				for _, h := range onboard.Detect(cmd.Context(), e) {
					if h.Installed {
						args = append(args, h.Name)
					}
				}
			}
			if len(args) == 0 {
				return errors.New("no AI CLI on PATH to verify: run halo doctor")
			}
			var rs []onboard.VerifyResult
			failed := false
			for _, h := range args {
				r := onboard.Verify(cmd.Context(), e, h, assume, dry, timeout)
				failed = failed || r.Status == onboard.VerifyFail
				rs = append(rs, r)
			}
			if err := a.emit(rs, func() {
				for _, r := range rs {
					st := map[string]string{onboard.VerifyPass: a.green("pass"), onboard.VerifyFail: a.red("FAIL"),
						onboard.VerifySkipped: a.yellow("skip"), onboard.VerifyDryRun: "dry "}[r.Status]
					fmt.Fprintf(a.out, "%s %-12s %s\n     $ %s\n", st, r.Harness, r.Detail, strings.Join(r.Command, " "))
					if r.Output != "" {
						fmt.Fprintf(a.out, "     > %s\n", strings.ReplaceAll(r.Output, "\n", "\n     > "))
					}
				}
			}); err != nil {
				return err
			}
			if failed {
				return &exitErr{code: exitError}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&assume, "assume-auth", false, "run even when no credential variable is set (the CLI is logged in)")
	c.Flags().BoolVar(&dry, "dry-run", false, "print the commands instead of running them")
	c.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "per-CLI timeout")
	return c
}

func (a *app) cmdOnboardCompany() *cobra.Command {
	var o onboard.CompanyOptions
	var tools, models []string
	var apply bool
	c := &cobra.Command{
		Use:   "company",
		Short: "My company: generate the policy repo, Helm values, IdP client and enrollment config from interview answers",
		Long: "Writes (with --apply) into an empty --policy-dir: halos.yaml, .halos/helm-values.yaml,\n" +
			".halos/oidc-client.yaml, .halos/enroll/* per delivery channel, a validate+plan CI workflow, a smoke eval\n" +
			"and a README of the human steps. Nothing is secret, published, enrolled or pushed.",
		Example: "  halo onboard company --policy-dir acme-halos --org acme --tools claude-code@2.1.280,codex@0.99.0 \\\n" +
			"    --provider bedrock --gateway https://ai.acme.com --gateway-kind halo-proxy --issuer https://login.acme.com \\\n" +
			"    --admin-group ai-platform --delivery halod,devcontainer --registry ghcr.io/acme/halos-releases \\\n" +
			"    --policy-repo https://github.com/acme/halos-policy.git --portal-url https://halos.acme.com",
		Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			if o.Init.Tools, err = splitKV(tools, "@", "--tools"); err != nil {
				return err
			}
			if o.Init.Models, err = splitKV(models, "=", "--model"); err != nil {
				return err
			}
			r, err := onboard.WriteCompany(dir, o, apply)
			if err != nil {
				return err
			}
			if err := a.emit(r, func() {
				var ps []string
				for p := range r.Files {
					ps = append(ps, p)
				}
				sort.Strings(ps)
				for _, p := range ps {
					act := r.Files[p]
					if r.DryRun && act != onboard.ActionUnchanged {
						act = "would " + act
					}
					fmt.Fprintln(a.out, a.green(act), filepath.Join(dir, filepath.FromSlash(p)))
				}
				for _, i := range r.Issues {
					fmt.Fprintln(a.out, i)
				}
				if !r.Valid {
					fmt.Fprintln(a.out, a.red("generated policy does not validate; nothing written"))
					return
				}
				for _, n := range r.Next {
					fmt.Fprintln(a.out, a.bold("next:"), n)
				}
				if r.DryRun {
					fmt.Fprintln(a.out, "dry run: nothing written")
				}
			}); err != nil {
				return err
			}
			if !r.Valid {
				return &exitErr{code: exitValidation}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&o.Init.Org, "org", "", "organization name (required)")
	f.StringSliceVar(&tools, "tools", []string{"claude-code@2.1.280"}, "harnesses as name@version")
	f.StringVar(&o.Init.Provider, "provider", "anthropic", "anthropic | bedrock | vertex | openai | gemini | multi")
	f.StringArrayVar(&models, "model", nil, "model alias=provider model id, repeatable")
	f.StringVar(&o.Init.Project, "project", "", "Google Cloud project (provider vertex)")
	f.StringVar(&o.Init.Gateway, "gateway", "", "https URL the CLIs call (required)")
	f.StringVar(&o.GatewayKind, "gateway-kind", "halo-proxy", strings.Join(onboard.Gateways, " | "))
	f.StringVar(&o.AuthHelper, "auth-helper", "", "command each laptop runs to print a short-lived gateway token (optional)")
	f.StringVar(&o.Init.Issuer, "issuer", "", "OIDC issuer URL of your IdP (required)")
	f.StringVar(&o.Init.ClientID, "client-id", "halos", "OIDC client id")
	f.StringSliceVar(&o.Init.Admins, "admin-group", nil, "IdP group of platform admins (ring0 and portal admins), repeatable")
	f.StringSliceVar(&o.Delivery, "delivery", []string{"halod"}, strings.Join(onboard.Deliveries, " | ")+", comma-separated")
	f.StringVar(&o.Registry, "registry", "", "OCI repository releases are published to (required)")
	f.StringVar(&o.PolicyRepo, "policy-repo", "", "git URL of this policy repo, for Helm git-sync (required)")
	f.StringVar(&o.PortalURL, "portal-url", "", "https URL halo-server will serve the console on (required)")
	f.StringVar(&o.HaloVersion, "halo-version", version, "halo version CI installs")
	f.StringVar(&o.Init.Safety, "safety", "standard", "strict | standard | relaxed")
	f.StringVar(&o.Init.Rollout, "rollout", "standard", "fast | standard | careful")
	f.BoolVar(&apply, "apply", false, "write the files (default: dry run)")
	_ = c.MarkFlagRequired("org")
	return c
}

// cmdQuickstart wraps scripts/demo.sh (make demo): it needs a Halos checkout.
func (a *app) cmdQuickstart() *cobra.Command {
	var src string
	var noOpen, dry bool
	c := &cobra.Command{
		Use:   "quickstart [down]",
		Short: "Try it: bring up the whole stack on Docker (make demo), open the console and print a guided tour",
		Long: "Runs scripts/demo.sh from a Halos checkout: --src, else the current directory if it is one, else a\n" +
			"shallow clone it makes under your user cache dir (halos/src; the path is printed). DEV ONLY: mock IdP, mock models, throwaway keys.\n" +
			"`halo quickstart down` stops it and deletes its volumes.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			down := len(args) == 1
			if down && args[0] != "down" {
				return fmt.Errorf("unknown argument %q (want: down)", args[0])
			}
			if src == "" {
				src = "."
				if _, err := os.Stat(filepath.Join(src, "scripts", "demo.sh")); err != nil {
					cache, err := os.UserCacheDir()
					if err != nil {
						return err
					}
					src = filepath.Join(cache, "halos", "src")
				}
			}
			steps := [][]string{}
			if _, err := os.Stat(filepath.Join(src, "scripts", "demo.sh")); err != nil {
				steps = append(steps, []string{"git", "clone", "--depth", "1", "https://github.com/dshakes/halos", src})
			}
			script := []string{"./scripts/demo.sh"}
			if down {
				script = append(script, "down")
			}
			steps = append(steps, script)
			console := cmpOr(os.Getenv("HALO_DEMO_CONSOLE_URL"), "http://localhost:"+cmpOr(os.Getenv("HALO_DEMO_CONSOLE_PORT"), "18080"))
			if dry {
				return a.emit(map[string]any{"dir": src, "commands": steps, "console": console}, func() {
					for _, s := range steps {
						fmt.Fprintf(a.out, "would run (in %s): %s\n", src, strings.Join(s, " "))
					}
				})
			}
			for _, t := range []string{"docker", "git"} {
				if _, err := exec.LookPath(t); err != nil {
					return fmt.Errorf("%s is not on PATH: run halo doctor for the fix", t)
				}
			}
			for _, s := range steps {
				if s[0] == "git" {
					fmt.Fprintf(a.out, "cloning halos into %s\n", src)
				}
				x := exec.CommandContext(cmd.Context(), s[0], s[1:]...) //nolint:gosec // fixed commands
				if s[0] != "git" {
					x.Dir = src
				}
				x.Stdout, x.Stderr = a.errw, a.errw // stdout stays clean for --output json
				if err := x.Run(); err != nil {
					return fmt.Errorf("%s: %w", strings.Join(s, " "), err)
				}
			}
			if down {
				return a.emit(map[string]any{"down": true}, func() { fmt.Fprintln(a.out, "quickstart stopped") })
			}
			opened := false
			if !noOpen {
				opener := map[string]string{"darwin": "open", "linux": "xdg-open", "windows": "explorer"}[runtime.GOOS]
				opened = opener != "" && exec.Command(opener, console).Start() == nil //nolint:gosec // fixed opener and local URL
			}
			return a.emit(map[string]any{"console": console, "opened": opened, "tour": quickstartTour}, func() {
				fmt.Fprintf(a.out, "\n%s %s\n", a.bold("Console:"), console)
				for i, s := range quickstartTour {
					fmt.Fprintf(a.out, "%d. %s\n", i+1, s)
				}
			})
		},
	}
	c.Flags().StringVar(&src, "src", "", "Halos checkout to run from")
	c.Flags().BoolVar(&noOpen, "no-open", false, "do not open the console in a browser")
	c.Flags().BoolVar(&dry, "dry-run", false, "print the commands instead of running them")
	return c
}

// quickstartTour follows what scripts/demo.sh seeds and prints.
var quickstartTour = []string{
	"Open the console, Sign in and pick alice@acme.com (ai-platform, admin): she sees experiments, rollouts and toggles.",
	"Sign in as bob@acme.com (eng, ring2-early): he is in the claude-cli A/B and the sonnet shadow.",
	"Call halo-proxy as alice with the curl the demo printed: ring and model come from the verified token, never from x-halo-* headers.",
	"Grafana (default http://localhost:13000, admin / halo-dev-only) shows the evidence plane.",
	"Your own machine next: halo doctor, then halo onboard local (dry run).",
	"Tear down: halo quickstart down",
}
