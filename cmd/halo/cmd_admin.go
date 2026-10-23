package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/vendoradmin"
)

// apiVendors have a public read API; the rest are render + export only.
var apiVendors = []string{"gemini", "copilot"}

// exitUnchecked is `halo admin plan --offline`: nothing was compared, so it is
// neither in sync (0) nor drift (2). Never gate CI on it.
const exitUnchecked = 3

// adminFlags are the credential and endpoint flags of halo admin plan|apply.
type adminFlags struct {
	offline   bool
	tokenFile map[string]*string
	tokenEnv  map[string]*string
	baseURL   map[string]*string
}

func (f *adminFlags) add(c *cobra.Command, live bool) {
	f.tokenFile, f.tokenEnv, f.baseURL = map[string]*string{}, map[string]*string{}, map[string]*string{}
	for _, v := range apiVendors {
		f.tokenFile[v] = c.Flags().String(v+"-token-file", "", "file holding the "+v+" API credential (read once, never logged)")
		f.tokenEnv[v] = c.Flags().String(v+"-token-env", vendoradmin.TokenEnv(v), "environment variable holding the "+v+" API credential")
		f.baseURL[v] = c.Flags().String(v+"-base-url", "", v+" API base URL: https, or http to a loopback host only (default the vendor's; e.g. a GitHub Enterprise Server API)")
	}
	if live {
		c.Flags().BoolVar(&f.offline, "offline", false, "render only: do not read the live consoles (no credentials needed, no drift check; exits 3)")
	}
}

func (f *adminFlags) creds() (map[string]vendoradmin.Cred, error) {
	out := map[string]vendoradmin.Cred{}
	for _, v := range apiVendors {
		tok := os.Getenv(*f.tokenEnv[v])
		if p := *f.tokenFile[v]; p != "" {
			b, err := os.ReadFile(p) //nolint:gosec // operator-supplied credential path is the point
			if err != nil {
				return nil, fmt.Errorf("--%s-token-file: %w", v, err)
			}
			tok = strings.TrimSpace(string(b))
		}
		out[v] = vendoradmin.Cred{Token: tok, BaseURL: *f.baseURL[v]}
	}
	return out, nil
}

// adminReport loads the policy, renders every console and, unless offline,
// reads and diffs the ones with an API.
func (a *app) adminReport(cmd *cobra.Command, f *adminFlags) (*vendoradmin.Report, map[string]*vendoradmin.Client, error) {
	dir, err := policyDir(cmd, nil)
	if err != nil {
		return nil, nil, err
	}
	org, err := a.loadValid(dir)
	if err != nil {
		return nil, nil, err
	}
	rep, err := vendoradmin.Render(org)
	if err != nil {
		return nil, nil, err
	}
	if f.offline {
		return rep, nil, nil
	}
	creds, err := f.creds()
	if err != nil {
		return nil, nil, err
	}
	clients, err := rep.Clients(vendoradmin.Targets(org.VendorAdmin), creds)
	if err != nil {
		return nil, nil, err
	}
	rep.ReadLive(cmd.Context(), clients, func(v string) string {
		return fmt.Sprintf("set %s or pass --%s-token-file", *f.tokenEnv[v], v)
	})
	return rep, clients, nil
}

func (a *app) cmdAdmin() *cobra.Command {
	c := &cobra.Command{Use: "admin", Short: "Sync vendor admin consoles (Claude, ChatGPT/Codex, Gemini, Copilot, Cursor) with policy (ADR-0025)"}

	var pf adminFlags
	plan := &cobra.Command{
		Use:         "plan",
		Annotations: policyDirAnno,
		Short:       "Render vendorAdmin's consoles from policy and diff them against the live settings (read-only)",
		Long: "Renders the console settings of every vendor under halos.yaml vendorAdmin from one ring's profile and, for vendors " +
			"with a public read API (gemini, copilot), reads the live settings and diffs them. Credentials come from " +
			"--<vendor>-token-file or the environment variable --<vendor>-token-env names (default HALO_ADMIN_<VENDOR>_TOKEN), never " +
			"from policy. Vendors without a read API are reported as not checked, never as in sync. Exit 0 when every readable " +
			"console is in sync, 2 on drift, 1 when a console could not be read, 3 with --offline (nothing compared; do not gate " +
			"CI on it). Writes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, _, err := a.adminReport(cmd, &pf)
			if err != nil {
				return err
			}
			if err := a.emit(rep, func() { a.printAdmin(rep) }); err != nil {
				return err
			}
			if pf.offline {
				return &exitErr{code: exitUnchecked}
			}
			if errs := rep.Errors(); len(errs) > 0 {
				return &exitErr{code: exitError, err: errors.New(vendoradmin.Sanitize(strings.Join(errs, "; ")))}
			}
			if rep.Drift() {
				return &exitErr{code: exitValidation}
			}
			return nil
		},
	}
	pf.add(plan, true)

	var af adminFlags
	var yes bool
	apply := &cobra.Command{
		Use:         "apply",
		Annotations: policyDirAnno,
		Short:       "Write the drifted settings of vendors with a public write API, after showing the diff",
		Long: "Runs plan, prints it, asks for confirmation (or --yes) and writes the drifted settings that have a public write " +
			"API (gemini logging and release channel, copilot content exclusion). It refuses the whole run if a change it " +
			"would write loosens a control the console has now, if a console resource Halos does not own governs the same " +
			"target, or if a change would emit bypassPermissions or danger-full-access. Just before writing it re-reads each " +
			"console and aborts that vendor if it changed since the confirmed plan. Read-only and manual settings are listed " +
			"for a human. Prints an apply record with one result per change for the audit trail.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, clients, err := a.adminReport(cmd, &af)
			if err != nil {
				return err
			}
			fmt.Fprint(a.errw, a.renderAdmin(rep))
			if errs := rep.Errors(); len(errs) > 0 {
				return &exitErr{code: exitError, err: errors.New(vendoradmin.Sanitize(strings.Join(errs, "; ")))}
			}
			var refuse []string
			n := 0
			for _, p := range rep.Vendors {
				for _, ch := range p.Loosenings() {
					refuse = append(refuse, p.Vendor+" "+ch.Key+" would loosen a console control")
				}
				for _, cf := range p.Conflicts {
					refuse = append(refuse, p.Vendor+" "+cf+" also governs "+p.Target)
				}
				for _, ch := range p.Changes {
					if ch.Access == vendoradmin.AccessWrite {
						n++
					}
				}
			}
			if len(refuse) > 0 {
				return &exitErr{code: exitError, err: fmt.Errorf("refusing to apply, nothing written: %s; change it in the console by hand or tighten the policy", vendoradmin.Sanitize(strings.Join(refuse, "; ")))}
			}
			rec := adminRecord{Time: time.Now().UTC(), Actor: actor(), Ring: rep.Ring, Profile: rep.Profile, Applied: []adminApplied{}}
			if n == 0 {
				fmt.Fprintln(a.errw, "nothing to apply")
				return a.emit(rec, func() {})
			}
			if !yes {
				fmt.Fprintf(a.errw, "Apply %d change(s) to the live consoles? Type yes to continue: ", n)
				line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if strings.TrimSpace(line) != "yes" {
					return &exitErr{code: exitError, err: errors.New("not confirmed; nothing applied")}
				}
			}
			var failed error
			for _, p := range rep.Vendors {
				cl := clients[p.Vendor]
				if cl == nil || len(p.Changes) == 0 {
					continue
				}
				res, err := cl.Apply(cmd.Context(), p)
				for _, r := range res {
					rec.Applied = append(rec.Applied, adminApplied{Vendor: p.Vendor, Target: p.Target, Change: r.Change, OK: r.OK, Error: r.Error})
					if !r.OK {
						failed = errors.Join(failed, errors.New(r.Error))
					}
				}
				if err != nil { // refused before any write: record every writable change as not written
					for _, ch := range p.Changes {
						if ch.Access == vendoradmin.AccessWrite {
							rec.Applied = append(rec.Applied, adminApplied{Vendor: p.Vendor, Target: p.Target, Change: ch, Error: "not written: " + err.Error()})
						}
					}
					failed = errors.Join(failed, err)
				}
			}
			if err := a.emit(rec, func() {
				for _, x := range rec.Applied {
					status, why := a.green("applied"), ""
					if !x.OK {
						status, why = a.red("failed "), " ("+x.Error+")"
					}
					fmt.Fprintln(a.out, vendoradmin.Sanitize(fmt.Sprintf("%s %s %s %s: %s -> %s%s", status, x.Vendor, x.Target, x.Change.Key, show(x.Change.Current), show(x.Change.Desired), why)))
				}
				fmt.Fprintf(a.out, "apply record: %s by %s, ring %s (profile %s)\n", rec.Time.Format(time.RFC3339), vendoradmin.Sanitize(rec.Actor), rec.Ring, rec.Profile)
			}); err != nil {
				return err
			}
			if failed != nil {
				return &exitErr{code: exitError, err: errors.New(vendoradmin.Sanitize(failed.Error()))}
			}
			return nil
		},
	}
	af.add(apply, false)
	apply.Flags().BoolVar(&yes, "yes", false, "apply without the interactive confirmation")

	var out string
	export := &cobra.Command{
		Use:         "export",
		Annotations: policyDirAnno,
		Short:       "Write the console artifacts and manual steps for every vendorAdmin vendor",
		Long: "Writes <out>/<vendor>/ with the artifacts an admin reconciles into a console that has no write API (Claude " +
			"managed settings JSON without machine-only keys, Codex requirements and config TOML, the Cursor model list) and a " +
			"STEPS.md with the manual steps, the read-only settings and every warning. Reads no console.",
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
			rep, err := vendoradmin.Render(org)
			if err != nil {
				return err
			}
			var written []string
			for _, p := range rep.Vendors {
				for _, art := range p.Artifacts {
					fp := filepath.Join(out, p.Vendor, art.Name)
					if err := writeFile(fp, []byte(art.Content), 0); err != nil {
						return err
					}
					written = append(written, fp)
				}
				fp := filepath.Join(out, p.Vendor, "STEPS.md")
				if err := writeFile(fp, []byte(steps(rep, p)), 0); err != nil {
					return err
				}
				written = append(written, fp)
			}
			return a.emit(map[string]any{"ring": rep.Ring, "files": written}, func() {
				for _, w := range written {
					fmt.Fprintln(a.out, "wrote", w)
				}
			})
		},
	}
	export.Flags().StringVar(&out, "out", "vendor-admin", "output directory")

	c.AddCommand(plan, apply, export)
	return c
}

// adminRecord is the audit record `halo admin apply` prints: one entry per
// writable change it attempted or refused, each with its own outcome.
type adminRecord struct {
	Time    time.Time      `json:"time"`
	Actor   string         `json:"actor"`
	Ring    string         `json:"ring"`
	Profile string         `json:"profile"`
	Applied []adminApplied `json:"applied"`
}

type adminApplied struct {
	Vendor string             `json:"vendor"`
	Target string             `json:"target"`
	Change vendoradmin.Change `json:"change"`
	OK     bool               `json:"ok"`
	Error  string             `json:"error,omitempty"`
}

func actor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

func show(v any) string {
	if v == nil {
		return "(unset)"
	}
	return fmt.Sprint(v)
}

func (a *app) printAdmin(rep *vendoradmin.Report) { fmt.Fprint(a.out, a.renderAdmin(rep)) }

// renderAdmin is the plan as text. Every value from policy or a console goes
// through vendoradmin.Sanitize before it reaches the terminal.
func (a *app) renderAdmin(rep *vendoradmin.Report) string {
	s := vendoradmin.Sanitize
	var b strings.Builder
	fmt.Fprintf(&b, "%s ring %s (profile %s)\n", a.bold("vendor admin:"), s(rep.Ring), s(rep.Profile))
	for _, w := range rep.Warnings {
		fmt.Fprintf(&b, "  %s %s\n", a.yellow("warning"), s(w))
	}
	for _, p := range rep.Vendors {
		state := "not checked (manual)"
		switch {
		case p.Error != "":
			state = a.red("unread: " + s(p.Error))
		case p.Read && len(p.Changes) == 0:
			state = a.green("in sync")
		case p.Read:
			state = a.yellow(fmt.Sprintf("%d drifted", len(p.Changes)))
		case p.HasAPI():
			state = "not checked (offline)"
		}
		fmt.Fprintf(&b, "\n%s %s: %s\n", a.bold(p.Vendor), s(p.Target), state)
		for _, d := range p.Desired {
			fmt.Fprintf(&b, "  %-48s %-22s %-6s from %s\n", s(d.Key), s(show(d.Value)), d.Access, s(d.From))
		}
		for _, ch := range p.Changes {
			tag := "~"
			switch {
			case ch.Loosens && ch.Access == vendoradmin.AccessWrite:
				tag = a.red("! loosens (apply refuses)")
			case ch.Loosens:
				tag = a.yellow("! loosens (set by hand)")
			}
			fmt.Fprintf(&b, "  %s %s: %s -> %s (%s)\n", tag, s(ch.Key), s(show(ch.Current)), s(show(ch.Desired)), ch.Access)
		}
		for _, cf := range p.Conflicts {
			fmt.Fprintf(&b, "  %s %s also governs %s (apply refuses)\n", a.red("conflict"), s(cf), s(p.Target))
		}
		for _, art := range p.Artifacts {
			fmt.Fprintf(&b, "  artifact %s (halo admin export)\n", s(art.Name))
		}
		for _, w := range p.Warnings {
			fmt.Fprintf(&b, "  %s %s\n", a.yellow("warning"), s(w))
		}
	}
	return b.String()
}

// md makes s safe inside a Markdown table cell or code span: no control or
// format characters, no cell break, no code-span break.
func md(s string) string {
	return strings.NewReplacer("|", `\|`, "`", "'", "\n", " ").Replace(vendoradmin.Sanitize(s))
}

// steps is the STEPS.md `halo admin export` writes for one vendor.
func steps(rep *vendoradmin.Report, p *vendoradmin.Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s console (%s)\n\nRendered by `halo admin export` from ring %s (profile %s). See ADR-0025.\n\n", md(p.Vendor), md(p.Target), md(rep.Ring), md(rep.Profile))
	if len(p.Manual) > 0 {
		b.WriteString("## Steps\n\n")
		for i, s := range p.Manual {
			fmt.Fprintf(&b, "%d. %s\n", i+1, vendoradmin.Sanitize(s))
		}
		b.WriteString("\n")
	}
	if len(p.Desired) > 0 {
		b.WriteString("## Settings\n\n| Setting | Value | Access | From |\n|---|---|---|---|\n")
		for _, s := range p.Desired {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` |\n", md(s.Key), md(show(s.Value)), s.Access, md(s.From))
		}
		b.WriteString("\n")
	}
	if ws := append(append([]string{}, rep.Warnings...), p.Warnings...); len(ws) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, w := range ws {
			fmt.Fprintf(&b, "- %s\n", md(w))
		}
	}
	return b.String()
}
