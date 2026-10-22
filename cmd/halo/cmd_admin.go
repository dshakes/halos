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
		f.baseURL[v] = c.Flags().String(v+"-base-url", "", v+" API base URL (default the vendor's; e.g. a GitHub Enterprise Server API)")
	}
	if live {
		c.Flags().BoolVar(&f.offline, "offline", false, "render only: do not read the live consoles (no credentials needed, no drift check)")
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
	clients := rep.Clients(vendoradmin.Targets(org.VendorAdmin), creds)
	rep.ReadLive(cmd.Context(), clients)
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
			"from policy. Exit 0 in sync, 2 on drift, 1 when a console could not be read. Writes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, _, err := a.adminReport(cmd, &pf)
			if err != nil {
				return err
			}
			if err := a.emit(rep, func() { a.printAdmin(rep) }); err != nil {
				return err
			}
			if errs := rep.Errors(); len(errs) > 0 {
				return &exitErr{code: exitError, err: errors.New(strings.Join(errs, "; "))}
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
			"API (gemini logging and release channel, copilot content exclusion). It refuses the whole run if any change would " +
			"loosen a control the console has now, or would emit bypassPermissions or danger-full-access. Read-only and manual " +
			"settings are listed for a human. Prints an apply record for the audit trail.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, clients, err := a.adminReport(cmd, &af)
			if err != nil {
				return err
			}
			if errs := rep.Errors(); len(errs) > 0 {
				a.printAdmin(rep)
				return &exitErr{code: exitError, err: errors.New(strings.Join(errs, "; "))}
			}
			var loosen []string
			n := 0
			for _, p := range rep.Vendors {
				for _, ch := range p.Changes {
					if ch.Loosens {
						loosen = append(loosen, p.Vendor+" "+ch.Key)
					} else if ch.Access == vendoradmin.AccessWrite {
						n++
					}
				}
			}
			fmt.Fprint(a.errw, a.renderAdmin(rep))
			if len(loosen) > 0 {
				return &exitErr{code: exitError, err: fmt.Errorf("refusing to apply: %s would loosen a console control; change it in the console by hand or tighten the policy", strings.Join(loosen, ", "))}
			}
			if n == 0 {
				fmt.Fprintln(a.errw, "nothing to apply")
				return a.emit(adminRecord{Time: time.Now().UTC(), Actor: actor(), Ring: rep.Ring, Profile: rep.Profile, Applied: []adminApplied{}}, func() {})
			}
			if !yes {
				fmt.Fprintf(a.errw, "Apply %d change(s) to the live consoles? Type yes to continue: ", n)
				line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if strings.TrimSpace(line) != "yes" {
					return &exitErr{code: exitError, err: errors.New("not confirmed; nothing applied")}
				}
			}
			rec := adminRecord{Time: time.Now().UTC(), Actor: actor(), Ring: rep.Ring, Profile: rep.Profile, Applied: []adminApplied{}}
			var failed error
			for _, p := range rep.Vendors {
				cl := clients[p.Vendor]
				if cl == nil || len(p.Changes) == 0 {
					continue
				}
				done, err := cl.Apply(cmd.Context(), p)
				for _, ch := range done {
					rec.Applied = append(rec.Applied, adminApplied{Vendor: p.Vendor, Target: p.Target, Change: ch, OK: err == nil})
				}
				if err != nil {
					failed = errors.Join(failed, err)
				}
			}
			if err := a.emit(rec, func() {
				for _, x := range rec.Applied {
					status := a.green("applied")
					if !x.OK {
						status = a.red("failed ")
					}
					fmt.Fprintf(a.out, "%s %s %s %s: %s -> %s\n", status, x.Vendor, x.Target, x.Change.Key, show(x.Change.Current), show(x.Change.Desired))
				}
				fmt.Fprintf(a.out, "apply record: %s by %s, ring %s (profile %s)\n", rec.Time.Format(time.RFC3339), rec.Actor, rec.Ring, rec.Profile)
			}); err != nil {
				return err
			}
			if failed != nil {
				return &exitErr{code: exitError, err: failed}
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
		Long: "Writes <out>/<vendor>/ with the artifacts an admin pastes into a console that has no write API (Claude managed " +
			"settings JSON, Codex requirements and config TOML, the Cursor model list) and a STEPS.md with the manual steps, " +
			"the read-only settings and every warning. Reads no console.",
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

// adminRecord is the audit record `halo admin apply` prints.
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

func (a *app) renderAdmin(rep *vendoradmin.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s ring %s (profile %s)\n", a.bold("vendor admin:"), rep.Ring, rep.Profile)
	for _, w := range rep.Warnings {
		fmt.Fprintf(&b, "  %s %s\n", a.yellow("warning"), w)
	}
	for _, p := range rep.Vendors {
		state := "manual (no API)"
		switch {
		case p.Error != "":
			state = a.red("unread: " + p.Error)
		case p.Read && len(p.Changes) == 0:
			state = a.green("in sync")
		case p.Read:
			state = a.yellow(fmt.Sprintf("%d drifted", len(p.Changes)))
		case p.HasAPI():
			state = "rendered (offline)"
		}
		fmt.Fprintf(&b, "\n%s %s: %s\n", a.bold(p.Vendor), p.Target, state)
		for _, s := range p.Desired {
			fmt.Fprintf(&b, "  %-48s %-22v %-6s from %s\n", s.Key, show(s.Value), s.Access, s.From)
		}
		for _, ch := range p.Changes {
			tag := "~"
			if ch.Loosens {
				tag = a.red("! loosens")
			}
			fmt.Fprintf(&b, "  %s %s: %s -> %s (%s)\n", tag, ch.Key, show(ch.Current), show(ch.Desired), ch.Access)
		}
		for _, art := range p.Artifacts {
			fmt.Fprintf(&b, "  artifact %s (halo admin export)\n", art.Name)
		}
		for _, w := range p.Warnings {
			fmt.Fprintf(&b, "  %s %s\n", a.yellow("warning"), w)
		}
	}
	return b.String()
}

// steps is the STEPS.md `halo admin export` writes for one vendor.
func steps(rep *vendoradmin.Report, p *vendoradmin.Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s console (%s)\n\nRendered by `halo admin export` from ring %s (profile %s). See ADR-0025.\n\n", p.Vendor, p.Target, rep.Ring, rep.Profile)
	if len(p.Manual) > 0 {
		b.WriteString("## Steps\n\n")
		for i, s := range p.Manual {
			fmt.Fprintf(&b, "%d. %s\n", i+1, s)
		}
		b.WriteString("\n")
	}
	if len(p.Desired) > 0 {
		b.WriteString("## Settings\n\n| Setting | Value | Access | From |\n|---|---|---|---|\n")
		for _, s := range p.Desired {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` |\n", s.Key, show(s.Value), s.Access, s.From)
		}
		b.WriteString("\n")
	}
	if ws := append(append([]string{}, rep.Warnings...), p.Warnings...); len(ws) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, w := range ws {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	return b.String()
}
