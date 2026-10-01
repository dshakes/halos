package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/cmd/halo/scaffold"
	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // register adapters
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

func (a *app) cmdInit() *cobra.Command {
	var org string
	c := &cobra.Command{
		Use:         "init",
		Annotations: policyDirAnno,
		Short:       "Scaffold a minimal policy repo",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(dir, policy.RootFile)); err == nil {
				return fmt.Errorf("%s already exists in %s; refusing to overwrite", policy.RootFile, dir)
			}
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
		},
	}
	c.Flags().StringVar(&org, "org", "my-org", "organization name")
	return c
}

func (a *app) cmdValidate() *cobra.Command {
	return &cobra.Command{
		Use:         "validate",
		Annotations: policyDirAnno,
		Short:       "Load and validate a policy repo (exit 2 on errors)",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			return a.report(org.Validate())
		},
	}
}

func (a *app) cmdRender() *cobra.Command {
	var ring, osName, out, ver string
	c := &cobra.Command{
		Use:         "render",
		Annotations: policyDirAnno,
		Short:       "Render a ring's harness config files under --out, mirroring absolute paths",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch osName {
			case "darwin", "linux", "windows":
			default:
				return fmt.Errorf("--os must be darwin, linux or windows, got %q", osName)
			}
			dir, err := policyDir(cmd, args)
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
			rel, err := release.Build(org, r.Profile, ring, release.Options{Version: ver, OSes: []harness.OS{harness.OS(osName)}})
			if err != nil {
				return fmt.Errorf("render ring %s: %w", ring, err)
			}
			var written []string
			hs := make([]string, 0, len(rel.Manifest.Harnesses))
			for h := range rel.Manifest.Harnesses {
				hs = append(hs, h)
			}
			sort.Strings(hs)
			for _, h := range hs {
				for _, f := range rel.Manifest.Harnesses[h].Files[osName] {
					data, ok := rel.Content(f)
					if !ok {
						return fmt.Errorf("release is missing blob for %s", f.Path)
					}
					dst := safeJoin(out, f.Path)
					if err := writeFile(dst, data, os.FileMode(f.Mode)); err != nil {
						return fmt.Errorf("write %s: %w", dst, err)
					}
					written = append(written, dst)
				}
			}
			return a.emit(map[string]any{"files": written, "warnings": rel.Manifest.Warnings}, func() {
				for _, w := range written {
					fmt.Fprintln(a.out, a.green("write"), w)
				}
				for _, w := range rel.Manifest.Warnings {
					fmt.Fprintln(a.errw, a.yellow("warning:"), w)
				}
			})
		},
	}
	c.Flags().StringVar(&ring, "ring", "", "ring to render (required)")
	c.Flags().StringVar(&osName, "os", runtime.GOOS, "target OS: darwin|linux|windows")
	c.Flags().StringVar(&out, "out", "rendered", "output directory")
	c.Flags().StringVar(&ver, "release-version", "0.0.0-dev", "release version label stamped into config")
	_ = c.MarkFlagRequired("ring")
	return c
}

func (a *app) cmdWhoami() *cobra.Command {
	var user, groups string
	c := &cobra.Command{
		Use:         "whoami",
		Annotations: policyDirAnno,
		Short:       "Show the ring and experiment variants a user is assigned",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			sub := policy.Subject{ID: user}
			for _, g := range strings.Split(groups, ",") {
				if g = strings.TrimSpace(g); g != "" {
					sub.Groups = append(sub.Groups, g)
				}
			}
			type assignment struct {
				Experiment string `json:"experiment"`
				Variant    string `json:"variant"`
			}
			res := struct {
				User        string       `json:"user"`
				Groups      []string     `json:"groups"`
				Ring        string       `json:"ring"`
				Profile     string       `json:"profile"`
				Experiments []assignment `json:"experiments"`
			}{User: user, Groups: sub.Groups, Experiments: []assignment{}}
			ring := org.ResolveRing(sub)
			if ring != nil {
				res.Ring, res.Profile = ring.Name, ring.Profile
				for _, e := range org.Experiments {
					if e.Status != "running" {
						continue
					}
					if v := e.ResolveVariant(sub, ring.Name); v != nil {
						res.Experiments = append(res.Experiments, assignment{e.Name, v.Name})
					}
				}
			}
			return a.emit(res, func() {
				if ring == nil {
					fmt.Fprintf(a.out, "%s: no ring matches\n", user)
					return
				}
				fmt.Fprintf(a.out, "user     %s\nring     %s\nprofile  %s\n", user, a.bold(res.Ring), res.Profile)
				if len(res.Experiments) == 0 {
					fmt.Fprintln(a.out, "variants (none: no running experiment enrolls this user)")
				}
				for _, x := range res.Experiments {
					fmt.Fprintf(a.out, "variant  %s = %s\n", x.Experiment, x.Variant)
				}
			})
		},
	}
	c.Flags().StringVar(&user, "user", "", "user id (required)")
	c.Flags().StringVar(&groups, "groups", "", "comma-separated IdP groups")
	_ = c.MarkFlagRequired("user")
	return c
}

var allCaps = []harness.Capability{
	harness.CapVersionPin, harness.CapModelLock, harness.CapMCPAllowlist, harness.CapHooksLock,
	harness.CapPermissions, harness.CapGateway, harness.CapTelemetry, harness.CapInstructions, harness.CapHeaders,
}

func (a *app) cmdHarnesses() *cobra.Command {
	return &cobra.Command{
		Use:   "harnesses",
		Short: "Show the harness capability matrix",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			m := harness.Matrix()
			if len(m) == 0 {
				return errors.New("no harness adapters registered")
			}
			names := harness.Names()
			return a.emit(m, func() {
				tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
				fmt.Fprint(tw, "HARNESS")
				for _, c := range allCaps {
					fmt.Fprint(tw, "\t", c)
				}
				fmt.Fprintln(tw)
				for _, n := range names {
					have := map[harness.Capability]bool{}
					for _, c := range m[n] {
						have[c] = true
					}
					fmt.Fprint(tw, n)
					for _, c := range allCaps {
						mark := "-"
						if have[c] {
							mark = "yes"
						}
						fmt.Fprint(tw, "\t", mark)
					}
					fmt.Fprintln(tw)
				}
				tw.Flush()
			})
		},
	}
}
