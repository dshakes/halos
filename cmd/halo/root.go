package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// Set via -ldflags by goreleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Exit codes: 0 ok, 1 error, 2 validation issues.
const (
	exitError      = 1
	exitValidation = 2
)

// exitErr carries a specific exit code. A nil-message error means the output
// was already printed.
type exitErr struct {
	code int
	err  error
}

func (e *exitErr) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}
func (e *exitErr) Unwrap() error { return e.err }

type app struct {
	out, errw io.Writer
	json      bool
	color     bool
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (a *app) paint(code, s string) string {
	if !a.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (a *app) red(s string) string    { return a.paint("31", s) }
func (a *app) green(s string) string  { return a.paint("32", s) }
func (a *app) yellow(s string) string { return a.paint("33", s) }
func (a *app) bold(s string) string   { return a.paint("1", s) }

// emit writes v as indented JSON in --output json mode, else runs text.
func (a *app) emit(v any, text func()) error {
	if a.json {
		enc := json.NewEncoder(a.out)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	text()
	return nil
}

func newRoot(out, errw io.Writer) *cobra.Command {
	a := &app{out: out, errw: errw, color: isTTY(out) && os.Getenv("NO_COLOR") == ""}
	var output string
	root := &cobra.Command{
		Use:           "halo",
		Short:         "Halos: versioned, ring-deployed AI dev-tool configuration",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			switch output {
			case "text":
			case "json":
				a.json = true
			default:
				return fmt.Errorf("--output must be text or json, got %q", output)
			}
			return nil
		},
	}
	root.SetOut(out)
	root.SetErr(errw)
	root.PersistentFlags().StringVar(&output, "output", "text", "output format: text|json")
	root.AddCommand(a.cmdInit(), a.cmdValidate(), a.cmdRender(), a.cmdPlan(), a.cmdRelease(),
		a.cmdRollback(), a.cmdKeys(), a.cmdWhoami(), a.cmdHarnesses(), a.cmdExport(),
		a.cmdExp(), a.cmdController(), a.cmdGateway(), a.cmdTelemetry(), a.cmdEval(), a.cmdUpgrade(), a.cmdMCP(), a.cmdToggle(), a.cmdRollout(), a.cmdVersion(), a.cmdDocs(),
		a.cmdModel(), a.cmdEnable(), a.cmdKill(), a.cmdStatus(), a.cmdExplain(), a.cmdEject(), a.cmdMigrate(),
		a.cmdDoctor(), a.cmdOnboard(), a.cmdQuickstart())
	addPolicyDirFlags(root)
	return root
}

// run executes halo and returns the process exit code.
func run(ctx context.Context, args []string, out, errw io.Writer) int {
	root := newRoot(out, errw)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var ee *exitErr
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintln(errw, "error:", ee.err)
		}
		return ee.code
	}
	fmt.Fprintln(errw, "error:", err)
	return exitError
}

func (a *app) load(dir string) (*policy.Org, error) {
	org, err := policy.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("load policy %s: %w", dir, err)
	}
	return org, nil
}

type issueJSON struct {
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

// report prints issues and returns an exit-2 error when any is an error.
func (a *app) report(issues []policy.Issue) error {
	errs, warns := 0, 0
	js := make([]issueJSON, 0, len(issues))
	for _, i := range issues {
		js = append(js, issueJSON{string(i.Severity), i.Path, i.Message})
		if i.Severity == policy.SeverityError {
			errs++
		} else {
			warns++
		}
	}
	if err := a.emit(map[string]any{"ok": errs == 0, "errors": errs, "warnings": warns, "issues": js}, func() {
		for _, i := range issues {
			sev := a.yellow(fmt.Sprintf("%-7s", i.Severity))
			if i.Severity == policy.SeverityError {
				sev = a.red(fmt.Sprintf("%-7s", i.Severity))
			}
			fmt.Fprintf(a.out, "%s %s  %s\n", sev, a.bold(i.Path), i.Message)
		}
		if errs == 0 {
			fmt.Fprintln(a.out, a.green("OK")+fmt.Sprintf(": policy valid (%d warnings)", warns))
		} else {
			fmt.Fprintf(a.out, "%d errors, %d warnings\n", errs, warns)
		}
	}); err != nil {
		return err
	}
	if errs > 0 {
		return &exitErr{code: exitValidation}
	}
	return nil
}

// loadValid loads dir and refuses to proceed (exit 2) when validation fails.
func (a *app) loadValid(dir string) (*policy.Org, error) {
	org, err := a.load(dir)
	if err != nil {
		return nil, err
	}
	issues := org.Validate()
	if policy.HasErrors(issues) {
		// always human-readable on stderr so JSON stdout stays clean
		for _, i := range issues {
			fmt.Fprintln(a.errw, i.String())
		}
		return nil, &exitErr{code: exitValidation, err: errors.New("policy has validation errors; run `halo validate`")}
	}
	return org, nil
}

func findRing(org *policy.Org, name string) (*policy.Ring, error) {
	var names []string
	for _, r := range org.Rings {
		if r.Name == name {
			return r, nil
		}
		names = append(names, r.Name)
	}
	return nil, fmt.Errorf("unknown ring %q (have: %s)", name, strings.Join(names, ", "))
}

func (a *app) buildRelease(dir, ring, ver string) (*release.Release, error) {
	rel, _, err := a.buildRing(dir, ring, ver)
	return rel, err
}

// buildRing builds ring's release plus the variant releases of the running
// client-axis experiments enrolling it (see release.BuildRing).
func (a *app) buildRing(dir, ring, ver string) (*release.Release, []*release.Release, error) {
	org, err := a.loadValid(dir)
	if err != nil {
		return nil, nil, err
	}
	if _, err := findRing(org, ring); err != nil {
		return nil, nil, err
	}
	rel, variants, err := release.BuildRing(org, ring, release.Options{Version: ver, Org: org.Name})
	if err != nil {
		return nil, nil, fmt.Errorf("build release for ring %s: %w", ring, err)
	}
	return rel, variants, nil
}

// refusePinned stops publish from moving a ring that policy pins to another
// release (ADR-0002): a pinned ring follows Ring.release, so re-point it with
// `halo rollback --to <version> --expect-digest <pin>` or clear the pin; it never builds from Profile.
func (a *app) refusePinned(dir, ring, digest string) error {
	org, err := a.load(dir)
	if err != nil {
		return err
	}
	r, err := findRing(org, ring)
	if err != nil {
		return err
	}
	if r.Release != "" && r.Release != digest {
		return fmt.Errorf("ring %s is pinned to release %s in policy; publishing a build from profile %s would bypass the pin. Re-point with `halo rollback --ring %s --to <version> --expect-digest %s` or remove `release:` from the ring", ring, r.Release, r.Profile, ring, r.Release)
	}
	return nil
}

// safeJoin joins a (possibly absolute, possibly Windows) path under out,
// neutralising drive letters and "..".
func safeJoin(out, p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) > 1 && p[1] == ':' {
		p = p[2:]
	}
	return filepath.Join(out, filepath.FromSlash(path.Clean("/"+p)))
}

func writeFile(p string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o644
	}
	return os.WriteFile(p, data, mode)
}

func (a *app) cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the halo version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return a.emit(map[string]string{"version": version, "commit": commit, "date": date}, func() {
				fmt.Fprintf(a.out, "halo %s (commit %s, built %s)\n", version, commit, date)
			})
		},
	}
}

// policyDirAnno marks commands that read a policy repo; newRoot gives them
// --policy-dir (canonical) plus the deprecated --dir alias.
var policyDirAnno = map[string]string{"policyDir": "true"}

func addPolicyDirFlags(c *cobra.Command) {
	for _, sub := range c.Commands() {
		addPolicyDirFlags(sub)
	}
	if c.Annotations["policyDir"] != "true" {
		return
	}
	c.Flags().String("policy-dir", "", `policy repo directory (default ".")`)
	c.Flags().String("dir", "", "policy repo directory")
	_ = c.Flags().MarkDeprecated("dir", "use --policy-dir")
	c.Flags().SetOutput(c.ErrOrStderr()) // deprecation notice goes to halo's stderr
}

// policyDir resolves --policy-dir, the deprecated --dir, or the deprecated
// positional [dir] (default "."). Giving two different ones is an error.
func policyDir(c *cobra.Command, args []string) (string, error) {
	var got []string
	for _, n := range []string{"policy-dir", "dir"} {
		if f := c.Flags().Lookup(n); f != nil && f.Changed {
			got = append(got, f.Value.String())
		}
	}
	if len(args) > 0 {
		got = append(got, args[0])
	}
	if len(got) == 0 {
		return ".", nil
	}
	for _, g := range got[1:] {
		if filepath.Clean(g) != filepath.Clean(got[0]) {
			return "", fmt.Errorf("policy dir given twice (%q and %q); use --policy-dir", got[0], g)
		}
	}
	return got[0], nil
}
