package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/cloudagents"
	"github.com/dshakes/halos/internal/cloudagents/workflow"
	"github.com/dshakes/halos/internal/server"
	"github.com/dshakes/halos/internal/vendoradmin"
)

// cloudTokenEnv is the default variable holding a cloud agent API credential.
func cloudTokenEnv(v string) string { return "HALO_CLOUD_" + strings.ToUpper(v) + "_TOKEN" }

func (a *app) cmdCloudAgents() *cobra.Command {
	c := &cobra.Command{Use: "cloud-agents", Short: "Govern cloud and background coding agents: render workflows, list tasks, kill (ADR-0034)"}

	var out string
	render := &cobra.Command{
		Use: "render", Short: "Render the SHA-pinned, least-privilege workflow files of the repo-configured cloud agents",
		Long: "Renders .github/workflows/halos-claude.yml, halos-gemini.yml and copilot-setup-steps.yml from halos.yaml\n" +
			"cloudAgents, checked against the never-bypass invariant. Without --out it prints them. Commit them to the\n" +
			"repositories cloudAgents.<vendor>.repos names, by pull request. Console-configured vendors are in `halo admin plan`.",
		Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			org, err := a.loadValid(dir)
			if err != nil {
				return err
			}
			files, warns, err := workflow.Render(org)
			if err != nil {
				return err
			}
			if out != "" {
				for _, f := range files {
					p := filepath.Join(out, filepath.FromSlash(f.Path))
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						return err
					}
					if err := os.WriteFile(p, f.Data, 0o644); err != nil { //nolint:gosec // workflow files are public repository content
						return err
					}
				}
			}
			type rendered struct {
				workflow.File
				Content string `json:"content"`
			}
			res := struct {
				Files    []rendered `json:"files"`
				Warnings []string   `json:"warnings"`
			}{Files: []rendered{}, Warnings: warns}
			for _, f := range files {
				res.Files = append(res.Files, rendered{f, string(f.Data)})
			}
			return a.emit(res, func() {
				for _, f := range files {
					if out != "" {
						fmt.Fprintf(a.out, "%s %s (%s; for %s)\n", a.green("wrote"), filepath.Join(out, f.Path), f.Vendor, strings.Join(orAll(f.Repos), ", "))
						continue
					}
					fmt.Fprintf(a.out, "%s %s\n%s\n", a.bold("#"), f.Path, f.Data)
				}
				for _, w := range warns {
					fmt.Fprintf(a.out, "%s %s\n", a.yellow("warning"), vendoradmin.Sanitize(w))
				}
			})
		},
	}
	render.Flags().StringVar(&out, "out", "", "write the files under this directory (a repository checkout); default: print them")
	c.AddCommand(render)

	var sf serverFlags
	var cf adminFlags
	var since time.Duration
	var activeOnly bool
	var cursorUser string
	list := &cobra.Command{
		Use: "list", Short: "List active and recent cloud agent tasks with policy alerts",
		Long: "With --server (or HALO_SERVER) and HALO_SESSION: halo-server's inventory (webhooks and vendor APIs; read permission).\n" +
			"Otherwise reads the vendor APIs directly: GitHub Actions runs of the explicit cloudAgents repos and the\n" +
			"Cursor key's agents, with credentials from --<vendor>-token-file or HALO_CLOUD_<VENDOR>_TOKEN. Exit 2 when\n" +
			"any alert is raised, 1 when a vendor could not be read. Changes nothing.",
		Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			srv, session, err := sf.resolve()
			if err != nil {
				return err
			}
			var view server.CloudAgentsView
			var errs []string
			if srv != "" {
				path := "/api/v1/cloud-agents"
				if activeOnly {
					path += "?active=true"
				}
				if err := sessionJSON(cmd.Context(), srv, session, http.MethodGet, path, nil, &view); err != nil {
					return err
				}
			} else {
				dir, err := policyDir(cmd, nil)
				if err != nil {
					return err
				}
				org, err := a.loadValid(dir)
				if err != nil {
					return err
				}
				creds, err := cf.creds()
				if err != nil {
					return err
				}
				var cl cloudagents.Clients
				for _, v := range []struct {
					name string
					dst  **vendoradmin.Client
				}{{"github", &cl.GitHub}, {"cursor", &cl.Cursor}} {
					if creds[v.name].Token == "" {
						continue
					}
					if *v.dst, err = cloudagents.NewClient(v.name, creds[v.name].BaseURL, creds[v.name].Token); err != nil {
						return err
					}
				}
				if cl.GitHub == nil && cl.Cursor == nil {
					return errors.New("no credential: set HALO_CLOUD_GITHUB_TOKEN or HALO_CLOUD_CURSOR_TOKEN (or --<vendor>-token-file), or use --server")
				}
				cl.CursorUser = cursorUser
				tasks, warns, ferrs := cl.Fetch(cmd.Context(), org, time.Now().Add(-since))
				errs = ferrs
				for _, w := range warns {
					fmt.Fprintf(a.errw, "%s %s\n", a.yellow("warning"), vendoradmin.Sanitize(w))
				}
				view.Tasks = []cloudagents.Task{}
				for _, t := range tasks {
					if !activeOnly || t.Active() {
						view.Tasks = append(view.Tasks, t)
					}
				}
				view.Alerts = cloudagents.Evaluate(org, view.Tasks, nil, time.Now())
				view.Configured = map[string]bool{"github": cl.GitHub != nil, "cursor": cl.Cursor != nil}
			}
			if err := a.emit(view, func() { a.printCloud(view) }); err != nil {
				return err
			}
			if len(errs) > 0 {
				return &exitErr{code: exitError, err: errors.New(vendoradmin.Sanitize(strings.Join(errs, "; ")))}
			}
			if len(view.Alerts) > 0 {
				return &exitErr{code: exitValidation}
			}
			return nil
		},
	}
	sf.add(list, "for its inventory")
	cf.names, cf.envName = []string{"github", "cursor"}, cloudTokenEnv
	cf.add(list, false)
	list.Flags().DurationVar(&since, "since", 24*time.Hour, "direct reads: tasks created this recently (GitHub filters by day)")
	list.Flags().BoolVar(&activeOnly, "active", false, "only queued and running tasks")
	list.Flags().StringVar(&cursorUser, "cursor-user", "", "direct reads: Halos user the Cursor key belongs to")
	c.AddCommand(list)

	var ksf serverFlags
	var scope, name, reason string
	var execute bool
	kill := &cobra.Command{
		Use: "kill", Short: "Cancel the cloud tasks of a user, ring or experiment through halo-server (dry run unless --execute)",
		Long: "Plans, and with --execute sends, the vendor cancel call for every active cloud task of --scope user|ring|experiment\n" +
			"--name. halo-server resolves rings and experiments from the tasks' Halos identities (internal/assign), audits the\n" +
			"intent before any call and every result after, and needs the operate permission. Vendors without a cancel API get\n" +
			"a manual step. Nothing is ever resumed automatically.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(reason) == "" {
				return errors.New("--reason is required (recorded in the audit log)")
			}
			srv, session, err := ksf.resolve()
			if err != nil {
				return err
			}
			if srv == "" {
				return errors.New("set --server (or HALO_SERVER) and HALO_TOKEN or HALO_SESSION (an operator halo_session cookie value)")
			}
			dry := !execute
			var res server.CloudKillResponse
			if err := sessionJSON(cmd.Context(), srv, session, http.MethodPost, "/api/v1/cloud-agents/kill",
				server.CloudKillRequest{Scope: scope, Name: name, Reason: reason, DryRun: &dry}, &res); err != nil {
				return err
			}
			return a.emit(res, func() {
				tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "TASK\tVENDOR\tUSER\tCALL\tRESULT")
				for _, ac := range res.Actions {
					call := ac.Call
					if call == "" {
						call = "-"
					}
					result := ac.Result
					if ac.Error != "" {
						result += ": " + ac.Error
					}
					if ac.Manual != "" {
						result += " (" + ac.Manual + ")"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ac.Task.ID, ac.Task.Vendor, orDash(ac.Task.User), call, vendoradmin.Sanitize(result))
				}
				tw.Flush()
				if res.DryRun {
					fmt.Fprintln(a.out, a.yellow("dry run:"), "nothing was cancelled; re-run with --execute")
				}
				for _, s := range res.NextSteps {
					fmt.Fprintln(a.out, "next:", vendoradmin.Sanitize(s))
				}
			})
		},
	}
	kill.Flags().StringVar(&scope, "scope", "user", "user | ring | experiment")
	kill.Flags().StringVar(&name, "name", "", "the user id, ring or experiment")
	kill.Flags().StringVar(&reason, "reason", "", "why (required; recorded in the audit log)")
	kill.Flags().BoolVar(&execute, "execute", false, "send the cancel calls (default: plan only)")
	ksf.add(kill, "")
	c.AddCommand(kill)
	return c
}

func orAll(repos []string) []string {
	if len(repos) == 0 {
		return []string{"every repository"}
	}
	return repos
}

func (a *app) printCloud(v server.CloudAgentsView) {
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TASK\tVENDOR\tSTATUS\tUSER\tREPO\tSTARTED")
	for _, t := range v.Tasks {
		status := t.Status
		if t.Active() {
			status = a.yellow(status)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Vendor, status, orDash(t.User), orDash(t.Repo), t.Start.Format(time.RFC3339))
	}
	tw.Flush()
	if len(v.Tasks) == 0 {
		fmt.Fprintln(a.out, "(no cloud agent tasks)")
	}
	for _, al := range v.Alerts {
		fmt.Fprintf(a.out, "%s %s/%s: %s\n", a.red("alert"), al.Vendor, al.Kind, vendoradmin.Sanitize(al.Message))
	}
}
