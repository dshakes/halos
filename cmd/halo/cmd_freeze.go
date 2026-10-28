package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/impact"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/server"
)

// serverFlags is the optional halo-server a command consults. The session
// cookie value is a credential: it comes from HALO_SESSION only.
type serverFlags struct{ url string }

func (f *serverFlags) add(c *cobra.Command, use string) {
	c.Flags().StringVar(&f.url, "server", "", "halo-server base URL (or HALO_SERVER) "+use+"; session from HALO_SESSION")
}

// resolve returns the server and session, both "" when neither is set.
func (f *serverFlags) resolve() (string, string, error) {
	srv := f.url
	if srv == "" {
		srv = os.Getenv("HALO_SERVER")
	}
	session := strings.TrimSpace(os.Getenv("HALO_SESSION"))
	if srv == "" && session == "" {
		return "", "", nil
	}
	if srv == "" || session == "" {
		return "", "", errors.New("set --server (or HALO_SERVER) and HALO_SESSION (a halo_session cookie value) together")
	}
	return srv, session, nil
}

// sessionJSON calls halo-server with the session cookie: in (nil = no body)
// as JSON, the 2xx answer decoded into out.
func sessionJSON(ctx context.Context, srv, session, method, path string, in, out any) error {
	base, err := sessionServer(srv)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base.String(), "/")+path, body)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "halo_session", Value: session}) //nolint:gosec // outgoing request cookie; Secure/HttpOnly only apply to Set-Cookie
	cl := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("halo-server %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("halo-server %s %s: read: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("halo-server %s %s: %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("halo-server %s %s: decode: %w", method, path, err)
	}
	return nil
}

// serverGovernance reads the incident freeze and, for r (nil = none), its
// step approvals and the caller's identity from halo-server. ok is false when
// no server is configured: policy windows only, and no approvals.
func serverGovernance(ctx context.Context, sf serverFlags, r *policy.Rollout) (g rollout.Governance, ok bool, err error) {
	srv, session, err := sf.resolve()
	if err != nil || srv == "" {
		return g, false, err
	}
	var fv server.FreezeView
	if err := sessionJSON(ctx, srv, session, http.MethodGet, "/api/v1/freeze", nil, &fv); err != nil {
		return g, false, err
	}
	g.Incident = fv.Incident
	if r == nil {
		return g, true, nil
	}
	var ra server.RolloutApprovals
	if err := sessionJSON(ctx, srv, session, http.MethodGet, "/api/v1/rollouts/"+r.Name+"/approvals", nil, &ra); err != nil {
		return g, false, err
	}
	var me struct {
		ID string `json:"id"`
	}
	if err := sessionJSON(ctx, srv, session, http.MethodGet, "/api/v1/me", nil, &me); err != nil {
		return g, false, err
	}
	g.Approvals, g.Requester = ra.Approvals, me.ID
	return g, true, nil
}

// freezeFor is the freeze covering target now: policy windows, plus the
// incident freeze when a server is configured.
func freezeFor(ctx context.Context, org *policy.Org, target policy.ChangeTarget, sf serverFlags, now time.Time) (policy.FreezeStatus, bool, error) {
	st := org.FreezeAt(now, target)
	g, ok, err := serverGovernance(ctx, sf, nil)
	if err != nil {
		return st, false, fmt.Errorf("read the incident freeze: %w", err)
	}
	if g.Incident != nil {
		st.AddIncident(g.Incident.By, g.Incident.Reason)
	}
	return st, ok, nil
}

func (a *app) cmdFreeze() *cobra.Command {
	c := &cobra.Command{Use: "freeze", Short: "Change freezes: policy windows and the incident freeze (ADR-0030); rollbacks are never frozen"}
	var sf serverFlags
	var reason string
	for _, on := range []bool{true, false} {
		verb, short := "on", "Set the incident freeze on halo-server: no rollout advances or promotions until lifted (admin)"
		if !on {
			verb, short = "off", "Lift the incident freeze on halo-server (admin)"
		}
		cmd := &cobra.Command{
			Use: verb, Short: short, Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if strings.TrimSpace(reason) == "" {
					return errors.New("--reason is required (recorded in the audit log)")
				}
				srv, session, err := sf.resolve()
				if err != nil {
					return err
				}
				if srv == "" {
					return errors.New("set --server (or HALO_SERVER) and HALO_SESSION (an admin halo_session cookie value)")
				}
				var res map[string]any
				if err := sessionJSON(cmd.Context(), srv, session, http.MethodPost, "/api/v1/freeze", map[string]any{"frozen": on, "reason": reason}, &res); err != nil {
					return err
				}
				return a.emit(res, func() {
					state := a.green("lifted")
					if on {
						state = a.red("on")
					}
					fmt.Fprintf(a.out, "incident freeze %s (changed=%v). Rollbacks and the kill switch stay allowed.\n", state, res["changed"])
				})
			},
		}
		cmd.Flags().StringVar(&reason, "reason", "", "why (required; recorded in the audit log)")
		sf.add(cmd, "")
		c.AddCommand(cmd)
	}

	var ring, at, branch string
	status := &cobra.Command{
		Use: "status", Short: "Show which rings are frozen now (or --at), why, and when each opens", Args: cobra.NoArgs, Annotations: policyDirAnno,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			rows, ok, err := a.freezeRows(cmd, sf, dir, ring, at)
			if err != nil {
				return err
			}
			return a.emit(rows, func() {
				tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "RING\tFROZEN\tNEXT OPEN\tWHY")
				for _, r := range rows {
					frozen, next, why := a.green("no"), "-", "-"
					if r.Status.Frozen {
						frozen, next, why = a.red("yes"), "until lifted", r.Status.String()
						if !r.Status.NextOpen.IsZero() {
							next = r.Status.NextOpen.Format(time.RFC3339)
						}
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Ring, frozen, next, why)
				}
				tw.Flush()
				if !ok {
					fmt.Fprintln(a.out, "(policy windows only: set --server and HALO_SESSION to include the incident freeze)")
				}
			})
		},
	}
	var event, base string
	check := &cobra.Command{
		Use: "check", Short: "Exit non-zero while a change to --ring (default: any ring) is frozen; rollbacks always pass (CI status check)", Args: cobra.NoArgs, Annotations: policyDirAnno,
		Long: "A required status check for policy-repo pull requests and the merge queue. With --event (the\n" +
			"GitHub event payload: pull_request or merge_group) or --base, freeze windows are read from the base\n" +
			"branch, never from the change itself, and the change is classified from its diff: one that only\n" +
			"pauses or aborts rollouts, pauses experiments, or moves rings back to a release they pointed at\n" +
			"before on the base branch is a rollback and always passes. Needs the base history (actions/checkout\n" +
			"fetch-depth: 0). Without either flag it checks the local policy's windows and exempts nothing.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if branch != "" {
				return errors.New("--branch is no longer trusted (a branch name proves nothing): pass --event \"$GITHUB_EVENT_PATH\" so the base branch's windows apply and rollbacks are recognised from the diff")
			}
			dir, err := policyDir(cmd, nil)
			if err != nil {
				return err
			}
			var ch *ciChange
			switch {
			case event != "" && base != "":
				return errors.New("set --event or --base, not both")
			case event != "":
				c, err := eventChange(event)
				if err != nil {
					return err
				}
				ch = &c
			case base != "":
				ch = &ciChange{base: base, from: base}
			}
			govDir := dir
			if ch != nil {
				d, cleanup, err := impact.CheckoutAt(cmd.Context(), dir, ch.base)
				if err != nil {
					return fmt.Errorf("freeze check: read the base branch's policy (fetch it: actions/checkout fetch-depth: 0): %w", err)
				}
				defer cleanup()
				govDir = d
			}
			rows, _, err := a.freezeRows(cmd, sf, govDir, ring, at)
			if err != nil {
				return err
			}
			var held []string
			for _, r := range rows {
				if r.Status.Frozen {
					held = append(held, r.Ring+": "+r.Status.String())
				}
			}
			if len(held) > 0 && ch != nil {
				top, err := promote.Run(cmd.Context(), dir, "git", "rev-parse", "--show-toplevel")
				if err != nil {
					return fmt.Errorf("freeze check: %w", err)
				}
				rb, why, err := rollbackDiff(cmd.Context(), strings.TrimSpace(string(top)), *ch)
				if err != nil {
					return err
				}
				if rb {
					return a.emit(map[string]any{"frozen": false, "rollback": true, "rings": rows}, func() {
						fmt.Fprintln(a.out, a.green("ok:"), "the change is a rollback: never frozen")
					})
				}
				held = append(held, "not a rollback: "+why)
			}
			if err := a.emit(map[string]any{"frozen": len(held) > 0, "rings": rows}, func() {
				if len(held) == 0 {
					fmt.Fprintln(a.out, a.green("ok:"), "no change freeze")
				}
			}); err != nil {
				return err
			}
			if len(held) > 0 {
				return &exitErr{code: exitError, err: errors.New(strings.Join(held, "\n"))}
			}
			return nil
		},
	}
	for _, cmd := range []*cobra.Command{status, check} {
		cmd.Flags().StringVar(&ring, "ring", "", "only this ring (default: every ring)")
		cmd.Flags().StringVar(&at, "at", "", "evaluate at this RFC 3339 time instead of now (planning; policy windows only)")
		sf.add(cmd, "to include the incident freeze")
		c.AddCommand(cmd)
	}
	check.Flags().StringVar(&event, "event", "", "GitHub event payload ($GITHUB_EVENT_PATH; pull_request or merge_group): windows from the base branch, rollbacks from the diff")
	check.Flags().StringVar(&base, "base", "", "git ref of the protected base branch (e.g. origin/main): windows from it, rollbacks from the diff against it")
	check.Flags().StringVar(&branch, "branch", "", "removed: use --event")
	_ = check.Flags().MarkHidden("branch")
	return c
}

type freezeRow struct {
	Ring   string              `json:"ring"`
	Status policy.FreezeStatus `json:"status"`
}

// freezeRows is each ring's freeze in the policy at dir (or only ring's). With
// --at the incident freeze is not consulted: it has no schedule.
func (a *app) freezeRows(cmd *cobra.Command, sf serverFlags, dir, ring, at string) ([]freezeRow, bool, error) {
	org, err := a.loadValid(dir)
	if err != nil {
		return nil, false, err
	}
	now, live := time.Now(), at == ""
	if !live {
		if now, err = time.Parse(time.RFC3339, at); err != nil {
			return nil, false, fmt.Errorf("--at: %w", err)
		}
	}
	var rings []string
	for _, r := range org.Rings {
		if ring == "" || r.Name == ring {
			rings = append(rings, r.Name)
		}
	}
	if ring != "" && !slices.Contains(rings, ring) {
		_, err := findRing(org, ring)
		return nil, false, err
	}
	var inc *policy.ActiveFreeze
	ok := false
	if live {
		g, srvOK, err := serverGovernance(cmd.Context(), sf, nil)
		if err != nil {
			return nil, false, fmt.Errorf("read the incident freeze: %w", err)
		}
		inc, ok = g.Incident, srvOK
	}
	rows := []freezeRow{}
	for _, r := range rings {
		st := org.FreezeAt(now, org.RingTarget(r))
		if inc != nil {
			st.AddIncident(inc.By, inc.Reason)
		}
		rows = append(rows, freezeRow{Ring: r, Status: st})
	}
	return rows, ok, nil
}
