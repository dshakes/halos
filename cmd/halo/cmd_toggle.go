package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/toggle"
)

func (a *app) cmdToggle() *cobra.Command {
	c := &cobra.Command{Use: "toggle", Short: "Feature toggles: list, evaluate, kill, find stale"}
	c.AddCommand(a.cmdToggleList(), a.cmdToggleEval(), a.cmdToggleKill(), a.cmdToggleStale())
	return c
}

type toggleRow struct {
	Name    string `json:"name"`
	Axis    string `json:"axis"`
	Owner   string `json:"owner"`
	Default bool   `json:"default"`
	Rules   int    `json:"rules"`
	Expires string `json:"expires,omitempty"`
	Stale   bool   `json:"stale"`
}

func toggleRows(org *policy.Org) []toggleRow {
	rows := make([]toggleRow, 0, len(org.Toggles))
	now := time.Now()
	for _, t := range org.Toggles {
		rows = append(rows, toggleRow{t.Name, string(t.Axis), t.Owner, t.Default, len(t.Rules), t.Expires, t.Expired(now)})
	}
	return rows
}

func (a *app) cmdToggleList() *cobra.Command {
	return &cobra.Command{
		Use: "list", Annotations: policyDirAnno, Short: "List feature toggles", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			rows := toggleRows(org)
			return a.emit(map[string]any{"toggles": rows}, func() {
				for _, r := range rows {
					stale := ""
					if r.Stale {
						stale = a.yellow("  STALE")
					}
					fmt.Fprintf(a.out, "%-28s %-7s default=%-5t rules=%d owner=%s expires=%s%s\n", r.Name, r.Axis, r.Default, r.Rules, r.Owner, r.Expires, stale)
				}
				if len(rows) == 0 {
					fmt.Fprintln(a.out, "no toggles")
				}
			})
		},
	}
}

func (a *app) cmdToggleStale() *cobra.Command {
	return &cobra.Command{
		Use: "stale", Annotations: policyDirAnno, Short: "List toggles past their expiry date", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			stale := []toggleRow{}
			for _, r := range toggleRows(org) {
				if r.Stale {
					stale = append(stale, r)
				}
			}
			return a.emit(map[string]any{"stale": stale}, func() {
				for _, r := range stale {
					fmt.Fprintf(a.out, "%s  expired %s  owner %s\n", a.bold(r.Name), r.Expires, r.Owner)
				}
				if len(stale) == 0 {
					fmt.Fprintln(a.out, a.green("OK")+": no stale toggles")
				}
			})
		},
	}
}

func (a *app) cmdToggleEval() *cobra.Command {
	var user, ring, groups, killed string
	c := &cobra.Command{
		Use: "eval", Annotations: policyDirAnno, Short: "Show which toggles are on for a user, and why", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			org, err := a.load(dir)
			if err != nil {
				return err
			}
			sub := toggle.Subject{ID: user, Groups: splitList(groups), Ring: ring}
			if sub.Ring == "" { // same resolution as the gateway and the portal
				if r := org.ResolveRing(policy.Subject{ID: user, Groups: sub.Groups}); r != nil {
					sub.Ring = r.Name
				}
			} else if _, err := findRing(org, ring); err != nil {
				return err
			}
			ds := toggle.EvalAll(org, sub, splitList(killed))
			return a.emit(map[string]any{"subject": sub, "toggles": ds}, func() {
				fmt.Fprintf(a.out, "user %s  ring %s  groups %v\n", user, a.bold(sub.Ring), sub.Groups)
				for _, d := range ds {
					state := a.red("off")
					if d.On {
						state = a.green("on ")
					}
					fmt.Fprintf(a.out, "%s %-28s %s\n", state, d.Name, d.Why)
					for _, tr := range d.Trace {
						fmt.Fprintf(a.out, "      %s\n", tr)
					}
				}
				if len(ds) == 0 {
					fmt.Fprintln(a.out, "no toggles")
				}
			})
		},
	}
	c.Flags().StringVar(&user, "user", "", "user id (required)")
	c.Flags().StringVar(&ring, "ring", "", "ring (default: resolved from the user and groups)")
	c.Flags().StringVar(&groups, "groups", "", "comma-separated IdP groups")
	c.Flags().StringVar(&killed, "killed", "", "comma-separated toggle names to treat as killed")
	_ = c.MarkFlagRequired("user")
	return c
}

func splitList(s string) []string {
	var out []string
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

// cmdToggleKill trips (or with --unkill clears) halo-server's signed kill list
// for a toggle, through the same admin endpoint family and session auth as the
// experiment kill switch. The session cookie value comes from HALO_SESSION: it
// is a credential, so it is never taken from a flag (shell history) and is sent
// only over https or to a loopback host.
func (a *app) cmdToggleKill() *cobra.Command {
	var server, reason string
	var unkill bool
	c := &cobra.Command{
		Use: "kill <name>", Short: "Kill a toggle fleet-wide via halo-server (off everywhere at the next poll)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !unkill && strings.TrimSpace(reason) == "" {
				return errors.New("--reason is required to kill a toggle")
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
			res, err := postToggleKill(cmd.Context(), http.DefaultClient, server, session, args[0], verb, reason)
			if err != nil {
				return err
			}
			return a.emit(res, func() {
				fmt.Fprintf(a.out, "toggle %s: killed=%v changed=%v\n", args[0], res["killed"], res["changed"])
			})
		},
	}
	c.Flags().StringVar(&server, "server", "", "halo-server base URL (or HALO_SERVER)")
	c.Flags().StringVar(&reason, "reason", "", "why; recorded in the audit log (required to kill)")
	c.Flags().BoolVar(&unkill, "unkill", false, "clear the kill instead")
	return c
}

func postToggleKill(ctx context.Context, hc *http.Client, server, session, name, verb, reason string) (map[string]any, error) {
	base, err := url.Parse(server)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("invalid --server %q", server)
	}
	ip := net.ParseIP(base.Hostname())
	loopbackHTTP := base.Scheme == "http" && (base.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()))
	if base.Scheme != "https" && !loopbackHTTP {
		return nil, fmt.Errorf("--server must be https (or http on loopback): the session cookie would travel in clear")
	}
	body, err := json.Marshal(map[string]string{"reason": reason})
	if err != nil {
		return nil, err
	}
	u := base.JoinPath("api", "v1", "toggles", url.PathEscape(name), verb)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("toggle %s: %w", verb, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "halo_session", Value: session})
	cl := *hc
	cl.Timeout = 15 * time.Second
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("toggle %s: %w", verb, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("toggle %s: read response: %w", verb, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("toggle %s %q: server answered %d: %s", verb, name, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("toggle %s: decode response: %w", verb, err)
	}
	return out, nil
}
