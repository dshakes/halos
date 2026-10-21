package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/server"
)

func (a *app) cmdBudget() *cobra.Command {
	c := &cobra.Command{Use: "budget", Short: "Gateway cost budgets: spend per user, group, ring and org"}
	c.AddCommand(a.cmdBudgetStatus())
	return c
}

// cmdBudgetStatus shows halo-server's live budget counters (ADR-0017). The
// session cookie value comes from HALO_SESSION, never a flag, as for kill.
func (a *app) cmdBudgetStatus() *cobra.Command {
	var srv, name, key string
	c := &cobra.Command{
		Use: "status", Short: "Show spend against each budget in its current window (halo-server, admin)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if srv == "" {
				srv = os.Getenv("HALO_SERVER")
			}
			session := os.Getenv("HALO_SESSION")
			if srv == "" || session == "" {
				return errors.New("set --server (or HALO_SERVER) and HALO_SESSION (an admin halo_session cookie value)")
			}
			res, err := getBudgets(cmd.Context(), http.DefaultClient, srv, session, name, key)
			if err != nil {
				return err
			}
			return a.emit(res, func() {
				if len(res.Budgets) == 0 {
					fmt.Fprintln(a.out, "no budget counters (no budgets in policy, or nothing spent yet)")
					return
				}
				fmt.Fprintf(a.out, "%-24s %-34s %-12s %-8s %-22s %-22s %6s  %s\n", "BUDGET", "KEY", "WINDOW", "ACTION", "SPENT", "LIMIT", "USED", "RESETS")
				for _, s := range res.Budgets {
					window := s.Window
					if s.Period != "" {
						window = "rolling " + s.Period
					}
					spent, limit := money(s.SpentUSD, s.LimitUSD, s.SpentTokens, s.LimitTokens)
					used := fmt.Sprintf("%.0f%%", 100*s.Utilization())
					switch {
					case s.Exceeded():
						used = a.red(used)
					case s.Alert() > 0:
						used = a.yellow(used)
					}
					fmt.Fprintf(a.out, "%-24s %-34s %-12s %-8s %-22s %-22s %6s  %s\n", s.Budget, s.Key, window, s.Action, spent, limit, used, s.ResetAt.UTC().Format(time.RFC3339))
				}
			})
		},
	}
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (or HALO_SERVER)")
	c.Flags().StringVar(&name, "budget", "", "only this budget")
	c.Flags().StringVar(&key, "key", "", "only this counter, e.g. user:alice@example.com, group:platform, ring:ring1 or org")
	return c
}

// money renders the limits a budget sets: USD, tokens or both.
func money(spentUSD, limitUSD float64, spentTok, limitTok int64) (spent, limit string) {
	var s, l []string
	if limitUSD > 0 || limitTok == 0 {
		s, l = append(s, fmt.Sprintf("$%.2f", spentUSD)), append(l, fmt.Sprintf("$%.2f", limitUSD))
	}
	if limitTok > 0 {
		s, l = append(s, fmt.Sprintf("%d tok", spentTok)), append(l, fmt.Sprintf("%d tok", limitTok))
	}
	return strings.Join(s, " / "), strings.Join(l, " / ")
}

func getBudgets(ctx context.Context, hc *http.Client, srv, session, name, key string) (server.BudgetsResponse, error) {
	var out server.BudgetsResponse
	base, err := sessionServer(srv)
	if err != nil {
		return out, err
	}
	u := base.JoinPath("api", "v1", "budgets")
	q := u.Query()
	if name != "" {
		q.Set("budget", name)
	}
	if key != "" {
		q.Set("key", key)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return out, fmt.Errorf("budget status: %w", err)
	}
	req.AddCookie(&http.Cookie{Name: "halo_session", Value: session}) //nolint:gosec // outgoing request cookie; Secure/HttpOnly only apply to Set-Cookie
	cl := *hc
	cl.Timeout = 15 * time.Second
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := cl.Do(req)
	if err != nil {
		return out, fmt.Errorf("budget status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return out, fmt.Errorf("budget status: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("budget status: server answered %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("budget status: decode response: %w", err)
	}
	return out, nil
}
