package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/server"
)

// cmdServiceToken manages halo-server service-account API tokens (ADR-0036):
// the credential automation should use instead of a copied console cookie.
func (a *app) cmdServiceToken() *cobra.Command {
	c := &cobra.Command{
		Use:   "service-token",
		Short: "Create, list and revoke halo-server service-account API tokens (admin)",
		Long: "Service-account tokens are bearer credentials for automation (CI, `halo mcp serve`, scripts), bound to one halo-server role " +
			"and always expiring. Use them as HALO_TOKEN instead of copying a browser's halo_session cookie into HALO_SESSION. " +
			"Creating one needs an interactive admin session (HALO_SESSION): a token cannot mint tokens.",
	}
	c.AddCommand(a.cmdServiceTokenCreate(), a.cmdServiceTokenList(), a.cmdServiceTokenRevoke())
	return c
}

func (a *app) cmdServiceTokenCreate() *cobra.Command {
	var srv string
	var in server.CreateServiceTokenRequest
	var rings, units []string
	c := &cobra.Command{
		Use:   "create",
		Short: "Create a service-account token; it is printed once and never again",
		Long: "Prints the token once: store it in your secret manager right away and pass it to automation as HALO_TOKEN. " +
			"The role is one of " + strings.Join(server.Roles, ", ") + " and may not exceed your own; --ttl defaults to the server's maximum (90 days unless configured). " +
			"--scope-ring and --scope-unit bound the role to those rings and units (ADR-0037); the scope must be within your own admin grants. Without them the token is global.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if in.Name == "" || in.Role == "" {
				return errors.New("--name and --role are required")
			}
			if len(rings) > 0 || len(units) > 0 { // ADR-0037: absent is global
				b, err := json.Marshal(policy.RoleScope{Rings: rings, Units: units})
				if err != nil {
					return err
				}
				in.Scope = b
			}
			cred, err := adminSession(&srv)
			if err != nil {
				return err
			}
			var out server.CreateServiceTokenResponse
			if err := sessionJSON(cmd.Context(), srv, cred, http.MethodPost, "/api/v1/service-tokens", in, &out); err != nil {
				return fmt.Errorf("service-token create: %w", err)
			}
			return a.emit(out, func() {
				fmt.Fprintln(a.out, out.Token)
				fmt.Fprintln(a.errw, a.yellow("store this token now: it is not shown again."), "Use it as HALO_TOKEN.")
				fmt.Fprintln(a.errw, tokenLine(out.ServiceToken))
			})
		},
	}
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (or HALO_SERVER); credential from HALO_SESSION (an interactive admin session)")
	c.Flags().StringVar(&in.Name, "name", "", "service account name (lowercase), e.g. ci-killswitch")
	c.Flags().StringVar(&in.Role, "role", "", "halo-server role the token holds: "+strings.Join(server.Roles, ", "))
	c.Flags().StringVar(&in.TTL, "ttl", "", "lifetime as a duration, e.g. 720h (default and maximum: the server's --service-token-max-ttl)")
	c.Flags().StringVar(&in.Description, "description", "", "what the token is for")
	c.Flags().StringVar(&in.Owner, "owner", "", "the team or person accountable for it")
	c.Flags().StringSliceVar(&rings, "scope-ring", nil, "bound the role to these rings (repeatable or comma-separated)")
	c.Flags().StringSliceVar(&units, "scope-unit", nil, "bound the role to these units and their descendants (repeatable or comma-separated)")
	return c
}

func (a *app) cmdServiceTokenList() *cobra.Command {
	var srv string
	c := &cobra.Command{
		Use: "list", Short: "List service-account tokens (never their secrets)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cred, err := adminSession(&srv)
			if err != nil {
				return err
			}
			var out server.ServiceTokensResponse
			if err := sessionJSON(cmd.Context(), srv, cred, http.MethodGet, "/api/v1/service-tokens", nil, &out); err != nil {
				return fmt.Errorf("service-token list: %w", err)
			}
			return a.emit(out, func() {
				if len(out.Tokens) == 0 {
					fmt.Fprintln(a.out, "no service tokens")
					return
				}
				tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tNAME\tROLE\tSCOPE\tSTATUS\tEXPIRES\tOWNER\tCREATED BY")
				for _, t := range out.Tokens {
					fmt.Fprintln(tw, termSafe(strings.Join([]string{t.ID, t.Name, t.Role, t.Scope.String(), tokenStatus(t), t.ExpiresAt.Format(time.RFC3339), dash(t.Owner != "", t.Owner), t.CreatedBy}, "\t")))
				}
				_ = tw.Flush() // stdout
			})
		},
	}
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (or HALO_SERVER); credential from HALO_TOKEN or HALO_SESSION (admin)")
	return c
}

func (a *app) cmdServiceTokenRevoke() *cobra.Command {
	var srv, reason string
	c := &cobra.Command{
		Use: "revoke <id>", Short: "Revoke a service-account token at once, on every replica", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return errors.New("--reason is required (it is recorded in the audit log)")
			}
			cred, err := adminSession(&srv)
			if err != nil {
				return err
			}
			var out server.ServiceTokenInfo
			if err := sessionJSON(cmd.Context(), srv, cred, http.MethodPost, "/api/v1/service-tokens/"+url.PathEscape(args[0])+"/revoke", server.RevokeServiceTokenRequest{Reason: reason}, &out); err != nil {
				return fmt.Errorf("service-token revoke: %w", err)
			}
			return a.emit(out, func() { fmt.Fprintln(a.out, tokenLine(out)) })
		},
	}
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (or HALO_SERVER); credential from HALO_TOKEN or HALO_SESSION (admin)")
	c.Flags().StringVar(&reason, "reason", "", "why; recorded in the audit log (required)")
	return c
}

func tokenStatus(t server.ServiceTokenInfo) string {
	switch {
	case t.Revoked:
		return "revoked"
	case t.Expired:
		return "expired"
	}
	return "active"
}

func tokenLine(t server.ServiceTokenInfo) string {
	return termSafe(fmt.Sprintf("%s %s (%s, role %s over %s, %s until %s)", t.ID, t.Name, t.Principal, t.Role, t.Scope, tokenStatus(t), t.ExpiresAt.Format(time.RFC3339)))
}
