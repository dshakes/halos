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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/server"
)

// cmdAgentsRevoke revokes one agent or workload credential by jti, or every
// credential of a subject issued so far (ADR-0026), through halo-server's
// admin API with the session in HALO_SESSION, as for kill.
func (a *app) cmdAgentsRevoke() *cobra.Command {
	var srv, jti, subject, reason string
	c := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an agent or workload credential (--jti) or a subject's credentials (--subject) via halo-server (admin)",
		Long: "--jti kills one credential and every credential exchanged from it. --subject kills every credential issued so far " +
			"for an agent (agent:<name>, anywhere in a delegation chain), a workload (workload:...) or a human root (their id: " +
			"also ends their sessions). halo-server refuses revoked credentials at once on every replica; gateways with a " +
			"directory configured within 30s. New credentials for an agent or workload subject are refused for one minute (clock-skew pad).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (jti == "") == (subject == "") {
				return errors.New("give exactly one of --jti and --subject")
			}
			if strings.TrimSpace(reason) == "" {
				return errors.New("--reason is required (it is recorded in the audit log)")
			}
			session, err := adminSession(&srv)
			if err != nil {
				return err
			}
			var out server.Revocation
			if err := callServer(cmd.Context(), http.DefaultClient, srv, session, http.MethodPost, server.RevokeRequest{JTI: jti, Subject: subject, Reason: reason}, &out); err != nil {
				return fmt.Errorf("revoke: %w", err)
			}
			return a.emit(out, func() { fmt.Fprintln(a.out, revocationLine(out)) })
		},
	}
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (or HALO_SERVER)")
	c.Flags().StringVar(&jti, "jti", "", "the credential's jti (from the agent.token.exchange or workload.token.exchange audit entry)")
	c.Flags().StringVar(&subject, "subject", "", "agent:<name>, workload:<subject>, or a human user id")
	c.Flags().StringVar(&reason, "reason", "", "why; recorded in the audit log (required)")
	return c
}

// cmdAgentsRevocations lists the active revocations.
func (a *app) cmdAgentsRevocations() *cobra.Command {
	var srv string
	c := &cobra.Command{
		Use: "revocations", Short: "List active credential revocations (halo-server, admin)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			session, err := adminSession(&srv)
			if err != nil {
				return err
			}
			var out server.RevocationsResponse
			if err := callServer(cmd.Context(), http.DefaultClient, srv, session, http.MethodGet, nil, &out); err != nil {
				return fmt.Errorf("revocations: %w", err)
			}
			return a.emit(out, func() {
				if len(out.Revocations) == 0 {
					fmt.Fprintln(a.out, "no active revocations")
				}
				for _, r := range out.Revocations {
					fmt.Fprintln(a.out, revocationLine(r))
				}
			})
		},
	}
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (or HALO_SERVER)")
	return c
}

func revocationLine(r server.Revocation) string {
	what := "jti " + r.JTI
	if r.Subject != "" {
		what = fmt.Sprintf("subject %s (issued at or before %s)", r.Subject, r.RevokedBefore.Format(time.RFC3339))
	}
	return termSafe(fmt.Sprintf("%s  by %s at %s, until %s: %s", what, r.By, r.At.Format(time.RFC3339), r.Expires.Format(time.RFC3339), r.Reason))
}

// adminSession resolves --server (or HALO_SERVER) and the HALO_SESSION cookie value.
func adminSession(srv *string) (string, error) {
	if *srv == "" {
		*srv = os.Getenv("HALO_SERVER")
	}
	session := os.Getenv("HALO_SESSION")
	if *srv == "" || session == "" {
		return "", errors.New("set --server (or HALO_SERVER) and HALO_SESSION (an admin halo_session cookie value)")
	}
	return session, nil
}

// callServer sends body (JSON, nil for none) to /api/v1/revocations with the
// session cookie, over https or to loopback only, and decodes a 200 into out.
func callServer(ctx context.Context, hc *http.Client, srv, session, method string, body, out any) error {
	base, err := sessionServer(srv)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base.JoinPath("api", "v1", "revocations").String(), rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(&http.Cookie{Name: "halo_session", Value: session}) //nolint:gosec // outgoing request cookie; Secure/HttpOnly only apply to Set-Cookie
	cl := *hc
	cl.Timeout = 15 * time.Second
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server answered %d: %s", resp.StatusCode, termSafe(strings.TrimSpace(string(b))))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
