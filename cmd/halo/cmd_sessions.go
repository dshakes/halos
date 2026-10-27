package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/ledger"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/server"
	"github.com/dshakes/halos/internal/vendoradmin"
)

// ledgerVendors take a credential; their default variables are
// HALO_SESSIONS_<VENDOR>_TOKEN, not the admin console ones (a read-only audit
// key and a console admin key are different credentials).
var ledgerVendors = []string{ledger.SourceAnthropic, ledger.SourceGitHub}

func ledgerTokenEnv(v string) string { return "HALO_SESSIONS_" + strings.ToUpper(v) + "_TOKEN" }

func (a *app) cmdSessions() *cobra.Command {
	c := &cobra.Command{Use: "sessions", Short: "Agent session ledger: one identity-linked record per agent session (ADR-0031)"}
	c.AddCommand(a.cmdSessionsImport(), a.cmdSessionsList(), a.cmdSessionsShow(), a.cmdSessionsExport())
	return c
}

// serverSession resolves --server/HALO_SERVER and HALO_SESSION.
func serverSession(srv string) (string, string, error) {
	if srv == "" {
		srv = os.Getenv("HALO_SERVER")
	}
	session := os.Getenv("HALO_SESSION")
	if srv == "" || session == "" {
		return "", "", errors.New("set --server (or HALO_SERVER) and HALO_SESSION (a halo_session cookie value; list/show/export need the audit role, import needs admin)")
	}
	return srv, session, nil
}

// sessionsCall sends one request to halo-server's ledger API and decodes the answer into out.
func sessionsCall(ctx context.Context, srv, session, method, path string, q url.Values, body, out any) error {
	base, err := sessionServer(srv)
	if err != nil {
		return err
	}
	u := base.JoinPath(strings.Split(strings.Trim(path, "/"), "/")...)
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "halo_session", Value: session}) //nolint:gosec // outgoing request cookie; Secure/HttpOnly only apply to Set-Cookie
	cl := http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("sessions: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sessions: %s %s: server answered %d: %s", method, path, resp.StatusCode, vendoradmin.Sanitize(strings.TrimSpace(string(b))))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("sessions: decode response: %w", err)
	}
	return nil
}

func (a *app) cmdSessionsImport() *cobra.Command {
	var (
		sources                 []string
		file, since, until      string
		chURL, chDB, chUser     string
		ghEnterprise, ghPhrase  string
		paths, saltFile, srv    string
		dryRun, writeClickHouse bool
		creds                   = adminFlags{names: ledgerVendors, envName: ledgerTokenEnv}
	)
	c := &cobra.Command{
		Use:   "import",
		Short: "Read sessions from evidence sources, normalize and redact them, and store them in halo-server's ledger",
		Long: "Reads agent sessions from each --source, merges records of the same session, applies the redaction policy " +
			"(no prompt text is ever read or stored; file paths and repositories are dropped by default, or HMAC-hashed with " +
			"--paths hash), and posts them to halo-server, which joins each to a Halos identity through its SCIM directory and " +
			"appends it to the hash-chained audit log (exported to SIEM like any audit entry). Sources: gateway (halo-proxy " +
			"GenAI spans in ClickHouse), otel (Claude Code OTel events in ClickHouse), anthropic (Compliance API), github " +
			"(enterprise audit log), jsonl (--file). Vendor credentials come from --<vendor>-token-file or the variable " +
			"--<vendor>-token-env names (default HALO_SESSIONS_<VENDOR>_TOKEN), never from a flag value, and are never printed. " +
			"--dry-run prints the normalized records and stores nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			now := time.Now().UTC()
			s, err := ledger.ParseTime(since, now)
			if err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			u, err := ledger.ParseTime(until, now)
			if err != nil {
				return fmt.Errorf("--until: %w", err)
			}
			if u.IsZero() {
				u = now
			}
			if !s.Before(u) {
				return errors.New("--since must be before --until")
			}
			pol := ledger.Redaction{Paths: paths}
			if saltFile != "" {
				if pol.Salt, err = os.ReadFile(saltFile); err != nil { //nolint:gosec // operator-supplied path is the point
					return fmt.Errorf("--hash-salt-file: %w", err)
				}
				pol.Salt = bytes.TrimSpace(pol.Salt)
			}
			var ch *promote.ClickHouse
			if chURL != "" {
				ch = &promote.ClickHouse{URL: chURL, Database: chDB, User: chUser, Password: os.Getenv("HALO_CLICKHOUSE_PASSWORD")}
			}
			var session string
			if !dryRun {
				if srv, session, err = serverSession(srv); err != nil {
					return err
				}
			}
			cr, err := creds.creds()
			if err != nil {
				return err
			}
			var srcs []ledger.Source
			for _, name := range sources {
				src, err := ledgerSource(name, ch, cr, file, ghEnterprise, ghPhrase, *creds.tokenEnv[ledger.SourceAnthropic], *creds.tokenEnv[ledger.SourceGitHub])
				if err != nil {
					return err
				}
				srcs = append(srcs, src)
			}
			if len(srcs) == 0 {
				return errors.New("name at least one --source: gateway, otel, anthropic, github or jsonl")
			}
			var raw []ledger.Record
			counts := map[string]int{}
			for _, src := range srcs {
				recs, err := src.Fetch(cmd.Context(), ledger.Window{Since: s, Until: u})
				if err != nil {
					return err
				}
				counts[src.Name()] = len(recs)
				raw = append(raw, recs...)
			}
			recs, err := ledger.Normalize(raw, pol)
			if err != nil {
				return fmt.Errorf("nothing stored: %w", err)
			}
			res := map[string]any{"sources": counts, "sessions": len(recs), "stored": 0, "dryRun": dryRun}
			if !dryRun && len(recs) > 0 {
				var stored []ledger.Record
				for i := 0; i < len(recs); i += 1000 {
					var out server.SessionsIngest
					if err := sessionsCall(cmd.Context(), srv, session, http.MethodPost, "/api/v1/sessions", nil, server.SessionsIngest{Records: recs[i:min(i+1000, len(recs))]}, &out); err != nil {
						return fmt.Errorf("%w (%d of %d sessions stored before this)", err, len(stored), len(recs))
					}
					stored = append(stored, out.Records...)
				}
				recs = stored
				res["stored"] = len(stored)
				if writeClickHouse {
					if ch == nil {
						return errors.New("--write-clickhouse needs --clickhouse")
					}
					if err := ledger.Insert(cmd.Context(), ch, stored, time.Now().UTC()); err != nil {
						return fmt.Errorf("stored in halo-server, ClickHouse copy failed (re-run to retry): %w", err)
					}
					res["clickhouse"] = len(stored)
				}
			}
			res["records"] = recs
			return a.emit(res, func() {
				for _, n := range sources {
					fmt.Fprintf(a.out, "%-10s %d sessions\n", n, counts[n])
				}
				a.printSessions(recs)
				switch {
				case dryRun:
					fmt.Fprintf(a.out, "%d sessions normalized; dry run, nothing stored\n", len(recs))
				default:
					fmt.Fprintf(a.out, "%s %d sessions in halo-server's ledger\n", a.green("stored"), res["stored"])
				}
			})
		},
	}
	f := c.Flags()
	f.StringSliceVar(&sources, "source", nil, "evidence source, repeatable: gateway, otel, anthropic, github, jsonl")
	f.StringVar(&file, "file", "", "JSONL file for --source jsonl (- for stdin)")
	f.StringVar(&since, "since", "24h", "window start: RFC 3339, a duration back (24h) or days (7d)")
	f.StringVar(&until, "until", "", "window end (default now)")
	f.StringVar(&chURL, "clickhouse", "", "ClickHouse HTTP URL for --source gateway|otel and --write-clickhouse (password from HALO_CLICKHOUSE_PASSWORD)")
	f.StringVar(&chDB, "database", "halo", "ClickHouse database holding otel_logs, otel_traces and halo_session_ledger")
	f.StringVar(&chUser, "clickhouse-user", "", "ClickHouse user")
	f.StringVar(&ghEnterprise, "github-enterprise", "", "GitHub enterprise slug for --source github")
	f.StringVar(&ghPhrase, "github-phrase", "", `audit log search phrase for --source github (default "action:agent_session"; the window is added)`)
	f.StringVar(&paths, "paths", ledger.PathsDrop, "file and repository redaction: drop (count only) or hash (HMAC-SHA256 with --hash-salt-file)")
	f.StringVar(&saltFile, "hash-salt-file", "", "file holding the HMAC salt for --paths hash (at least 16 bytes; keep it stable to compare across imports)")
	f.StringVar(&srv, "server", "", "halo-server base URL (or HALO_SERVER); the session cookie comes from HALO_SESSION")
	f.BoolVar(&dryRun, "dry-run", false, "print the normalized, redacted records; store nothing")
	f.BoolVar(&writeClickHouse, "write-clickhouse", false, "also copy the stored records into ClickHouse halo_session_ledger")
	creds.add(c, false)
	return c
}

// ledgerSource builds one evidence adapter.
func ledgerSource(name string, ch *promote.ClickHouse, cr map[string]vendoradmin.Cred, file, ghEnterprise, ghPhrase, anthropicEnv, githubEnv string) (ledger.Source, error) {
	needCH := func() error {
		if ch == nil {
			return fmt.Errorf("--source %s reads ClickHouse: set --clickhouse", name)
		}
		return nil
	}
	client := func(vendor, def, env string) (*vendoradmin.Client, error) {
		c := cr[vendor]
		if c.Token == "" {
			return nil, fmt.Errorf("--source %s: no credential: set %s or pass --%s-token-file", vendor, env, vendor)
		}
		if err := vendoradmin.CheckBaseURL(c.BaseURL); err != nil {
			return nil, fmt.Errorf("--%s-base-url: %w", vendor, err)
		}
		base := c.BaseURL
		if base == "" {
			base = def
		}
		return &vendoradmin.Client{Vendor: vendor, BaseURL: strings.TrimRight(base, "/"), Token: c.Token, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
	}
	switch name {
	case ledger.SourceGateway:
		return ledger.Gateway{CH: ch}, needCH()
	case ledger.SourceOTel:
		return ledger.ClaudeOTel{CH: ch}, needCH()
	case ledger.SourceAnthropic:
		c, err := client(name, ledger.AnthropicBaseURL, anthropicEnv)
		return ledger.Anthropic{Client: c}, err
	case ledger.SourceGitHub:
		if ghEnterprise == "" {
			return nil, errors.New("--source github needs --github-enterprise")
		}
		c, err := client(name, vendoradmin.GitHubBaseURL, githubEnv)
		return ledger.GitHubAudit{Client: c, Enterprise: ghEnterprise, Phrase: ghPhrase}, err
	case ledger.SourceJSONL:
		switch file {
		case "":
			return nil, errors.New("--source jsonl needs --file")
		case "-":
			return ledger.JSONL{R: os.Stdin}, nil
		}
		b, err := os.ReadFile(file) //nolint:gosec // operator-supplied path is the point
		if err != nil {
			return nil, fmt.Errorf("--file: %w", err)
		}
		return ledger.JSONL{R: bytes.NewReader(b)}, nil
	}
	return nil, fmt.Errorf("unknown --source %q (want gateway, otel, anthropic, github or jsonl)", name)
}

type sessionFilterFlags struct{ user, harness, ring, tool, since, until, srv string }

func (f *sessionFilterFlags) add(c *cobra.Command) {
	c.Flags().StringVar(&f.user, "user", "", "Halos identity, or the vendor identity of an unresolved session")
	c.Flags().StringVar(&f.harness, "harness", "", "harness, e.g. claude-code, copilot-agent")
	c.Flags().StringVar(&f.ring, "ring", "", "ring")
	c.Flags().StringVar(&f.tool, "tool", "", "tool or MCP server used")
	c.Flags().StringVar(&f.since, "since", "", "sessions started at or after: RFC 3339, a duration back (24h) or days (7d)")
	c.Flags().StringVar(&f.until, "until", "", "sessions started before")
	c.Flags().StringVar(&f.srv, "server", "", "halo-server base URL (or HALO_SERVER); the session cookie comes from HALO_SESSION (audit role)")
}

func (f *sessionFilterFlags) query(limit int) (url.Values, error) {
	q := url.Values{}
	for k, v := range map[string]string{"user": f.user, "harness": f.harness, "ring": f.ring, "tool": f.tool} {
		if v != "" {
			q.Set(k, v)
		}
	}
	now := time.Now().UTC()
	for k, v := range map[string]string{"since": f.since, "until": f.until} {
		t, err := ledger.ParseTime(v, now)
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", k, err)
		}
		if !t.IsZero() {
			q.Set(k, t.UTC().Format(time.RFC3339))
		}
	}
	q.Set("limit", fmt.Sprint(limit))
	return q, nil
}

func (a *app) listSessions(ctx context.Context, f *sessionFilterFlags, limit int) (server.SessionsResponse, error) {
	var out server.SessionsResponse
	srv, session, err := serverSession(f.srv)
	if err != nil {
		return out, err
	}
	q, err := f.query(limit)
	if err != nil {
		return out, err
	}
	err = sessionsCall(ctx, srv, session, http.MethodGet, "/api/v1/sessions", q, nil, &out)
	return out, err
}

// chainWarning tells the reader when the audit chain holding the ledger does not verify.
func (a *app) chainWarning(r server.SessionsResponse) {
	if !r.Verified {
		fmt.Fprintln(a.errw, a.red("warning:"), "the audit chain holding the ledger does not verify:", vendoradmin.Sanitize(r.VerifyError), "(run `halo audit verify`)")
	}
}

func (a *app) cmdSessionsList() *cobra.Command {
	var (
		f     sessionFilterFlags
		limit int
	)
	c := &cobra.Command{
		Use:   "list",
		Short: "List ledger sessions, newest first (halo-server, audit role)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.listSessions(cmd.Context(), &f, limit)
			if err != nil {
				return err
			}
			a.chainWarning(r)
			return a.emit(r, func() {
				recs := make([]ledger.Record, len(r.Sessions))
				for i, s := range r.Sessions {
					recs[i] = s.Record
				}
				a.printSessions(recs)
				fmt.Fprintf(a.out, "%d of %d sessions\n", len(r.Sessions), r.Total)
			})
		},
	}
	f.add(c)
	c.Flags().IntVar(&limit, "limit", 100, "at most this many sessions (1..5000)")
	return c
}

func (a *app) cmdSessionsShow() *cobra.Command {
	var srv string
	c := &cobra.Command{
		Use:   "show <id|session-id>",
		Short: "Show one ledger session with its audit chain position (halo-server, audit role)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			srv, session, err := serverSession(srv)
			if err != nil {
				return err
			}
			var r server.SessionsResponse
			if err := sessionsCall(cmd.Context(), srv, session, http.MethodGet, "/api/v1/sessions/"+url.PathEscape(args[0]), nil, nil, &r); err != nil {
				return err
			}
			a.chainWarning(r)
			return a.emit(r, func() {
				for _, s := range r.Sessions {
					b, _ := json.MarshalIndent(s, "", "  ") // plain struct: cannot fail
					fmt.Fprintln(a.out, vendoradmin.Sanitize(string(b)))
				}
			})
		},
	}
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (or HALO_SERVER); the session cookie comes from HALO_SESSION (audit role)")
	return c
}

func (a *app) cmdSessionsExport() *cobra.Command {
	var (
		f     sessionFilterFlags
		out   string
		limit int
	)
	c := &cobra.Command{
		Use:   "export",
		Short: "Export ledger sessions as JSONL, one stored record per line (halo-server, audit role)",
		Long: "Writes the matching sessions as JSONL (each line a record with its auditSeq and auditHash), newest first. " +
			"For continuous delivery to a SIEM use the audit export (ADR-0016): every ledger record is an audit entry " +
			"with action session.record. Exits 1 when the audit chain does not verify, after writing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.listSessions(cmd.Context(), &f, limit)
			if err != nil {
				return err
			}
			w := a.out
			if out != "" && out != "-" {
				fh, err := os.Create(out) //nolint:gosec // operator-supplied path is the point
				if err != nil {
					return err
				}
				defer func() { _ = fh.Close() }() // closed explicitly below on success
				w = fh
			}
			enc := json.NewEncoder(w)
			for _, s := range r.Sessions {
				if err := enc.Encode(s); err != nil {
					return err
				}
			}
			if c, ok := w.(io.Closer); ok && w != a.out {
				if err := c.Close(); err != nil {
					return err
				}
			}
			if r.Total > len(r.Sessions) {
				fmt.Fprintf(a.errw, "exported %d of %d matching sessions: narrow --since/--until or raise --limit\n", len(r.Sessions), r.Total)
			}
			if !r.Verified {
				a.chainWarning(r)
				return &exitErr{code: exitError}
			}
			return nil
		},
	}
	f.add(c)
	c.Flags().StringVar(&out, "out", "", "file to write (default stdout)")
	c.Flags().IntVar(&limit, "limit", 5000, "at most this many sessions (1..5000)")
	return c
}

// printSessions is the text table for import and list.
func (a *app) printSessions(recs []ledger.Record) {
	if len(recs) == 0 {
		return
	}
	fmt.Fprintf(a.out, "%-20s %-28s %-14s %-10s %-24s %6s %9s %8s %-9s %-6s %s\n", "START", "WHO", "HARNESS", "RING", "MODELS", "TOOLS", "TOKENS", "COST", "OUTCOME", "CONF", "SOURCES")
	for _, r := range recs {
		who := r.Who.User
		if who == "" {
			who = "?" + r.Who.VendorUser // unresolved: the vendor's identity
			if r.Who.VendorUser == "" {
				who = "unit:" + r.Who.Unit
			}
		}
		if len(r.Who.Agents) > 0 {
			who += " via " + strings.Join(r.Who.Agents, ">")
		}
		fmt.Fprintln(a.out, vendoradmin.Sanitize(fmt.Sprintf("%-20s %-28s %-14s %-10s %-24s %6d %9d %8.2f %-9s %-6s %s",
			r.Start.UTC().Format(time.RFC3339), who, r.Harness, r.Ring, strings.Join(r.Models, ","), len(r.Tools)+len(r.MCPServers),
			r.InputTokens+r.OutputTokens, r.CostUSD, r.Outcome, r.Confidence, strings.Join(r.Sources, ","))))
	}
}
