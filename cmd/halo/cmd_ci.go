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
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/server"
)

// Workload federation client (ADR-0023): a CI job trades its provider's OIDC
// token for a short-lived Halos gateway credential, never a provider API key.

const (
	ciGrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // RFC 8693 identifier, not a credential
	ciTokenTypeJWT       = "urn:ietf:params:oauth:token-type:jwt"            //nolint:gosec // RFC 8693 identifier, not a credential
	ciMaxResponse        = 64 << 10
)

func (a *app) cmdCI() *cobra.Command {
	c := &cobra.Command{
		Use:   "ci",
		Short: "Governed gateway credentials and config for headless CI / cloud agents",
	}
	c.AddCommand(a.cmdCIToken(), a.cmdCIConfig())
	return c
}

func (a *app) cmdCIToken() *cobra.Command {
	var srv, aud, tokenEnv, format string
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "token",
		Short: "Exchange this job's OIDC token for a short-lived gateway credential and export it for the harnesses",
		Long: `Reads the CI provider's OIDC token (GitHub Actions: requested from
ACTIONS_ID_TOKEN_REQUEST_URL, needs "permissions: id-token: write"; anything
else: the variable named by --token-env, e.g. a GitLab id_tokens entry),
exchanges it at halo-server POST /api/v1/token/exchange and exports the
gateway URL and credential for Claude Code, Codex and Gemini CLI.

--format github (default inside GitHub Actions) masks the credential with
::add-mask:: and appends the variables to $GITHUB_ENV; --format env prints
"export" lines for eval; --format json prints the exchange response.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format == "" {
				format = "env"
				if os.Getenv("GITHUB_ACTIONS") == "true" {
					format = "github"
				}
			}
			if format != "env" && format != "github" && format != "json" {
				return fmt.Errorf("--format must be env, github or json, got %q", format)
			}
			if srv == "" {
				srv = os.Getenv("HALO_SERVER")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			hc := &http.Client{Timeout: timeout}
			subject, err := ciSubjectToken(ctx, hc, os.Getenv, aud, tokenEnv)
			if err != nil {
				return err
			}
			resp, err := ciExchange(ctx, hc, srv, subject)
			if err != nil {
				return err
			}
			return a.ciExport(format, resp, os.Getenv("GITHUB_ENV"))
		},
	}
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (env HALO_SERVER); https unless loopback")
	c.Flags().StringVar(&aud, "audience", "halos", "audience to request for the GitHub Actions OIDC token (policy workloads.audience)")
	c.Flags().StringVar(&tokenEnv, "token-env", "HALO_ID_TOKEN", "variable holding the OIDC token on non-GitHub CI (GitLab id_tokens, Buildkite, CircleCI, cloud metadata)")
	c.Flags().StringVar(&format, "format", "", "env | github | json (default: github inside GitHub Actions, else env)")
	c.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "overall timeout for fetching and exchanging the token")
	return c
}

// ciSubjectToken returns the job's OIDC token: the --token-env variable when
// set, else GitHub Actions' token endpoint.
func ciSubjectToken(ctx context.Context, hc *http.Client, getenv func(string) string, aud, tokenEnv string) (string, error) {
	if t := strings.TrimSpace(getenv(tokenEnv)); t != "" {
		return t, nil
	}
	reqURL, reqTok := getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqTok == "" {
		return "", fmt.Errorf("no OIDC token: set %s (GitLab: an id_tokens entry with aud %q; Buildkite: buildkite-agent oidc request-token --audience %s; CircleCI: $CIRCLE_OIDC_TOKEN_V2), or on GitHub Actions grant \"permissions: id-token: write\"", tokenEnv, aud, aud)
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", aud)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("github oidc request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+reqTok)
	res, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("github oidc request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	var body struct {
		Value string `json:"value"`
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github oidc request: %s", res.Status)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, ciMaxResponse)).Decode(&body); err != nil || body.Value == "" {
		return "", fmt.Errorf("github oidc response has no token value: %v", err)
	}
	return body.Value, nil
}

func ciExchange(ctx context.Context, hc *http.Client, srv, subject string) (server.TokenExchangeResponse, error) {
	return postExchange(ctx, hc, srv, url.Values{"grant_type": {ciGrantTokenExchange}, "subject_token": {subject}, "subject_token_type": {ciTokenTypeJWT}})
}

// postExchange POSTs an RFC 8693 form to halo-server's token endpoint.
func postExchange(ctx context.Context, hc *http.Client, srv string, form url.Values) (server.TokenExchangeResponse, error) {
	var out server.TokenExchangeResponse
	if srv == "" {
		return out, errors.New("--server (or HALO_SERVER) is required")
	}
	u, err := url.Parse(strings.TrimRight(srv, "/") + "/api/v1/token/exchange")
	if err != nil || u.Host == "" {
		return out, fmt.Errorf("--server %q is not an absolute URL", srv)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())) {
		return out, fmt.Errorf("--server %q must be https (http only for loopback): the subject token is a credential", srv)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return out, fmt.Errorf("token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := hc.Do(req)
	if err != nil {
		return out, fmt.Errorf("token exchange: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, ciMaxResponse))
	if err != nil {
		return out, fmt.Errorf("token exchange: read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
			Desc  string `json:"error_description"`
		}
		_ = json.Unmarshal(b, &e)
		return out, fmt.Errorf("token exchange refused: %s: %s %s", res.Status, e.Error, e.Desc)
	}
	if err := json.Unmarshal(b, &out); err != nil || out.AccessToken == "" {
		return out, fmt.Errorf("token exchange: malformed response: %v", err)
	}
	return out, nil
}

func isLoopbackHost(h string) bool {
	ip := net.ParseIP(h)
	return h == "localhost" || (ip != nil && ip.IsLoopback())
}

// ciEnv maps the exchange to each harness's variables. OPENAI_BASE_URL gets
// /v1 like the Codex adapter's base_url.
func ciEnv(r server.TokenExchangeResponse) map[string]string {
	env := map[string]string{"HALO_GATEWAY_TOKEN": r.AccessToken, "HALO_SUBJECT": r.Subject, "HALO_RING": r.Ring,
		"ANTHROPIC_AUTH_TOKEN": r.AccessToken, "OPENAI_API_KEY": r.AccessToken, "GEMINI_API_KEY": r.AccessToken}
	if gw := strings.TrimRight(r.GatewayURL, "/"); gw != "" {
		env["ANTHROPIC_BASE_URL"], env["OPENAI_BASE_URL"], env["GOOGLE_GEMINI_BASE_URL"] = gw, gw+"/v1", gw
	}
	return env
}

func (a *app) ciExport(format string, r server.TokenExchangeResponse, githubEnv string) error {
	env := ciEnv(r)
	keys := make([]string, 0, len(env))
	for k, v := range env {
		if strings.ContainsAny(v, "\r\n") { // would inject extra variables into $GITHUB_ENV / the shell
			return fmt.Errorf("refusing to export %s: value contains a newline", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	summary := fmt.Sprintf("halo ci: credential for %s (ring %s, rule %s) valid %ds", r.Subject, orNone(r.Ring), r.Rule, r.ExpiresIn)
	switch format {
	case "json":
		return a.emitJSON(r)
	case "github":
		if githubEnv == "" {
			return errors.New("--format github needs $GITHUB_ENV (run inside a GitHub Actions step)")
		}
		fmt.Fprintf(a.out, "::add-mask::%s\n", r.AccessToken) // before the value can appear anywhere
		var b bytes.Buffer
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%s\n", k, env[k])
		}
		f, err := os.OpenFile(githubEnv, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // the runner-provided env file is the point
		if err != nil {
			return fmt.Errorf("open $GITHUB_ENV: %w", err)
		}
		if _, err := f.Write(b.Bytes()); err != nil {
			_ = f.Close()
			return fmt.Errorf("write $GITHUB_ENV: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("write $GITHUB_ENV: %w", err)
		}
		fmt.Fprintln(a.errw, summary)
		return nil
	}
	for _, k := range keys {
		fmt.Fprintf(a.out, "export %s=%s\n", k, shellQuote(env[k]))
	}
	fmt.Fprintln(a.errw, summary)
	return nil
}

func (a *app) emitJSON(v any) error {
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (a *app) cmdCIConfig() *cobra.Command {
	var h, ring, osName, out, ver string
	c := &cobra.Command{
		Use:         "config",
		Annotations: policyDirAnno,
		Short:       "Write one harness's managed config for a headless run from the ring's release",
		Long: `Renders the ring's release (the same bundle laptops get) and writes only
--harness's files under --out, mirroring absolute paths (use --out / as root
to install them where the harness reads managed settings). Nothing interactive
is added and no permission-bypass mode is ever written: in headless runs
(claude -p, codex exec, gemini -p) a tool the profile does not allow is denied,
so grant job-specific tools with the harness's own flag (claude --allowedTools)
within the profile's deny rules.`,
		Args: cobra.MaximumNArgs(1),
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
			if ring == "" {
				ring = os.Getenv("HALO_RING")
			}
			if ring == "" {
				return errors.New("--ring (or HALO_RING from `halo ci token`) is required")
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
			hm, ok := rel.Manifest.Harnesses[h]
			if !ok {
				return fmt.Errorf("profile %s of ring %s does not enable harness %q", r.Profile, ring, h)
			}
			written, err := writeCIFiles(rel, hm.Files[osName], out)
			if err != nil {
				return err
			}
			mode := ""
			if p, err := org.ResolveProfile(r.Profile); err == nil {
				mode = p.Permissions.Mode
			}
			return a.emit(map[string]any{"files": written, "permissionMode": mode, "warnings": rel.Manifest.Warnings}, func() {
				for _, w := range written {
					fmt.Fprintln(a.out, a.green("write"), w)
				}
				for _, w := range rel.Manifest.Warnings {
					fmt.Fprintln(a.errw, a.yellow("warning:"), w)
				}
				fmt.Fprintf(a.errw, "permission mode %q from profile %s: headless runs deny any tool the profile does not allow; add job tools with --allowedTools, never a bypass flag\n", orNone(mode), r.Profile)
			})
		},
	}
	c.Flags().StringVar(&h, "harness", "", "harness: claude-code | codex | gemini-cli | copilot-cli (required)")
	c.Flags().StringVar(&ring, "ring", "", "ring whose release to render (env HALO_RING, set by `halo ci token`)")
	c.Flags().StringVar(&osName, "os", runtime.GOOS, "target OS: darwin|linux|windows")
	c.Flags().StringVar(&out, "out", "", "output root (required; / installs in place)")
	c.Flags().StringVar(&ver, "release-version", "0.0.0-ci", "release version label stamped into config")
	_ = c.MarkFlagRequired("harness")
	_ = c.MarkFlagRequired("out")
	return c
}

func writeCIFiles(rel *release.Release, files []release.FileEntry, out string) ([]string, error) {
	var written []string
	for _, f := range files {
		data, ok := rel.Content(f)
		if !ok {
			return nil, fmt.Errorf("release is missing blob for %s", f.Path)
		}
		// invariant 1, re-checked at the last step before disk
		if tok := policy.BypassToken(string(data)); tok != "" {
			return nil, fmt.Errorf("refusing to write %s: it contains permission-bypass token %q (invariant 1)", f.Path, tok)
		}
		dst := safeJoin(out, f.Path)
		if err := writeFile(dst, data, os.FileMode(f.Mode)); err != nil {
			return nil, fmt.Errorf("write %s: %w", dst, err)
		}
		written = append(written, dst)
	}
	return written, nil
}
