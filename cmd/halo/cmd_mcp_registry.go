package main

import (
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
	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
)

// MCP registry and authorization (ADR-0029): import a server.json into a
// pinned halos.yaml mcp entry, and mint audience-bound tokens for servers
// whose authorization server is Halos.

const (
	officialMCPRegistry = "https://registry.modelcontextprotocol.io"
	maxServerJSON       = 1 << 20
	// Token types halo-server accepts as a Halos credential (internal/server).
	tokenTypeSessionURN = "urn:halos:params:oauth:token-type:session" //nolint:gosec // token type identifier, not a credential
)

func (a *app) cmdMCPRegistry() *cobra.Command {
	c := &cobra.Command{Use: "registry", Short: "The halos.yaml mcp registry of approved MCP servers (ADR-0029)"}
	var o policy.ImportOptions
	var base string
	var timeout time.Duration
	imp := &cobra.Command{
		Use:   "import <name|https-url|file>",
		Short: "Print a pinned halos.yaml mcp entry for a server from the official MCP Registry",
		Long: `Reads a server.json (the official MCP Registry format) and prints a
halos.yaml mcp.servers entry pinned to its exact version: the npm, pypi or oci
stdio package (oci needs --sha256), or with --remote the streamable-HTTP URL.

The argument is a local file, an https URL serving server.json, or a registry
name (io.github.owner/server), fetched read-only from --registry's
/v0/servers/<name>/versions/latest. Nothing is written: review the entry, set
rings/units, tools and auth, and add it to halos.yaml in a pull request.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			b, err := readServerJSON(ctx, registryClient(timeout), base, args[0])
			if err != nil {
				return err
			}
			s, notes, err := policy.ImportServerJSON(b, o)
			if err != nil {
				return err
			}
			return a.emit(map[string]any{"server": s, "notes": notes}, func() {
				y, _ := yaml.Marshal([]policy.RegistryServer{s}) // plain structs and strings: cannot fail
				fmt.Fprintln(a.out, "# add under mcp.servers in halos.yaml:")
				fmt.Fprint(a.out, string(y))
				for _, n := range notes {
					fmt.Fprintln(a.errw, a.yellow("note:"), n)
				}
			})
		},
	}
	imp.Flags().StringVar(&o.ID, "id", "", "registry id (default: derived from the server name)")
	imp.Flags().BoolVar(&o.Remote, "remote", false, "pin the remote streamable-HTTP endpoint instead of a package")
	imp.Flags().StringVar(&o.SHA256, "sha256", "", "image digest sha256:<hex> (required for an oci package)")
	imp.Flags().StringVar(&base, "registry", officialMCPRegistry, "MCP Registry base URL for a name argument")
	imp.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "fetch timeout")
	c.AddCommand(imp)
	return c
}

// registryClient fetches server.json. A redirect must stay on the same host
// and scheme (https, or http only on a loopback test host): a registry or URL
// cannot bounce the fetch to plain http or to another host.
func registryClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		orig := via[0].URL
		switch {
		case len(via) >= 5:
			return errors.New("too many redirects")
		case req.URL.Scheme != "https" && (req.URL.Scheme != orig.Scheme || !isLoopbackHost(req.URL.Hostname())):
			return fmt.Errorf("refusing redirect from %s to %s (https only)", orig.Scheme, req.URL.Scheme)
		case req.URL.Host != orig.Host:
			return fmt.Errorf("refusing redirect from %s to another host %s", orig.Host, req.URL.Host)
		}
		return nil
	}}
}

// readServerJSON reads arg as a file, an https URL, or a registry name.
func readServerJSON(ctx context.Context, hc *http.Client, base, arg string) ([]byte, error) {
	if fi, err := os.Stat(arg); err == nil && fi.Mode().IsRegular() {
		b, err := os.ReadFile(arg) //nolint:gosec // the operator names the file
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", arg, err)
		}
		return b, nil
	}
	u := arg
	if !strings.Contains(arg, "://") {
		u = strings.TrimRight(base, "/") + "/v0/servers/" + url.PathEscape(arg) + "/versions/latest"
	}
	p, err := url.Parse(u)
	if err != nil || p.Host == "" || (p.Scheme != "https" && (p.Scheme != "http" || !isLoopbackHost(p.Hostname()))) {
		return nil, fmt.Errorf("%q is not a file or an https URL", u)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer func() { _ = res.Body.Close() }() // read-only
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", u, res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxServerJSON+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	if len(b) > maxServerJSON {
		return nil, fmt.Errorf("fetch %s: server.json over %d bytes", u, maxServerJSON)
	}
	return b, nil
}

func (a *app) cmdMCPToken() *cobra.Command {
	var resource, srv, format string
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "token",
		Short: "Mint a short-lived token for one MCP server whose authorization server is Halos",
		Long: `Exchanges your Halos credential at halo-server POST /api/v1/token/exchange
(RFC 8693 with resource=<server URL>, RFC 8707) for a token only that server
accepts (aud = its URL, 5 minutes at most). The server must be in the
halos.yaml mcp registry with auth mode halos and enabled for your ring or unit.

The credential is HALO_SESSION (your halo_session cookie value) when set,
else HALO_GATEWAY_TOKEN holding a workload or delegated agent credential
(halo ci token, agent delegation). It is sent only to halo-server, never to
the MCP server.

--format headers (the default) prints {"Authorization": "Bearer ..."}, the
output Claude Code's headersHelper expects; token prints the bare token; json
the exchange response.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != "headers" && format != "token" && format != "json" {
				return fmt.Errorf("--format must be headers, token or json, got %q", format)
			}
			if _, ok := policy.CanonicalResource(resource); !ok {
				return fmt.Errorf("--resource %q must be an https URL without query or fragment", resource)
			}
			if srv == "" {
				srv = os.Getenv("HALO_SERVER")
			}
			form := url.Values{"grant_type": {ciGrantTokenExchange}, "resource": {resource}}
			switch {
			case os.Getenv("HALO_SESSION") != "":
				form.Set("subject_token", os.Getenv("HALO_SESSION"))
				form.Set("subject_token_type", tokenTypeSessionURN)
			case strings.TrimSpace(os.Getenv("HALO_GATEWAY_TOKEN")) != "":
				form.Set("subject_token", strings.TrimSpace(os.Getenv("HALO_GATEWAY_TOKEN")))
				form.Set("subject_token_type", ciTokenTypeJWT)
			default:
				return errors.New("no Halos credential: set HALO_SESSION (your halo_session cookie value) or HALO_GATEWAY_TOKEN (from halo ci token)")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			resp, err := postExchange(ctx, &http.Client{Timeout: timeout}, srv, form)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return a.emitJSON(resp)
			case "token":
				_, err = fmt.Fprintln(a.out, resp.AccessToken)
				return err
			}
			return json.NewEncoder(a.out).Encode(map[string]string{"Authorization": "Bearer " + resp.AccessToken})
		},
	}
	c.Flags().StringVar(&resource, "resource", "", "the MCP server's URL as the registry lists it (required)")
	c.Flags().StringVar(&srv, "server", "", "halo-server base URL (env HALO_SERVER); https unless loopback")
	c.Flags().StringVar(&format, "format", "headers", "headers | token | json")
	c.Flags().DurationVar(&timeout, "timeout", 15*time.Second, "exchange timeout")
	_ = c.MarkFlagRequired("resource")
	return c
}
