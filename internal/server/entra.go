package server

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
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// OIDC login hardening (ADR-0036): Entra ID groups overage and required
// authentication context (acr/amr).

// DefaultGraphURL is Microsoft Graph's v1.0 endpoint (Config.EntraGraphURL).
const DefaultGraphURL = "https://graph.microsoft.com/v1.0"

// graphScopes are added to the login when identity.groupsOverage is graph, so
// the access token can read the user's memberships.
var graphScopes = []string{"https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/GroupMember.Read.All"}

const (
	maxGraphBody   = 4 << 20
	maxGraphGroups = 20000 // getMemberObjects returns at most 11,000
	graphTimeout   = 10 * time.Second
)

// groupsOverage reports whether the ID token says the user's groups did not
// fit in it, as Entra ID does past 200 groups (150 in SAML): the groups claim
// is absent and either _claim_names points it elsewhere or hasgroups is true.
// The pointer itself (_claim_sources, an Azure AD Graph URL) is never followed.
func groupsOverage(claims map[string]any, groupsClaim string) bool {
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	if _, present := claims[groupsClaim]; present {
		return false
	}
	if names, ok := claims["_claim_names"].(map[string]any); ok {
		if _, ok := names[groupsClaim]; ok {
			return true
		}
	}
	has, _ := claims["hasgroups"].(bool)
	return has && groupsClaim == "groups"
}

func claimStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// checkAuthnContext enforces identity.requireAcr (the token's acr must be one
// of them) and identity.requireAmr (its amr must contain at least one of them).
func checkAuthnContext(claims map[string]any, id policy.Identity) error {
	if len(id.RequireAcr) > 0 {
		acr, _ := claims["acr"].(string)
		if !slices.Contains(id.RequireAcr, acr) {
			return fmt.Errorf("this sign-in does not meet the required authentication level (acr %q, required one of %s): sign in again with a stronger method such as MFA", acr, strings.Join(id.RequireAcr, ", "))
		}
	}
	if len(id.RequireAmr) > 0 {
		amr := claimStrings(claims["amr"])
		if !slices.ContainsFunc(id.RequireAmr, func(want string) bool { return slices.Contains(amr, want) }) {
			return fmt.Errorf("this sign-in did not use a required method (amr %v, required one of %s): sign in again with MFA", amr, strings.Join(id.RequireAmr, ", "))
		}
	}
	return nil
}

// checkGraphURL accepts https, or http to a loopback host (tests).
func checkGraphURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("server: Entra Graph URL %q is not an absolute URL", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("server: Entra Graph URL %q must be https (http only to loopback)", raw)
}

var errGraph = errors.New("microsoft graph")

// graphGroups resolves the signed-in user's group (and directory role) object
// ids with POST /me/getMemberObjects, using the login's access token: the same
// ids an Entra groups claim carries. Transitive memberships are included.
func (s *Server) graphGroups(ctx context.Context, accessToken string) ([]string, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("%w: the token response carried no access token", errGraph)
	}
	ctx, cancel := context.WithTimeout(ctx, graphTimeout)
	defer cancel()
	u := strings.TrimRight(s.graphURL, "/") + "/me/getMemberObjects"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader([]byte(`{"securityEnabledOnly":false}`)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errGraph, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	cl := &http.Client{Timeout: graphTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errGraph, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGraphBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %w", errGraph, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: getMemberObjects answered %d (grant the app User.Read and GroupMember.Read.All with admin consent)", errGraph, resp.StatusCode)
	}
	if len(body) > maxGraphBody {
		return nil, fmt.Errorf("%w: response over %d bytes", errGraph, maxGraphBody)
	}
	var out struct {
		Value    []string `json:"value"`
		NextLink string   `json:"@odata.nextLink"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", errGraph, err)
	}
	if out.NextLink != "" { // never silently drop a page: that would under-grant without saying so
		return nil, fmt.Errorf("%w: paged response (more groups than one page)", errGraph)
	}
	if len(out.Value) > maxGraphGroups {
		return nil, fmt.Errorf("%w: %d groups (over %d)", errGraph, len(out.Value), maxGraphGroups)
	}
	groups := make([]string, 0, len(out.Value))
	for _, g := range out.Value {
		if g == "" || len(g) > 256 {
			return nil, fmt.Errorf("%w: malformed object id", errGraph)
		}
		groups = append(groups, g)
	}
	return groups, nil
}
