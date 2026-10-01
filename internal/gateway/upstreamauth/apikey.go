package upstreamauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
)

// ErrNoSecret marks a credential-bearing upstream whose secret could not be
// read; callers fail the attempt (and may fail over), never forward unauthenticated.
var ErrNoSecret = errors.New("upstreamauth: provider credential unavailable")

// Secret reads the credential from its env var or file at use time (so
// rotation needs no restart). Policy only names the location.
func Secret(c *policy.Credential, getenv func(string) string) (string, error) {
	var v string
	switch {
	case c == nil:
		return "", ErrNoSecret
	case c.Env != "":
		v = getenv(c.Env)
	case c.File != "":
		b, err := os.ReadFile(c.File) //nolint:gosec // operator-supplied path is the point
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrNoSecret, err)
		}
		v = string(b)
	}
	if v = strings.TrimSpace(v); v == "" {
		return "", ErrNoSecret
	}
	return v, nil
}

// ClientCredentialHeaders are the headers a caller can use to present a
// credential. None of them is ever a gateway-to-provider credential: they are
// dropped before the gateway installs its own (or none).
var ClientCredentialHeaders = identity.ClientCredentialHeaders

// StripClientCredentials removes every ClientCredentialHeaders entry from h.
func StripClientCredentials(h http.Header) {
	for _, n := range ClientCredentialHeaders {
		h.Del(n)
	}
}

// SetAuth replaces the client's credentials on h with the provider's: Azure
// OpenAI takes api-key by default, OpenAI a bearer token; Credential.Scheme overrides.
func SetAuth(h http.Header, kind string, c *policy.Credential, secret string) {
	StripClientCredentials(h)
	scheme := c.Scheme
	if scheme == "" && kind == "azure-openai" {
		scheme = "api-key"
	}
	switch {
	case scheme == "bearer":
		h.Set("Authorization", "Bearer "+secret)
	case kind == "gemini":
		h.Set("X-Goog-Api-Key", secret)
	case scheme == "api-key":
		h.Set("api-key", secret)
	default:
		h.Set("Authorization", "Bearer "+secret)
	}
}

// SetBearer replaces the client's credentials on h with a bearer token.
func SetBearer(h http.Header, token string) {
	StripClientCredentials(h)
	h.Del("Anthropic-Version")
	h.Set("Authorization", "Bearer "+token)
}

// providerHosts are the hostname suffixes ("." prefix) or exact names that may
// receive each kind's credential.
var providerHosts = map[string][]string{
	"vertex":       {".googleapis.com"},
	"openai":       {"api.openai.com"},
	"gemini":       {"generativelanguage.googleapis.com"},
	"azure-openai": {".openai.azure.com", ".cognitiveservices.azure.com", ".services.ai.azure.com"},
}

// Credentialed reports whether halo-proxy attaches its own credential to
// requests for up (and so must restrict where they can go).
func Credentialed(up policy.Upstream) bool {
	return up.Kind == "vertex" || up.Kind == "azure-openai" || ((up.Kind == "openai" || up.Kind == "gemini") && up.Credential != nil)
}

// CheckURL is the SSRF guard for credentialed upstreams: https only (http only
// when insecure, the explicit in-cluster/test flag), no userinfo, and the host
// must be the provider's own domain or an exact entry of extra (operator
// allow list, e.g. a private endpoint). Other kinds are not checked here.
func CheckURL(up policy.Upstream, u *url.URL, extra []string, insecure bool) error {
	if !Credentialed(up) {
		return nil
	}
	if u.User != nil {
		return fmt.Errorf("upstream url must not carry userinfo")
	}
	if u.Scheme != "https" && (!insecure || u.Scheme != "http") {
		return fmt.Errorf("upstream %s must be https (set allowInsecureUpstreams only for in-cluster or test endpoints)", u.Redacted())
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, a := range extra {
		if strings.EqualFold(strings.TrimSuffix(a, "."), host) {
			return nil
		}
	}
	for _, p := range providerHosts[up.Kind] {
		if host == p || (strings.HasPrefix(p, ".") && strings.HasSuffix(host, p)) {
			return nil
		}
	}
	return fmt.Errorf("host %q is not a %s endpoint; add it to upstreamHosts if intended", host, up.Kind)
}
