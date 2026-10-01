package upstreamauth

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func TestCheckURL(t *testing.T) {
	vertex := policy.Upstream{Kind: "vertex"}
	azure := policy.Upstream{Kind: "azure-openai"}
	oai := policy.Upstream{Kind: "openai", Credential: &policy.Credential{Env: "K"}}
	for _, tc := range []struct {
		name     string
		up       policy.Upstream
		url      string
		extra    []string
		insecure bool
		ok       bool
	}{
		{"vertex regional", vertex, "https://us-east5-aiplatform.googleapis.com", nil, false, true},
		{"vertex global", vertex, "https://aiplatform.googleapis.com", nil, false, true},
		{"vertex foreign host", vertex, "https://evil.example.com", nil, false, false},
		{"vertex suffix trick", vertex, "https://aiplatform.googleapis.com.evil.example", nil, false, false},
		{"vertex lookalike", vertex, "https://notgoogleapis.com", nil, false, false},
		{"vertex http refused", vertex, "http://us-east5-aiplatform.googleapis.com", nil, false, false},
		{"azure resource", azure, "https://acme.openai.azure.com", nil, false, true},
		{"azure foreign", azure, "https://acme.openai.azure.com.evil.io", nil, false, false},
		{"openai direct", oai, "https://api.openai.com", nil, false, true},
		{"openai foreign", oai, "https://api.openai.com.evil.io", nil, false, false},
		{"userinfo", oai, "https://u:p@api.openai.com", nil, false, false},
		{"operator allowlist", azure, "https://pe.internal.corp", []string{"pe.internal.corp"}, false, true},
		{"in-cluster http needs the flag", azure, "http://pe.internal.corp:8080", []string{"pe.internal.corp"}, false, false},
		{"in-cluster http with the flag", azure, "http://pe.internal.corp:8080", []string{"pe.internal.corp"}, true, true},
		{"flag does not widen hosts", azure, "http://evil.example", nil, true, false},
		{"uncredentialed openai unrestricted", policy.Upstream{Kind: "openai"}, "http://llm.internal", nil, false, true},
		{"anthropic unrestricted", policy.Upstream{Kind: "anthropic"}, "http://127.0.0.1:9", nil, false, true},
	} {
		u, _ := url.Parse(tc.url)
		if err := CheckURL(tc.up, u, tc.extra, tc.insecure); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestSetAuth(t *testing.T) {
	for _, tc := range []struct {
		name, kind, scheme string
		wantH, wantV       string
	}{
		{"azure default api-key", "azure-openai", "", "Api-Key", "s3cret"},
		{"azure bearer", "azure-openai", "bearer", "Authorization", "Bearer s3cret"},
		{"openai default bearer", "openai", "", "Authorization", "Bearer s3cret"},
		{"openai api-key", "openai", "api-key", "Api-Key", "s3cret"},
	} {
		h := http.Header{"Authorization": {"Bearer client-idp-token"}, "X-Api-Key": {"client"}, "Api-Key": {"client"}}
		SetAuth(h, tc.kind, &policy.Credential{Scheme: tc.scheme}, "s3cret")
		if h.Get(tc.wantH) != tc.wantV {
			t.Errorf("%s: %s=%q, want %q", tc.name, tc.wantH, h.Get(tc.wantH), tc.wantV)
		}
		other := map[string]string{"Api-Key": "Authorization", "Authorization": "Api-Key"}[tc.wantH]
		if h.Get(other) != "" || h.Get("X-Api-Key") != "" {
			t.Errorf("%s: client credentials survived: %v", tc.name, h)
		}
	}
}

func TestSecret(t *testing.T) {
	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte(" file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string { return map[string]string{"K": "env-secret", "EMPTY": "  "}[k] }
	for name, c := range map[string]struct {
		cred *policy.Credential
		want string
	}{
		"env": {&policy.Credential{Env: "K"}, "env-secret"}, "file": {&policy.Credential{File: f}, "file-secret"},
		"unset env": {&policy.Credential{Env: "NOPE"}, ""}, "blank env": {&policy.Credential{Env: "EMPTY"}, ""},
		"missing file": {&policy.Credential{File: f + ".gone"}, ""}, "nil": {nil, ""},
	} {
		got, err := Secret(c.cred, env)
		if c.want == "" && !errors.Is(err, ErrNoSecret) || got != c.want {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
}

func TestClientCredentialsNeverSurviveAuthSetters(t *testing.T) {
	all := func() http.Header {
		h := http.Header{}
		for _, n := range ClientCredentialHeaders {
			h.Set(n, "client")
		}
		return h
	}
	check := func(name string, h http.Header, keep string) {
		for _, n := range ClientCredentialHeaders {
			if v := h.Get(n); v != "" && http.CanonicalHeaderKey(n) != http.CanonicalHeaderKey(keep) {
				t.Errorf("%s: %s=%q survived", name, n, v)
			}
		}
		if keep != "" && (h.Get(keep) == "" || h.Get(keep) == "client") {
			t.Errorf("%s: %s=%q is not the gateway credential", name, keep, h.Get(keep))
		}
	}
	h := all()
	StripClientCredentials(h)
	check("strip", h, "")
	h = all()
	SetBearer(h, "tok")
	check("SetBearer", h, "Authorization")
	h = all()
	SetAuth(h, "azure-openai", &policy.Credential{}, "k")
	check("SetAuth api-key", h, "Api-Key")
	h = all()
	SetAuth(h, "openai", &policy.Credential{}, "k")
	check("SetAuth bearer", h, "Authorization")
}
