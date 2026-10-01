package kong

import (
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files")

func org() *policy.Org {
	return &policy.Org{Gateway: &policy.Gateway{
		Auth: policy.GatewayAuth{IdentityHeader: "x-acme-user"},
		Models: map[string]policy.ModelRoute{
			"sonnet": {Upstream: "orch", Model: "us.anthropic.claude-sonnet-4-5"},
			"haiku":  {Upstream: "orch", Model: "us.anthropic.claude-haiku-4-5"},
			"opus":   {Upstream: "anthropic", Model: "claude-opus-4-1"},
		},
		Upstreams: map[string]policy.Upstream{
			"orch":      {URL: "https://orchestrator.internal:8443", Kind: "orchestrator"},
			"anthropic": {URL: "https://api.anthropic.com", Kind: "anthropic"},
		},
	}}
}

func TestGenerateGolden(t *testing.T) {
	checkGolden(t, "testdata/kong.golden.yml", Options{PolicyPath: "/etc/halos/policy.json", GroupsHeader: "x-acme-groups", ShadowURL: "http://halo-shadow:8090/mirror"})
}

func TestGenerateKillswitchGolden(t *testing.T) {
	checkGolden(t, "testdata/kong-killswitch.golden.yml", Options{PolicyPath: "/etc/halos/policy.json", KillswitchURL: "https://halo.example.com/api/v1/gateway/killswitch"})
}

func TestKillswitchURLMustBeHTTPS(t *testing.T) {
	if _, err := Generate(org(), Options{KillswitchURL: "http://halo/ks"}); err == nil {
		t.Error("http killswitch URL must be refused")
	}
	if _, err := Generate(org(), Options{KillswitchURL: "http://halo/ks", AllowHTTP: true}); err != nil {
		t.Errorf("http allowed with AllowHTTP: %v", err)
	}
	if _, err := Generate(org(), Options{KillswitchURL: "ftp://halo/ks", AllowHTTP: true}); err == nil {
		t.Error("non-http(s) scheme must be refused")
	}
}

func TestOptOutAndInsecureKillswitchOptions(t *testing.T) {
	b, err := Generate(org(), Options{PolicyPath: "/p.json", AllowUnverified: true, ForwardClientCredentials: true,
		KillswitchURL: "http://halo-server:8080/api/v1/gateway/killswitch", KillswitchAllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"allow_unverified: true", "forward_client_credentials: true", "# WARNING: allow_unverified", "# WARNING: forward_client_credentials", "killswitch_allow_insecure_in_cluster: true", "killswitch_url: http://halo-server:8080/"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in:\n%s", want, b)
		}
	}
	// The insecure allowance never admits other schemes, and is off by default.
	if _, err := Generate(org(), Options{KillswitchURL: "ftp://halo/ks", KillswitchAllowInsecure: true}); err == nil {
		t.Error("ftp must be refused")
	}
	if b, _ := Generate(org(), Options{PolicyPath: "/p.json"}); strings.Contains(string(b), "allow_unverified") || strings.Contains(string(b), "forward_client") || strings.Contains(string(b), "WARNING") || strings.Contains(string(b), "insecure") {
		t.Error("options must default off")
	}
}

func checkGolden(t *testing.T, golden string, o Options) {
	t.Helper()
	got, err := Generate(org(), o)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("golden mismatch (run with -update):\n%s", got)
	}
}

func TestGenerateErrors(t *testing.T) {
	if _, err := Generate(nil, Options{}); err == nil {
		t.Error("nil org")
	}
	o := org()
	o.Gateway.Auth.IdentityHeader = ""
	if _, err := Generate(o, Options{}); err == nil {
		t.Error("missing identity header")
	}
	if _, err := Generate(org(), Options{ShadowURL: "http://halo-shadow:8090/mirror", ShadowToken: "plaintext"}); err == nil {
		t.Error("plaintext halo-shadow token must be refused")
	}
}

func TestGenerateHTTPAndVault(t *testing.T) {
	b, err := Generate(org(), Options{ShadowURL: "http://s/mirror", ShadowToken: "{vault://aws/halo/token}", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, "- http\n") || !strings.Contains(s, "{vault://aws/halo/token}") {
		t.Fatalf("got:\n%s", s)
	}
}

// Kong regex routes (implicitly anchored at the start) must admit exactly the
// model calls halo-kong knows, and nothing else under those prefixes.
func TestRoutesExact(t *testing.T) {
	match := func(p string) bool {
		for _, r := range routes {
			if regexp.MustCompile("^" + strings.TrimPrefix(r.path, "~")).MatchString(p) {
				return true
			}
		}
		return false
	}
	for p, want := range map[string]bool{
		"/v1/messages": true, "/v1/messages/count_tokens": true, "/v1/responses": true, "/v1/models": true,
		"/model/sonnet/invoke": true, "/model/us.anthropic.x%3A0/invoke-with-response-stream": true,
		"/v1/messages/batches": false, "/v1/messages/": false, "/v1/messagesx": false, "/v1/responses/compact": false,
		"/model/a/b/invoke": false, "/model/sonnet/invoke/x": false, "/x/v1/messages": false,
	} {
		if got := match(p); got != want {
			t.Errorf("%s: routed=%v want %v", p, got, want)
		}
	}
}
