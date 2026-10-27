package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/server"
)

func TestCISubjectTokenSources(t *testing.T) {
	var gotAuth, gotAud string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotAud = r.Header.Get("Authorization"), r.URL.Query().Get("audience")
		if r.URL.Query().Get("api-version") != "2.0" {
			http.Error(w, "existing query dropped", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "gh.oidc.jwt"})
	}))
	defer gh.Close()
	envOf := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	ctx := context.Background()

	tok, err := ciSubjectToken(ctx, gh.Client(), envOf(map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL": gh.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-tok"}), "halos", "HALO_ID_TOKEN")
	if err != nil || tok != "gh.oidc.jwt" || gotAuth != "bearer req-tok" || gotAud != "halos" {
		t.Fatalf("github: %q %v auth=%q aud=%q", tok, err, gotAuth, gotAud)
	}
	// --token-env (GitLab id_tokens etc.) wins over GitHub's endpoint.
	tok, err = ciSubjectToken(ctx, gh.Client(), envOf(map[string]string{"HALO_ID_TOKEN": " gl.jwt\n",
		"ACTIONS_ID_TOKEN_REQUEST_URL": gh.URL, "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "x"}), "halos", "HALO_ID_TOKEN")
	if err != nil || tok != "gl.jwt" {
		t.Fatalf("token env: %q %v", tok, err)
	}
	if _, err := ciSubjectToken(ctx, gh.Client(), envOf(nil), "halos", "HALO_ID_TOKEN"); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Fatalf("no source: %v", err)
	}
}

func TestCIExchangeAndExport(t *testing.T) {
	var form map[string][]string
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		if r.PostForm.Get("subject_token") == "denied" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"no workloads rule matches"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(server.TokenExchangeResponse{AccessToken: "halo.workload.tok", TokenType: "Bearer", ExpiresIn: 900,
			Subject: "workload:gh:acme/app", Ring: "ring0", Rule: "main", GatewayURL: "https://gw.acme.example/"})
	}))
	defer hs.Close()
	ctx := context.Background()
	resp, err := ciExchange(ctx, hs.Client(), hs.URL, "ci.jwt")
	if err != nil || resp.AccessToken != "halo.workload.tok" {
		t.Fatalf("exchange: %+v %v", resp, err)
	}
	if form["grant_type"][0] != ciGrantTokenExchange || form["subject_token"][0] != "ci.jwt" || form["subject_token_type"][0] != ciTokenTypeJWT {
		t.Fatalf("request form %v", form)
	}
	if _, err := ciExchange(ctx, hs.Client(), hs.URL, "denied"); err == nil || !strings.Contains(err.Error(), "no workloads rule") {
		t.Fatalf("refusal not surfaced: %v", err)
	}
	if _, err := ciExchange(ctx, hs.Client(), "http://halo.example", "x"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http to a remote server allowed: %v", err)
	}

	// github: masked first, variables appended to $GITHUB_ENV, value never printed otherwise.
	var out, errb bytes.Buffer
	a := &app{out: &out, errw: &errb}
	ghEnv := filepath.Join(t.TempDir(), "github_env")
	if err := os.WriteFile(ghEnv, []byte("EXISTING=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.ciExport("github", resp, ghEnv); err != nil {
		t.Fatal(err)
	}
	if out.String() != "::add-mask::halo.workload.tok\n" || strings.Contains(errb.String(), "halo.workload.tok") {
		t.Fatalf("stdout %q stderr %q", out.String(), errb.String())
	}
	b, _ := os.ReadFile(ghEnv)
	for _, want := range []string{"EXISTING=1\n", "ANTHROPIC_BASE_URL=https://gw.acme.example\n", "ANTHROPIC_AUTH_TOKEN=halo.workload.tok\n",
		"OPENAI_BASE_URL=https://gw.acme.example/v1\n", "HALO_GATEWAY_TOKEN=halo.workload.tok\n", "GEMINI_API_KEY=halo.workload.tok\n",
		"GOOGLE_GEMINI_BASE_URL=https://gw.acme.example\n", "HALO_RING=ring0\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("$GITHUB_ENV lacks %q:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), "ANTHROPIC_API_KEY") {
		t.Error("exported a provider API key variable")
	}
	if err := a.ciExport("github", resp, ""); err == nil {
		t.Error("github format without $GITHUB_ENV")
	}

	out.Reset()
	if err := a.ciExport("env", server.TokenExchangeResponse{AccessToken: "it's", Subject: "workload:x"}, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `export ANTHROPIC_AUTH_TOKEN='it'\''s'`) {
		t.Fatalf("env not shell-quoted: %s", out.String())
	}
	if err := a.ciExport("env", server.TokenExchangeResponse{AccessToken: "x", GatewayURL: "https://gw\nEVIL=1"}, ""); err == nil {
		t.Fatal("newline in a value accepted (env injection)")
	}
}

func TestCIConfigWritesOneHarness(t *testing.T) {
	dir := buildable(t)
	out := t.TempDir()
	code, stdout, errs := halo(t, "ci", "config", "--policy-dir", dir, "--harness", "claude-code", "--ring", "ring3-ga", "--os", "linux", "--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(stdout, "managed-settings.json") || !strings.Contains(errs, "--allowedTools") {
		t.Fatalf("stdout %q stderr %q", stdout, errs)
	}
	err := filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if tok := policy.BypassToken(string(b)); tok != "" {
			t.Errorf("%s contains %s", p, tok)
		}
		if strings.Contains(p, "codex") || strings.Contains(p, "gemini") {
			t.Errorf("wrote another harness's file %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errs := halo(t, "ci", "config", "--policy-dir", dir, "--harness", "nope", "--ring", "ring3-ga", "--out", out); code == 0 || !strings.Contains(errs, "does not enable harness") {
		t.Fatalf("unknown harness: %d %s", code, errs)
	}
	if code, _, _ := halo(t, "ci", "config", "--policy-dir", dir, "--harness", "claude-code", "--ring", "", "--out", out); code == 0 {
		t.Fatal("missing ring accepted")
	}
}
