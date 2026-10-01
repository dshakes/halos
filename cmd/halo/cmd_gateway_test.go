package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/gateway/kong"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

func TestGatewayCompileAndDeck(t *testing.T) {
	org, err := policy.Load(example)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicy, err := policy.Compile(org)
	if err != nil {
		t.Fatal(err)
	}
	wantDeck, err := kong.Generate(org, kong.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pj, kj := filepath.Join(dir, "policy.json"), filepath.Join(dir, "kong.yml")
	for _, c := range [][]string{{"gateway", "compile", example, "-o", pj}, {"gateway", "deck", example, "-o", kj}} {
		if code, out, errs := halo(t, c...); code != 0 {
			t.Fatalf("%v: code %d\n%s%s", c, code, out, errs)
		}
	}
	for path, want := range map[string][]byte{pj: wantPolicy, kj: wantDeck} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from library output", filepath.Base(path))
		}
	}
	// stdout mode
	if _, out, _ := halo(t, "gateway", "compile", example); out != string(wantPolicy) {
		t.Error("stdout compile differs")
	}
	// invalid policy -> exit 2, no output file
	bad := copyDir(t, example)
	os.Remove(filepath.Join(bad, "gateway.yaml"))
	if code, _, _ := halo(t, "gateway", "deck", bad, "-o", filepath.Join(dir, "x.yml")); code == 0 {
		t.Error("deck without gateway should fail")
	}
}

func TestUpsertVerdict(t *testing.T) {
	p := filepath.Join(t.TempDir(), "verdicts.json")
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	other := `[{"experiment":"other","verdict":"continue","custom":1}]`
	if err := os.WriteFile(p, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsutil.RestrictToOwner(p); err != nil { // 0600 means nothing to Windows; UpsertVerdict must keep it private
		t.Fatal(err)
	}
	up := func(exp string, v promote.Verdict) {
		t.Helper()
		if err := promote.UpsertVerdict(p, exp, promote.Report{Verdict: v, NControl: 3}, at); err != nil {
			t.Fatal(err)
		}
	}
	read := func() []map[string]any {
		var rows []map[string]any
		b, _ := os.ReadFile(p)
		if err := json.Unmarshal(b, &rows); err != nil {
			t.Fatalf("%v\n%s", err, b)
		}
		return rows
	}
	up("e1", promote.Continue)
	up("e1", promote.Promote) // replace, not append
	rows := read()
	if len(rows) != 2 || rows[0]["custom"] != float64(1) {
		t.Fatalf("rows = %v", rows)
	}
	if rows[1]["experiment"] != "e1" || rows[1]["verdict"] != "promote" || rows[1]["nControl"] != float64(3) || rows[1]["evaluatedAt"] == nil {
		t.Fatalf("row = %v", rows[1])
	}
	// Windows has no POSIX mode bits (Perm() is always 0666); access is ACL-based.
	if err := fsutil.VerifyPrivate(p); err != nil {
		t.Errorf("verdicts file not private: %v", err)
	}
	// not an array -> error, file untouched
	os.WriteFile(p, []byte(`{"a":1}`), 0o644)
	if err := promote.UpsertVerdict(p, "e1", promote.Report{}, at); err == nil {
		t.Error("want error for non-array file")
	}
	if b, _ := os.ReadFile(p); string(b) != `{"a":1}` {
		t.Error("file modified on error")
	}
}

func TestGatewayDeckKillswitchFlag(t *testing.T) {
	const u = "https://halo.example.com/api/v1/gateway/killswitch"
	code, out, errs := halo(t, "gateway", "deck", example, "--killswitch-url", u)
	if code != 0 {
		t.Fatalf("code %d\n%s%s", code, out, errs)
	}
	for _, want := range []string{"killswitch_url: " + u, "{vault://env/halo-killswitch-token}", "{vault://env/halo-killswitch-pubkey}"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, _ := halo(t, "gateway", "deck", example, "--killswitch-url", "http://x/ks"); code == 0 {
		t.Error("http killswitch URL must fail")
	}
}

func TestGatewayRoutes(t *testing.T) {
	type table []struct {
		Alias      string `json:"alias"`
		Experiment string `json:"experiment"`
		Targets    []struct {
			Order    int    `json:"order"`
			Selected bool   `json:"selected"`
			Upstream string `json:"upstream"`
			Kind     string `json:"kind"`
		} `json:"targets"`
	}
	run := func(args ...string) table {
		t.Helper()
		code, out, errs := halo(t, append([]string{"gateway", "routes", "--policy-dir", example, "--output", "json"}, args...)...)
		if code != 0 {
			t.Fatalf("code %d\n%s%s", code, out, errs)
		}
		var tb table
		if err := json.Unmarshal([]byte(out), &tb); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return tb
	}
	pick := func(tb table, alias string) (ups []string, selected string) {
		for _, r := range tb {
			if r.Alias != alias {
				continue
			}
			for _, tg := range r.Targets {
				ups = append(ups, tg.Upstream)
				if tg.Selected {
					selected = tg.Upstream
				}
			}
		}
		return
	}

	tb := run("--user", "alice@acme.com", "--session", "s1")
	if ups, sel := pick(tb, "opus"); strings.Join(ups, ",") != "bedrock-use1,anthropic-direct" || sel != "bedrock-use1" {
		t.Errorf("opus targets %v selected %q", ups, sel)
	}
	// Both weighted targets of `default` are listed, in the order for this user/session.
	if ups, _ := pick(tb, "default"); len(ups) != 2 {
		t.Errorf("default targets %v", ups)
	}
	if _, sel := pick(tb, "sonnet"); sel != "orchestrator" {
		t.Errorf("single-target alias selected %q", sel)
	}

	code, out, errs := halo(t, "gateway", "routes", "--policy-dir", example, "--user", "alice@acme.com")
	if code != 0 || !strings.Contains(out, "bedrock-use1") || !strings.Contains(out, "<- hit when healthy") {
		t.Errorf("text output: code %d\n%s%s", code, out, errs)
	}
}

func TestGatewayDeckOptOutsWarn(t *testing.T) {
	code, out, errs := halo(t, "gateway", "deck", example)
	if code != 0 || strings.Contains(out, "allow_unverified") || strings.Contains(out, "forward_client_credentials") || strings.Contains(errs, "warning:") {
		t.Fatalf("secure defaults must emit nothing: code %d\n%s%s", code, out, errs)
	}
	code, out, errs = halo(t, "gateway", "deck", example, "--allow-unverified", "--forward-client-credentials")
	for _, want := range []string{"allow_unverified: true", "forward_client_credentials: true", "# WARNING: allow_unverified", "# WARNING: forward_client_credentials"} {
		if !strings.Contains(out, want) {
			t.Errorf("deck output missing %q", want)
		}
	}
	if code != 0 || strings.Count(errs, "warning:") != 2 {
		t.Errorf("code %d, stderr should carry two warnings:\n%s", code, errs)
	}
}
