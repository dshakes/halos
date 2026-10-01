package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/halos-dev/halos/internal/gateway/kong"
	"github.com/halos-dev/halos/internal/policy"
	"github.com/halos-dev/halos/internal/promote"
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
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", st.Mode())
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
