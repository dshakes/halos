//go:build uat

package uat

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testEval runs `halo eval run` with the real claude and codex drivers in the
// DockerRunner (evals/images, the pinned versions) against the mock upstream.
// The mock solves uat-pass for both CLIs; uat-fail never for codex and on every
// other attempt for claude, so the control arm is flaky on it by construction.
func testEval(t *testing.T, e *cliEnv) {
	const h = "eval"
	pins := map[string]string{"claude": e.pins["claude-code"], "codex": e.pins["codex"]}
	for n, v := range pins {
		if out, err := cliDocker("build", "-q", "--label=halos-uat-clis="+e.id, "--build-arg", "CLI_VERSION="+v,
			"-t", "ghcr.io/dshakes/eval-"+n+":"+v, filepath.Join(e.root, "evals/images", n)); err != nil {
			t.Fatalf("eval image %s:%s: %v: %s", n, v, err, out)
		}
	}
	// Codex's workspace-write sandbox is Landlock. Probe it the way the
	// DockerRunner isolates a trial; UAT_REQUIRE_LANDLOCK=1 (CI on a Linux
	// runner) turns the no-Landlock known gaps into failures.
	requireLandlock := os.Getenv("UAT_REQUIRE_LANDLOCK") == "1"
	landlockGap := func(missing bool) string {
		if !missing || requireLandlock {
			return ""
		}
		return "no Landlock on this Docker kernel; the DockerRunner reports codex trials as unmeasurable (sandbox unavailable) instead of failing them"
	}
	probe, perr := cliDocker("run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512", "--memory=4g", "--cpus=2",
		"--user=1000:1000", "--network", "none", "ghcr.io/dshakes/eval-codex:"+pins["codex"], "codex", "sandbox", "linux", "--full-auto", "true")
	check(t, h, "codex sandbox probe under the runner's isolation exits 0", perr == nil,
		fmt.Sprintf("err=%v %q; kernel %s", perr, tail(probe, 2), strings.TrimSpace(kernel())), landlockGap(strings.Contains(probe, "LandlockRestrict")))
	halo := filepath.Join(e.dir, "halo-host")
	if out, err := exec.Command("go", "build", "-o", halo, filepath.Join(e.root, "cmd/halo")).CombinedOutput(); err != nil {
		t.Fatalf("build halo: %v: %s", err, out)
	}
	es := filepath.Join(e.dir, "evals")
	files := map[string]string{
		"tasks/uat-pass/task.yaml":   "id: uat-pass\nrepo: repo\nprompt: \"UAT-TASK-PASS: write 42 to answer.txt\"\ncheck: test \"$(cat answer.txt 2>/dev/null)\" = 42\ntimeout: 5m\nmax_turns: 5\n",
		"tasks/uat-fail/task.yaml":   "id: uat-fail\nrepo: repo\nprompt: \"UAT-TASK-FAIL: write 42 to answer.txt\"\ncheck: test \"$(cat answer.txt 2>/dev/null)\" = 42\ntimeout: 5m\nmax_turns: 5\n",
		"tasks/uat-pass/repo/README": "uat\n", "tasks/uat-fail/repo/README": "uat\n",
		"suites/claude-settings.json": `{"env":{"ANTHROPIC_BASE_URL":"http://mock:8080","DISABLE_AUTOUPDATER":"1"},"apiKeyHelper":"echo uat-eval-key"}`,
		"suites/codex-settings.toml":  "model_provider = \"mock\"\n[model_providers.mock]\nname = \"mock\"\nbase_url = \"http://mock:8080/v1\"\nenv_key = \"HALO_GATEWAY_TOKEN\"\nwire_api = \"responses\"\n",
		"suites/uat.yaml": fmt.Sprintf(`name: uat
tasks: [uat-pass, uat-fail]
control: claude
repeats: 2
variants:
  - {name: claude, harness: claude, version: %[1]q, model: sonnet, settings: claude-settings.json}
  - {name: claude-b, harness: claude, version: %[1]q, model: opus, settings: claude-settings.json}
  - {name: codex, harness: codex, version: %[2]q, model: gpt-uat, settings: codex-settings.toml}
`, pins["claude"], pins["codex"]),
		"suites/matrix.yaml": fmt.Sprintf(`name: uat-matrix
tasks: [uat-pass]
repeats: 1
matrix:
  harnesses:
    - {harness: claude, version: %q, models: [sonnet], settings: claude-settings.json}
    - {harness: codex, version: %q, models: [gpt-uat], settings: codex-settings.toml}
`, pins["claude"], pins["codex"]),
	}
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(es, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(es, p), []byte(c), 0o644); err != nil { //nolint:gosec // fixture
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command(halo, append([]string{"eval", "run"}, args...)...)
		cmd.Env = append(os.Environ(), "HALO_GATEWAY_TOKEN=uat-eval-token")
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	e.resetMock()
	sc := filepath.Join(e.dir, "scorecard.json")
	out, err := run(filepath.Join(es, "suites/uat.yaml"), "--network", e.net, "--pass-env", "HALO_GATEWAY_TOKEN", "--parallel", "1",
		"--scorecard", sc, "--report", filepath.Join(e.dir, "eval-report.md"))
	t.Logf("halo eval run (err=%v):\n%s", err, tail(out, 30))
	var card struct {
		Variants []evalVariant `json:"variants"`
		Trials   []struct {
			Variant string `json:"variant"`
			Task    string `json:"task"`
			Pass    bool   `json:"pass"`
			Error   string `json:"error"`
		} `json:"trials"`
		Gate *struct {
			Verdict string   `json:"verdict"`
			Reasons []string `json:"reasons"`
		} `json:"gate"`
		Comparisons []struct {
			Variant string `json:"variant"`
			Gate    *struct {
				Verdict string   `json:"verdict"`
				Reasons []string `json:"reasons"`
				Flaky   []struct {
					Task string `json:"task"`
				} `json:"flaky"`
			} `json:"gate"`
		} `json:"comparisons"`
	}
	b, rerr := os.ReadFile(sc)
	if rerr != nil || json.Unmarshal(b, &card) != nil || len(card.Variants) != 3 {
		check(t, h, "scorecard written", false, fmt.Sprintf("read %s: %v; run err %v: %s", sc, rerr, err, tail(out, 5)), "")
		return
	}
	var trials []string
	for _, tr := range card.Trials {
		s := fmt.Sprintf("%s/%s=%v", tr.Variant, tr.Task, tr.Pass)
		if tr.Error != "" {
			s += " (" + tr.Error + ")"
		}
		trials = append(trials, s)
	}
	v := map[string]int{}
	for i, x := range card.Variants {
		v[x.Name] = i
	}
	cl, cb, cx := card.Variants[v["claude"]], card.Variants[v["claude-b"]], card.Variants[v["codex"]]
	stats := func(x evalVariant) string {
		return fmt.Sprintf("pass1=%.2f pass@k=%.2f pass^k=%.2f toolErrors=%d errors=%d", x.Pass1, x.PassAtK, x.PassHatK, x.ToolErrors, x.Errors)
	}
	// Without Landlock the DockerRunner marks codex trials unmeasurable instead of scoring them 0.
	noLandlock := cx.Errors > 0 && strings.Contains(strings.Join(trials, " "), "Landlock")
	check(t, h, "real claude + codex drivers ran every trial", len(card.Trials) == 12 && cl.Errors == 0 && cb.Errors == 0 && (cx.Errors == 0 || landlockGap(noLandlock) != ""),
		fmt.Sprintf("trials %v", trials), "")
	for _, x := range []evalVariant{cl, cb} {
		check(t, h, x.Name+" (claude driver): pass@1 3/4, pass@2 1, pass^2 0.5 (uat-pass 2/2, flaky uat-fail 1/2)", x.Pass1 == 0.75 && x.PassAtK == 1 && x.PassHatK == 0.5, stats(x), "")
	}
	check(t, h, "codex driver: pass@1 2/4 (uat-pass 2/2, uat-fail 0/2)", cx.Pass1 == 0.5 && cx.Errors == 0, stats(cx)+"; kernel "+strings.TrimSpace(kernel()), landlockGap(noLandlock))
	cmp := map[string]int{}
	for i, c := range card.Comparisons {
		cmp[c.Variant] = i
	}
	var flaky []string
	verdict := ""
	var reasons []string
	if i, ok := cmp["claude-b"]; ok && card.Comparisons[i].Gate != nil {
		g := card.Comparisons[i].Gate
		verdict, reasons = g.Verdict, g.Reasons
		for _, f := range g.Flaky {
			flaky = append(flaky, f.Task)
		}
	}
	check(t, h, "flake handling: control-flaky uat-fail excluded from the claude-b gate", strings.Join(flaky, ",") == "uat-fail",
		fmt.Sprintf("gate.flaky=%v", flaky), "")
	check(t, h, "claude-b gate verdict: ship (1 gated task, no pass drop)", verdict == "ship", fmt.Sprintf("verdict=%q reasons=%v", verdict, reasons), "")
	if card.Gate != nil {
		want := "ship"
		if noLandlock {
			want = "hold" // unmeasurable codex arm: rerun on a capable host, never ship or block
		}
		check(t, h, "overall gate follows the data ("+want+")", card.Gate.Verdict == want, fmt.Sprintf("verdict=%q reasons=%v", card.Gate.Verdict, card.Gate.Reasons), "")
	}
	rep, _ := os.ReadFile(filepath.Join(e.dir, "eval-report.md"))
	check(t, h, "Markdown report renders", strings.Contains(string(rep), "codex") && strings.Contains(string(rep), "claude"),
		fmt.Sprintf("%d bytes, first line %q", len(rep), strings.SplitN(string(rep), "\n", 2)[0]), "")

	out, err = run(filepath.Join(es, "suites/matrix.yaml"), "--matrix", "--network", e.net, "--pass-env", "HALO_GATEWAY_TOKEN", "--parallel", "1")
	t.Logf("halo eval run --matrix (err=%v):\n%s", err, out)
	check(t, h, "matrix report renders (claude x codex cells)", err == nil && strings.Contains(out, "claude@"+pins["claude"]) && strings.Contains(out, "codex@"+pins["codex"]),
		tail(out, 6), "")
}

func kernel() string {
	out, _ := cliDocker("run", "--rm", "debian:bookworm-slim", "uname", "-r")
	return out
}

type evalVariant struct {
	Name       string  `json:"name"`
	Trials     int     `json:"trials"`
	Pass1      float64 `json:"pass1"`
	PassAtK    float64 `json:"passAtK"`
	PassHatK   float64 `json:"passHatK"`
	Errors     int     `json:"errors"`
	ToolErrors int     `json:"toolErrors"`
}
