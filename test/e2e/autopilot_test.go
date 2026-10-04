//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpSession is `halo mcp serve` over stdio plus a typed call helper.
type mcpSession struct {
	t    *testing.T
	ctx  context.Context
	sess *mcp.ClientSession
}

func serveMCP(t *testing.T, env []string, args ...string) *mcpSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	cmd := exec.Command(filepath.Join(binDir, "halo"), append([]string{"mcp", "serve"}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("mcp serve %v: %v", args, err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return &mcpSession{t: t, ctx: ctx, sess: sess}
}

// call runs a tool and decodes its structured content; a tool error fails the test.
func (m *mcpSession) call(name string, args map[string]any) map[string]any {
	m.t.Helper()
	out, err := m.try(name, args)
	if err != nil {
		m.t.Fatalf("%s %v: %v", name, args, err)
	}
	return out
}

func (m *mcpSession) try(name string, args map[string]any) (map[string]any, error) {
	m.t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	res, err := m.sess.CallTool(m.ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, err
	}
	if res.IsError {
		return nil, &toolErr{res.Content[0].(*mcp.TextContent).Text}
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		m.t.Fatalf("%s structured content %s: %v", name, b, err)
	}
	return out, nil
}

type toolErr struct{ msg string }

func (e *toolErr) Error() string { return e.msg }

func steps(out map[string]any) string {
	b, _ := json.Marshal(out["next_steps"])
	return string(b)
}

// TestAutopilotLifecycle drives the whole lifecycle through `halo mcp serve`
// the way an agent would, with the real halo-server (kill switch), a bare
// origin and a recording `gh`: status -> validate -> release_build -> plan ->
// eval_run (dry) -> GATE 1 -> start_experiment -> wait_for -> GATE 2 ->
// propose_promotion (dry) -> propose_rollout_advance (PR) -> regression:
// wait_for -> kill_switch -> propose_rollout_rollback -> unkill. Origin main
// never moves and nothing is published: those are the human's steps.
func TestAutopilotLifecycle(t *testing.T) {
	dir := t.TempDir()
	repo := newRolloutRepo(t, dir)
	writeFile(t, filepath.Join(repo.pol, "experiments/e2e-draft.yaml"), `apiVersion: halos.dev/v1
kind: Experiment
name: e2e-draft
type: canary
axis: traffic
status: draft
rings: [ring0-canary]
variants:
  - {name: primary, weight: 90, control: true}
  - name: next
    weight: 10
    routes:
      sonnet: {upstream: candidate, model: claude-sonnet-next}
metrics:
  primary: {metric: halo.latency.p50_ms, direction: decrease}
  guardrails: [{metric: halo.api.error_rate, direction: decrease, maxRegression: 0.05}]
stopping: {method: msprt, alpha: 0.05}
`)
	writeFile(t, filepath.Join(repo.pol, ".halos/evals/smoke.yaml"), "name: smoke\ntasks: [x]\nmatrix: {harnesses: [{harness: codex, version: '1.0.0', models: [gpt]}]}\n")
	repo.push(t, "draft experiment + eval suite")

	data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
	must(t, nil, "halo", "keys", "generate", "--name", "killswitch", "--out", keys)
	writeFile(t, filepath.Join(dir, "fleet.token"), "e2e-fleet-token\n")
	writeFile(t, filepath.Join(dir, "gateway.token"), "e2e-gateway-token-0123456789\n")
	addr := freeAddr(t)
	base := "http://" + addr
	start(t, nil, "halo-server", "--listen", addr, "--policy-dir", repo.pol, "--token-file", filepath.Join(dir, "fleet.token"),
		"--data-dir", data, "--killswitch-key-file", filepath.Join(keys, "killswitch.key"),
		"--gateway-token-file", filepath.Join(dir, "gateway.token"), "--dev-insecure-user", "admin@acme.com", "--dev-insecure-admin")
	waitUp(t, base+"/healthz", 200)

	env := append(repo.env, "HALO_SESSION=e2e-admin") // dev-insecure server: any session value; the client still insists on one
	m := serveMCP(t, env, "--policy-dir", repo.pol, "--allow-writes", "--clickhouse", fakeClickHouse(t, 0), "--server", base)

	// 1. status: one call tells the agent what is on and what is in flight.
	st := m.call("status", nil)
	srvInfo := st["server"].(map[string]any)
	ks, _ := st["kill_switch"].(map[string]any)
	if srvInfo["allow_writes"] != true || srvInfo["clickhouse"] != true || srvInfo["admin_session"] != true || ks["configured"] != true {
		t.Fatalf("status planes: %s", mustJSON(st))
	}
	if s := steps(st); !strings.Contains(s, "sonnet-next-canary is running: wait_for") || !strings.Contains(s, "e2e-draft is a draft") || !strings.Contains(s, "rollout sonnet-next is active") {
		t.Fatalf("status next_steps: %s", s)
	}

	// 2-4. validate, release_build, plan.
	if v := m.call("validate", nil); v["ok"] != true {
		t.Fatalf("validate: %v", v)
	}
	rb := m.call("release_build", map[string]any{"ring": "ring0-canary", "release_version": "1.0.0"})
	digest, _ := rb["digest"].(string)
	if !strings.HasPrefix(digest, "sha256:") || !strings.Contains(steps(rb), "halo release publish") {
		t.Fatalf("release_build: %v", rb)
	}
	if p := m.call("plan", map[string]any{"ring": "ring0-canary"}); p["changed"] != true {
		t.Fatalf("plan: %v", p)
	}

	// 5. eval_run previews the command; the real run spends credentials and is the agent's next ask.
	ev := m.call("eval_run", map[string]any{"suite": ".halos/evals/smoke.yaml", "matrix": true})
	if ev["dry_run"] != true || ev["ran"] != false || !strings.HasPrefix(ev["command"].(string), "halo eval run ") {
		t.Fatalf("eval_run: %v", ev)
	}

	// 6-8. GATE 1 (a yes) then start_experiment: dry run shows the patch, the real call lands on a local branch only.
	d := m.call("start_experiment", map[string]any{"name": "e2e-draft", "reason": "e2e: GATE 1 approved"})
	if d["dry_run"] != true || !strings.Contains(d["patch"].(string), "+status: running") || !strings.Contains(steps(d), "human gate") {
		t.Fatalf("start dry run: %v", d)
	}
	a := m.call("start_experiment", map[string]any{"name": "e2e-draft", "reason": "e2e: GATE 1 approved", "dry_run": false})
	br, _ := a["branch"].(string)
	if a["applied"] != true || !strings.HasPrefix(br, "halos/start-e2e-draft-") || !strings.Contains(steps(a), "git -C "+repo.pol+" push -u origin "+br) {
		t.Fatalf("start: %v", a)
	}
	if got := git(t, repo.pol, "show", br+":experiments/e2e-draft.yaml"); !strings.Contains(got, "status: running") {
		t.Fatalf("branch content:\n%s", got)
	}
	repo.neverMerged(t)
	// Re-entrant: the same call again is another local branch, never a push or a merge.
	if a2 := m.call("start_experiment", map[string]any{"name": "e2e-draft", "reason": "again", "dry_run": false}); a2["applied"] != true || a2["branch"] == br {
		t.Fatalf("second start: %v", a2)
	}
	repo.neverMerged(t)

	// 9. wait_for on the running experiment (healthy data: no verdict yet) and on the rollout (gates pass: advance).
	w := m.call("wait_for", map[string]any{"kind": "experiment", "name": "sonnet-next-canary", "timeout_seconds": 1})
	if w["polls"].(float64) < 1 || w["outcome"] == "" || w["last"] == nil {
		t.Fatalf("wait experiment: %v", w)
	}
	if w["satisfied"] == false && !strings.Contains(steps(w), "call wait_for again") {
		t.Fatalf("wait experiment next_steps: %s", steps(w))
	}
	wr := m.call("wait_for", map[string]any{"kind": "rollout", "name": "sonnet-next", "timeout_seconds": 1})
	if wr["satisfied"] != true || wr["outcome"] != "advance" || !strings.Contains(steps(wr), "propose_rollout_advance sonnet-next") {
		t.Fatalf("wait rollout: %v", wr)
	}

	// 10. GATE 2: promotion is previewed (verdict shown, no PR); the rollout advance opens a PR a human merges.
	pp := m.call("propose_promotion", map[string]any{"experiment": "sonnet-next-canary", "ring": "ring0-canary", "release": digest, "reason": "e2e"})
	if pp["dry_run"] != true || pp["applied"] == true || pp["verdict"] == "" || pp["pr"] != nil {
		t.Fatalf("propose_promotion dry: %v", pp)
	}
	adv := m.call("propose_rollout_advance", map[string]any{"name": "sonnet-next", "reason": "e2e: GATE 2 approved"})
	if adv["dry_run"] != true || !strings.Contains(adv["patch"].(string), "canary-50") {
		t.Fatalf("advance dry: %v", adv)
	}
	adv = m.call("propose_rollout_advance", map[string]any{"name": "sonnet-next", "reason": "e2e: GATE 2 approved", "dry_run": false, "open_pr": true, "base": "main"})
	if adv["applied"] != true || adv["pr"] != "https://github.example/acme/policy/pull/1" || !strings.Contains(steps(adv), "merge") {
		t.Fatalf("advance PR: %v", adv)
	}
	prs := repo.prs(t)
	if len(prs) != 1 || !strings.Contains(prs[0], "pr create") || !strings.Contains(prs[0], "--head halos/rollout-sonnet-next-canary-50") || !strings.Contains(prs[0], "--base main") {
		t.Fatalf("gh calls: %q", prs)
	}
	if ro := repo.pushed(t, "halos/rollout-sonnet-next-canary-50", "rollouts/sonnet-next.yaml"); !strings.Contains(ro, "step: canary-50\n") {
		t.Fatalf("advance branch:\n%s", ro)
	}
	repo.neverMerged(t)

	// 11. Regression: a server reading bad evidence returns rollback; kill first (fleet), then record it (policy).
	bad := serveMCP(t, env, "--policy-dir", repo.pol, "--allow-writes", "--clickhouse", fakeClickHouse(t, 0.5), "--server", base)
	w = bad.call("wait_for", map[string]any{"kind": "experiment", "name": "sonnet-next-canary", "timeout_seconds": 5})
	if w["satisfied"] != true || w["outcome"] != "rollback" || !strings.Contains(steps(w), "kill_switch sonnet-next-canary") {
		t.Fatalf("wait regression: %v", w)
	}
	k := bad.call("kill_switch", map[string]any{"name": "sonnet-next", "reason": "e2e: error rate +50%"})
	if k["dry_run"] != true || k["applied"] != false || k["name"] != "sonnet-next-canary" || k["kind"] != "experiment" {
		t.Fatalf("kill dry: %v", k)
	}
	if got := killList(t, base, keys); len(got) != 0 {
		t.Fatalf("dry run killed: %v", got)
	}
	k = bad.call("kill_switch", map[string]any{"name": "sonnet-next", "reason": "e2e: error rate +50%", "dry_run": false})
	if k["applied"] != true || !strings.Contains(steps(k), "propose_rollout_rollback sonnet-next") {
		t.Fatalf("kill: %v", k)
	}
	if got := killList(t, base, keys); len(got) != 1 || got[0] != "sonnet-next-canary" {
		t.Fatalf("kill list %v", got)
	}
	ks = bad.call("kill_switch_status", nil)
	if ks["configured"] != true || len(ks["killed"].([]any)) != 1 {
		t.Fatalf("kill_switch_status: %v", ks)
	}
	if st2 := bad.call("status", nil); !strings.Contains(string(mustJSON(st2["experiments"])), `"killed":true`) {
		t.Fatalf("status does not show the kill: %v", st2["experiments"])
	}
	au := bad.call("audit_tail", map[string]any{"limit": 20})
	if !strings.Contains(string(mustJSON(au)), "kill") {
		t.Fatalf("audit_tail lacks the kill: %v", au)
	}
	if fl := bad.call("fleet_status", nil); fl["total"] == nil {
		t.Fatalf("fleet_status: %v", fl)
	}
	rbk := bad.call("propose_rollout_rollback", map[string]any{"name": "sonnet-next", "reason": "e2e: killed"})
	if rbk["dry_run"] != true || !strings.Contains(rbk["patch"].(string), "aborted") || !strings.Contains(rbk["patch"].(string), "paused") {
		t.Fatalf("rollback dry: %v", rbk)
	}
	rbk = bad.call("propose_rollout_rollback", map[string]any{"name": "sonnet-next", "reason": "e2e: killed", "dry_run": false})
	if rbk["applied"] != true || !strings.HasPrefix(rbk["branch"].(string), "halos/rollout-sonnet-next-rollback") {
		t.Fatalf("rollback: %v", rbk)
	}
	// Advance is refused while a gate fails; the agent cannot talk its way past it.
	if _, err := bad.try("propose_rollout_advance", map[string]any{"name": "sonnet-next", "reason": "please", "dry_run": false}); err == nil || !strings.Contains(err.Error(), "gate failed") {
		t.Fatalf("advance on a failing gate: %v", err)
	}
	// Unkill clears the fleet stop (reversible); the policy branch stays for the human.
	if u := bad.call("kill_switch", map[string]any{"name": "sonnet-next-canary", "reason": "e2e: fixed", "unkill": true, "dry_run": false}); u["applied"] != true {
		t.Fatalf("unkill: %v", u)
	}
	if got := killList(t, base, keys); len(got) != 0 {
		t.Fatalf("still killed: %v", got)
	}

	// Invariant 5, end to end: origin main never moved, the checkout is clean,
	// and the only remote branches are the review branches the tools opened.
	repo.neverMerged(t)
	for _, b := range strings.Fields(git(t, repo.origin, "for-each-ref", "--format=%(refname:short)", "refs/heads/")) {
		if b != "main" && !strings.HasPrefix(b, "halos/") {
			t.Fatalf("unexpected origin branch %s", b)
		}
	}
	if len(repo.prs(t)) != 1 {
		t.Fatalf("PRs opened: %q", repo.prs(t))
	}

	// A read-only server still answers every question and refuses every write.
	ro := serveMCP(t, env, "--policy-dir", repo.pol, "--server", base)
	if _, err := ro.try("kill_switch", map[string]any{"name": "sonnet-next-canary", "reason": "x", "dry_run": false}); err == nil || !strings.Contains(err.Error(), "--allow-writes") {
		t.Fatalf("read-only kill: %v", err)
	}
	if _, err := ro.try("start_experiment", map[string]any{"name": "e2e-draft", "reason": "x"}); err == nil {
		t.Fatal("read-only server exposes start_experiment")
	}
	if s := ro.call("status", nil); !strings.Contains(steps(s), "--allow-writes") {
		t.Fatalf("read-only status next_steps: %s", steps(s))
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
