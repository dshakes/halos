//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
)

const rolloutYAML = `apiVersion: halos.dev/v1alpha1
kind: Rollout
name: sonnet-next
axis: traffic
status: active
step: canary-5
experiment: sonnet-next-canary
change: {alias: sonnet}
steps:
  - name: canary-5
    strategy: canary
    percent: 5
    minSamples: 100
  - name: canary-50
    strategy: canary
    percent: 50
    minSamples: 100
`

// fakeClickHouse answers the controller's evidence queries over ClickHouse's
// HTTP interface (JSONEachRow), as internal/promote.ClickHouse sends them:
// 3000 users per arm; the treatment's error rate is `regress` worse.
func fakeClickHouse(t *testing.T, regress float64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "min(ts)") { // Window
			fmt.Fprintf(w, `{"n":1,"start":%d,"spend":0}`+"\n", time.Now().Add(-time.Hour).Unix())
			return
		}
		worse := 0.0
		if r.URL.Query().Get("param_metric") == "halo.api.error_rate" {
			worse = regress
		}
		for i := 0; i < 3000; i++ {
			v := 1 + 0.05*float64(i%7-3)/3
			fmt.Fprintf(w, `{"variant":"primary","v":%g}`+"\n{\"variant\":\"sonnet-next\",\"v\":%g}\n", v, v*(1+worse))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

type rolloutRepo struct {
	pol, origin, ghLog string
	env                []string
	mainAt             string // origin/main at setup: nothing may move it
}

// newRolloutRepo is a policy git repo (pushed to a bare origin) with a live
// traffic-axis rollout at canary-5, and a recording `gh` on PATH.
func newRolloutRepo(t *testing.T, dir string) rolloutRepo {
	t.Helper()
	pol := filepath.Join(dir, "policy")
	newPolicy(t, pol)
	writeFile(t, filepath.Join(pol, "gateway.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Gateway
name: acme-gateway
baseURL: https://ai.acme.example
auth: {helperCommand: /usr/local/bin/acme-token}
upstreams:
  primary: {url: "http://127.0.0.1:1", kind: anthropic}
  candidate: {url: "http://127.0.0.1:1", kind: anthropic}
models:
  sonnet: {upstream: primary, model: claude-sonnet-4-5}
`)
	writeFile(t, filepath.Join(pol, "experiments/sonnet-next-canary.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Experiment
name: sonnet-next-canary
type: canary
axis: traffic
status: running
rings: [ring0-canary, ring1-ga]
variants:
  - {name: primary, weight: 95, control: true}
  - name: sonnet-next
    weight: 5
    routes:
      sonnet: {upstream: candidate, model: claude-sonnet-next}
# The steps declare no guardrails: they inherit this one (audit M1).
metrics:
  primary: {metric: halo.latency.p50_ms, direction: decrease}
  guardrails: [{metric: halo.api.error_rate, direction: decrease, maxRegression: 0.05}]
stopping: {method: msprt, alpha: 0.05}
`)
	writeFile(t, filepath.Join(pol, "rollouts/sonnet-next.yaml"), rolloutYAML)
	if r := run(t, nil, "", "halo", "validate", "--policy-dir", pol); r.code != 0 {
		t.Fatalf("rollout policy invalid: %s", r)
	}
	return gitRepo(t, dir, pol)
}

// gitRepo commits pol, pushes it to a bare origin, and puts a recording `gh`
// on PATH (env).
func gitRepo(t *testing.T, dir, pol string) rolloutRepo {
	t.Helper()
	origin := filepath.Join(dir, "origin.git")
	if out, err := exec.Command("git", "init", "-q", "--bare", "-b", "main", origin).CombinedOutput(); err != nil {
		t.Fatalf("git init origin: %v %s", err, out)
	}
	git(t, pol, "init", "-q", "-b", "main")
	git(t, pol, "config", "user.name", "e2e")
	git(t, pol, "config", "user.email", "e2e@example.com")
	git(t, pol, "add", ".")
	git(t, pol, "commit", "-qm", "policy")
	git(t, pol, "remote", "add", "origin", origin)
	git(t, pol, "push", "-q", "origin", "main")

	bin := filepath.Join(dir, "fakebin")
	ghLog := filepath.Join(dir, "gh.log")
	writeFile(t, filepath.Join(bin, "gh"), "#!/bin/sh\n# one line per call: the PR body is multi-line\necho \"$*\" | tr '\\n' ' ' >> \""+ghLog+"\"\necho >> \""+ghLog+"\"\necho https://github.example/acme/policy/pull/1\n")
	if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
		t.Fatal(err)
	}
	return rolloutRepo{pol: pol, origin: origin, ghLog: ghLog, mainAt: git(t, origin, "rev-parse", "main"),
		env: []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}}
}

// pushed returns the one origin branch with prefix and the rollout file on it.
func (r rolloutRepo) pushed(t *testing.T, prefix, file string) string {
	t.Helper()
	var branches []string
	for _, b := range strings.Fields(git(t, r.origin, "for-each-ref", "--format=%(refname:short)", "refs/heads/")) {
		if strings.HasPrefix(b, prefix) {
			branches = append(branches, b)
		}
	}
	if len(branches) != 1 {
		t.Fatalf("origin branches with %s: %v", prefix, branches)
	}
	return git(t, r.origin, "show", branches[0]+":"+file)
}

// neverMerged: origin/main and the checkout are exactly as set up.
func (r rolloutRepo) neverMerged(t *testing.T) {
	t.Helper()
	if got := git(t, r.origin, "rev-parse", "main"); got != r.mainAt {
		t.Fatalf("origin/main moved: %s -> %s", r.mainAt, got)
	}
	if st := git(t, r.pol, "status", "--porcelain"); st != "" {
		t.Fatalf("policy checkout changed:\n%s", st)
	}
}

// push commits everything in the checkout to origin/main (a human merge).
func (r *rolloutRepo) push(t *testing.T, msg string) {
	t.Helper()
	git(t, r.pol, "add", "-A")
	git(t, r.pol, "commit", "-qm", msg)
	git(t, r.pol, "push", "-q", "origin", "main")
	r.mainAt = git(t, r.origin, "rev-parse", "main")
}

func (r rolloutRepo) prs(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(r.ghLog)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// TestRollout drives a real `halo controller run --once` over a live rollout.
// Healthy: every gate passes, the controller opens one PR to the next step
// (a pushed branch) and never merges. Regression: a gateway-sourced guardrail
// breach rolls back at once (rollback PR) and trips the kill switch, which
// halo-server signs and serves to gateways. The guardrail is the backing
// experiment's, inherited by steps that declare none.
func TestRollout(t *testing.T) {
	t.Run("healthy advance opens a PR and never merges", func(t *testing.T) {
		dir := t.TempDir()
		repo := newRolloutRepo(t, dir)
		ch := fakeClickHouse(t, 0)
		for i := 0; i < 2; i++ { // the second tick must not open a second PR
			must(t, repo.env, "halo", "controller", "run", "--once", "--policy-dir", repo.pol, "--data-dir", filepath.Join(dir, "data"),
				"--clickhouse", ch, "--base", "main")
		}
		prs := repo.prs(t)
		if len(prs) != 1 || !strings.Contains(prs[0], "pr create") || !strings.Contains(prs[0], "--head halos/rollout-sonnet-next-canary-50") ||
			!strings.Contains(prs[0], "--base main") || !strings.Contains(prs[0], "a human must review and merge") {
			t.Fatalf("gh calls: %q", prs)
		}
		ro := repo.pushed(t, "halos/rollout-sonnet-next-canary-50", "rollouts/sonnet-next.yaml")
		exp := repo.pushed(t, "halos/rollout-sonnet-next-canary-50", "experiments/sonnet-next-canary.yaml")
		if !strings.Contains(ro, "step: canary-50\n") || !strings.Contains(exp, "weight: 50\n") || strings.Contains(exp, "weight: 95") {
			t.Fatalf("advance branch:\n%s\n%s", ro, exp)
		}
		repo.neverMerged(t)
		st := readFile(t, filepath.Join(dir, "data", "rollouts", "sonnet-next.json"))
		if !strings.Contains(st, `"action": "advance"`) || !strings.Contains(st, `"key": "pr:advance"`) {
			t.Fatalf("state:\n%s", st)
		}
	})

	t.Run("regression rolls back and the kill list is signed and served", func(t *testing.T) {
		dir := t.TempDir()
		repo := newRolloutRepo(t, dir)
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

		r := must(t, repo.env, "halo", "controller", "run", "--once", "--policy-dir", repo.pol, "--data-dir", data,
			"--clickhouse", fakeClickHouse(t, 0.5), "--killswitch-served", "--base", "main")
		if !strings.Contains(r.stderr, "kill switch tripped for rollout") {
			t.Fatalf("no kill logged: %s", r)
		}
		prs := repo.prs(t)
		if len(prs) != 1 || !strings.Contains(prs[0], "--head halos/rollout-sonnet-next-rollback") {
			t.Fatalf("gh calls: %q", prs)
		}
		ro := repo.pushed(t, "halos/rollout-sonnet-next-rollback", "rollouts/sonnet-next.yaml")
		exp := repo.pushed(t, "halos/rollout-sonnet-next-rollback", "experiments/sonnet-next-canary.yaml")
		if !strings.Contains(ro, "status: aborted\n") || !strings.Contains(exp, "status: paused\n") {
			t.Fatalf("rollback branch:\n%s\n%s", ro, exp)
		}
		repo.neverMerged(t)

		// halo-server signs the kill and serves it to gateways.
		if got := killList(t, base, keys); len(got) != 1 || got[0] != "sonnet-next-canary" {
			t.Fatalf("kill list %v", got)
		}
		killAudited(t, data)
		halted(t, base)
		// A second tick kills and opens nothing more.
		must(t, repo.env, "halo", "controller", "run", "--once", "--policy-dir", repo.pol, "--data-dir", data,
			"--clickhouse", fakeClickHouse(t, 0.5), "--killswitch-served", "--base", "main")
		if n := len(repo.prs(t)); n != 1 {
			t.Fatalf("second tick opened %d PRs", n)
		}
	})

	// The same regression driven by halo-server's in-process controller
	// (--controller), whose kill goes through server.KillExperiment: it must
	// kill the backing experiment, not one named after the actor.
	t.Run("halo-server --controller rolls back and kills the right experiment", func(t *testing.T) {
		dir := t.TempDir()
		repo := newRolloutRepo(t, dir)
		clone := filepath.Join(dir, "clone") // the controller's PR clone: never the served dir
		if out, err := exec.Command("git", "clone", "-q", repo.origin, clone).CombinedOutput(); err != nil {
			t.Fatalf("git clone: %v %s", err, out)
		}
		git(t, clone, "config", "user.name", "halo-controller")
		git(t, clone, "config", "user.email", "halo-controller@example.com")
		data, keys := filepath.Join(dir, "data"), filepath.Join(dir, "keys")
		must(t, nil, "halo", "keys", "generate", "--name", "killswitch", "--out", keys)
		writeFile(t, filepath.Join(dir, "fleet.token"), "e2e-fleet-token\n")
		writeFile(t, filepath.Join(dir, "gateway.token"), "e2e-gateway-token-0123456789\n")
		addr := freeAddr(t)
		base := "http://" + addr
		start(t, repo.env, "halo-server", "--listen", addr, "--policy-dir", repo.pol, "--token-file", filepath.Join(dir, "fleet.token"),
			"--data-dir", data, "--killswitch-key-file", filepath.Join(keys, "killswitch.key"),
			"--gateway-token-file", filepath.Join(dir, "gateway.token"), "--dev-insecure-user", "admin@acme.com", "--dev-insecure-admin",
			"--controller", "--clickhouse-url", fakeClickHouse(t, 0.5), "--interval", "1m",
			"--policy-repo-dir", clone, "--policy-repo-base", "main")
		waitUp(t, base+"/healthz", 200)

		// The first tick runs at start-up.
		var got []string
		waitFor(t, 30*time.Second, "the rollback kill on the signed gateway list", func() bool {
			got = killList(t, base, keys)
			return len(got) > 0
		})
		if len(got) != 1 || got[0] != "sonnet-next-canary" {
			t.Fatalf("killed %v, want exactly the backing experiment", got)
		}
		killAudited(t, data)
		halted(t, base)
		waitFor(t, 30*time.Second, "the rollback PR", func() bool { return len(repo.prs(t)) == 1 })
		if prs := repo.prs(t); !strings.Contains(prs[0], "--head halos/rollout-sonnet-next-rollback") || !strings.Contains(prs[0], "--base main") {
			t.Fatalf("gh calls: %q", prs)
		}
		if ro := repo.pushed(t, "halos/rollout-sonnet-next-rollback", "rollouts/sonnet-next.yaml"); !strings.Contains(ro, "status: aborted\n") {
			t.Fatalf("rollback branch:\n%s", ro)
		}
		repo.neverMerged(t)
	})
}

// TestRolloutSimpleModeCompletion: in simple mode `halo model switch --canary`
// generates a gateway.yaml override next to the rollout; approving the last
// step (`halo rollout advance`) opens the completion PR, which re-points
// halos.yaml models.<alias> and deletes that override, so the merged policy
// is simple again. Nothing merges.
func TestRolloutSimpleModeCompletion(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	writeFile(t, filepath.Join(pol, "halos.yaml"), `org: acme
tools:
  claude-code: `+pin+`
provider: anthropic
models:
  default: claude-sonnet-4-5
  opus: claude-opus-4-1
gateway: https://ai.acme.example
`)
	repo := gitRepo(t, dir, pol)
	must(t, nil, "halo", "model", "switch", "opus", "claude-opus-5-5", "--canary", "--policy-dir", pol)
	const name = "opus-claude-opus-5-5"
	if gw := readFile(t, filepath.Join(pol, "gateway.yaml")); !strings.Contains(gw, "halos.dev/generated-by: rollout/"+name) {
		t.Fatalf("model switch did not label its gateway override:\n%s", gw)
	}
	repo.push(t, "canary model switch")
	// The ramp ran; a human now approves the last step.
	ro := filepath.Join(pol, "rollouts", name+".yaml")
	last := regexp.MustCompile(`(?m)^  - name: (\S+)$`).FindAllStringSubmatch(readFile(t, ro), -1)
	replaceIn(t, ro, "status: draft\n", "status: active\nstep: "+last[len(last)-1][1]+"\n")
	if r := run(t, nil, "", "halo", "validate", "--policy-dir", pol); r.code != 0 {
		t.Fatalf("policy invalid: %s", r)
	}
	repo.push(t, "ramp done")

	must(t, repo.env, "halo", "rollout", "advance", name, "--reason", "canary healthy", "--policy-dir", pol, "--base", "main")
	if prs := repo.prs(t); len(prs) != 1 || !strings.Contains(prs[0], "--head halos/rollout-"+name+"-complete") {
		t.Fatalf("gh calls: %q", prs)
	}
	if root := repo.pushed(t, "halos/rollout-"+name+"-complete", "halos.yaml"); !strings.Contains(root, "  opus: claude-opus-5-5\n") {
		t.Fatalf("halos.yaml on the completion branch:\n%s", root)
	}
	if got := repo.pushed(t, "halos/rollout-"+name+"-complete", "rollouts/"+name+".yaml"); !strings.Contains(got, "status: completed\n") {
		t.Fatalf("rollout on the completion branch:\n%s", got)
	}
	branch := strings.Fields(git(t, repo.origin, "for-each-ref", "--format=%(refname:short)", "refs/heads/halos/rollout-"+name+"-complete*"))[0]
	if out, err := exec.Command("git", "-C", repo.origin, "cat-file", "-e", branch+":gateway.yaml").CombinedOutput(); err == nil {
		t.Fatalf("generated gateway.yaml survived completion (%s)", out)
	}
	repo.neverMerged(t)
	// What the PR proposes is a clean simple-mode policy.
	merged := filepath.Join(dir, "merged")
	if out, err := exec.Command("git", "clone", "-q", "-b", strings.TrimPrefix(branch, "origin/"), repo.origin, merged).CombinedOutput(); err != nil {
		t.Fatalf("clone branch: %v %s", err, out)
	}
	if r := run(t, nil, "", "halo", "validate", "--policy-dir", merged); r.code != 0 {
		t.Fatalf("completed policy invalid: %s", r)
	}
}

// killList fetches the gateway kill list from halo-server and verifies its
// signature with the killswitch key in keys; nil while none is served.
func killList(t *testing.T, base, keys string) []string {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/api/v1/gateway/killswitch", nil)
	req.Header.Set("Authorization", "Bearer e2e-gateway-token-0123456789")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var env gateway.KillEnvelope
	if resp.StatusCode != 200 || json.Unmarshal(body, &env) != nil {
		t.Fatalf("gateway killswitch: %s %s", resp.Status, body)
	}
	v, err := bundle.ParseEd25519Verifier([]byte(readFile(t, filepath.Join(keys, "killswitch.pub"))))
	if err != nil {
		t.Fatal(err)
	}
	list, err := gateway.VerifyKillList(v.Key, env, time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("kill list: %v", err)
	}
	return list.Experiments
}

func killAudited(t *testing.T, data string) {
	t.Helper()
	if a := readFile(t, filepath.Join(data, "audit.jsonl")); !strings.Contains(a, `"experiment.kill"`) || !strings.Contains(a, `"sonnet-next-canary"`) {
		t.Fatalf("kill not audited:\n%s", a)
	}
}

// halted: the console shows the rollout halted on gateway evidence.
func halted(t *testing.T, base string) {
	t.Helper()
	resp, err := http.Get(base + "/api/v1/rollouts/sonnet-next")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var view struct {
		State struct{ Halted, HaltSource string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil || view.State.Halted != "rollback" || view.State.HaltSource != "gateway" {
		t.Fatalf("rollout view %+v: %v", view, err)
	}
}
