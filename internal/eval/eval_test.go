package eval

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeDriver stands in for a real harness. Model "fixer" repairs the bug;
// "noop" does nothing; "slow" sleeps past the timeout; "settings" fixes only
// if the managed settings file was mounted.
type fakeDriver struct{}

func (fakeDriver) Name() string         { return "fake" }
func (fakeDriver) SettingsPath() string { return "/etc/fake/settings.json" }
func (fakeDriver) Command(t *Task, v Variant) Command {
	fix := `sed -i.bak 's/a - b/a + b/' add.go && `
	switch v.Model {
	case "fixer":
		return sh(fix + `echo '{"type":"result","total_cost_usd":0.25,"num_turns":4}'`)
	case "settings":
		return sh(`test -s "$HALO_SETTINGS_FILE" && ` + fix + `echo '{"type":"result","total_cost_usd":0.1,"num_turns":1}'`)
	case "slow":
		return sh("sleep 5")
	}
	return sh(`echo '{"type":"result","total_cost_usd":0.05,"num_turns":2}'`)
}
func (fakeDriver) Parse(out []byte) (Usage, error) {
	var m struct {
		Cost  float64 `json:"total_cost_usd"`
		Turns int     `json:"num_turns"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return Usage{}, err
	}
	return Usage{CostUSD: m.Cost, Turns: m.Turns, Tokens: 100}, nil
}

func fixtureTask(t *testing.T) *Task {
	t.Helper()
	task, err := LoadTask("testdata/tasks/fix-add")
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestRunTrial(t *testing.T) {
	task := fixtureTask(t)
	settings, _ := filepath.Abs("testdata/suites/settings.json")
	tests := []struct {
		name     string
		v        Variant
		timeout  time.Duration
		pass     bool
		errSub   string
		wantCost float64
	}{
		{"agent fixes bug", Variant{Name: "a", Model: "fixer"}, 0, true, "", 0.25},
		{"agent does nothing", Variant{Name: "b", Model: "noop"}, 0, false, "", 0.05},
		{"settings mounted", Variant{Name: "c", Model: "settings", Settings: settings, Dir: filepath.Dir(settings)}, 0, true, "", 0.1},
		{"settings missing", Variant{Name: "d", Model: "settings"}, 0, false, "agent exit", 0},
		{"agent timeout", Variant{Name: "e", Model: "slow"}, 300 * time.Millisecond, false, "agent:", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tk := *task
			if tc.timeout > 0 {
				tk.Timeout = tc.timeout
			}
			tr := RunTrial(context.Background(), LocalRunner{}, fakeDriver{}, &tk, tc.v, 0)
			if tr.Pass != tc.pass || tr.CostUSD != tc.wantCost {
				t.Fatalf("got %+v", tr)
			}
			if !strings.Contains(tr.Error, tc.errSub) || (tc.errSub == "" && tr.Error != "") {
				t.Fatalf("error %q, want substring %q", tr.Error, tc.errSub)
			}
		})
	}
}

func TestRunTrialSetupFailure(t *testing.T) {
	tk := *fixtureTask(t)
	tk.Setup = []string{"exit 3"}
	tr := RunTrial(context.Background(), LocalRunner{}, fakeDriver{}, &tk, Variant{Name: "x", Model: "fixer"}, 0)
	if tr.Pass || !strings.Contains(tr.Error, "setup") {
		t.Fatalf("got %+v", tr)
	}
	tk.Repo = "does-not-exist"
	tr = RunTrial(context.Background(), LocalRunner{}, fakeDriver{}, &tk, Variant{Name: "x"}, 0)
	if tr.Pass || !strings.Contains(tr.Error, "start") {
		t.Fatalf("got %+v", tr)
	}
}

func TestSuiteEndToEnd(t *testing.T) {
	s, err := LoadSuite("testdata/suites/s.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := s.LoadTasks("testdata/tasks")
	if err != nil {
		t.Fatal(err)
	}
	trials, err := RunSuite(context.Background(), s, tasks, LocalRunner{}, map[string]Driver{"claude": fakeDriver{}}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(trials) != 6 {
		t.Fatalf("got %d trials", len(trials))
	}
	sc, err := BuildScorecard(s, trials, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctl, fix := sc.Variants[0], sc.Variants[1]
	if ctl.Pass1 != 0 || fix.Pass1 != 1 {
		t.Fatalf("pass@1 control=%v fixer=%v", ctl.Pass1, fix.Pass1)
	}
	if len(sc.Comparisons) != 1 || sc.Comparisons[0].Delta != 1 {
		t.Fatalf("comparisons: %+v", sc.Comparisons)
	}
	// One task: a paired bootstrap over one pair has a degenerate CI at +1.
	if sc.Comparisons[0].Verdict != VerdictBetter {
		t.Fatalf("verdict %q", sc.Comparisons[0].Verdict)
	}
	md := sc.Markdown()
	for _, want := range []string{"| fixer |", "pass@1", "better"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	if _, err := sc.JSON(); err != nil {
		t.Fatal(err)
	}
}

func TestRunSuiteErrors(t *testing.T) {
	s, _ := LoadSuite("testdata/suites/s.yaml")
	if _, err := RunSuite(context.Background(), s, nil, LocalRunner{}, map[string]Driver{}, 1); err == nil {
		t.Fatal("want missing-driver error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tasks, _ := s.LoadTasks("testdata/tasks")
	if _, err := RunSuite(ctx, s, tasks, LocalRunner{}, map[string]Driver{"claude": fakeDriver{}}, 1); err == nil {
		t.Fatal("want cancellation error")
	}
}

func TestBuildScorecardErrors(t *testing.T) {
	s, _ := LoadSuite("testdata/suites/s.yaml")
	if _, err := BuildScorecard(s, nil, 1); err == nil {
		t.Fatal("want no-trials error")
	}
	if _, err := BuildScorecard(s, []Trial{{Variant: "ghost"}}, 1); err == nil {
		t.Fatal("want unknown-variant error")
	}
}

func TestPercentile(t *testing.T) {
	x := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if percentile(x, 0.5) != 5 || percentile(x, 0.95) != 10 || percentile(nil, 0.5) != 0 {
		t.Fatal("percentile wrong")
	}
}

func TestValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, body := range map[string]string{
		"nocheck.yaml":    "name: x\ntasks: [a]\nvariants: [{name: a, harness: claude}]\ncontrol: zzz\n",
		"badharness.yaml": "name: x\ntasks: [a]\nvariants: [{name: a, harness: vim}]\n",
		"dupe.yaml":       "name: x\ntasks: [a]\nvariants: [{name: a, harness: codex},{name: a, harness: codex}]\n",
		"unknown.yaml":    "name: x\nbogus: 1\ntasks: [a]\nvariants: [{name: a, harness: codex}]\n",
	} {
		if _, err := LoadSuite(write(name, body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	td := filepath.Join(dir, "t")
	_ = os.Mkdir(td, 0o755)
	_ = os.WriteFile(filepath.Join(td, "task.yaml"), []byte("id: t\nrepo: r\nprompt: p\n"), 0o644)
	if _, err := LoadTask(td); err == nil {
		t.Error("want missing-check error")
	}
	if _, err := LoadTask(filepath.Join(dir, "nope")); err == nil {
		t.Error("want missing-file error")
	}
}

func TestDockerRunArgs(t *testing.T) {
	suite := t.TempDir()
	if err := os.WriteFile(filepath.Join(suite, "s.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &DockerRunner{PassEnv: []string{"ANTHROPIC_API_KEY"}}
	args, err := d.runArgs(Job{
		Variant:  Variant{Harness: "claude", Version: "2.1.0", Dir: suite},
		Settings: filepath.Join(suite, "s.json"), SettingsDest: "/etc/claude-code/managed-settings.json",
	}, "n1")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, w := range []string{"--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512",
		"--memory=4g", "--cpus=2", "--user=1000:1000", "--network none",
		":/etc/claude-code/managed-settings.json:ro"} {
		if !strings.Contains(got, w) {
			t.Errorf("args missing %q: %s", w, got)
		}
	}
	if strings.Contains(got, "ANTHROPIC_API_KEY") || strings.Contains(got, " -e ") {
		t.Errorf("env leaked into run args: %s", got)
	}
	d.Network = "halo-gw"
	args, _ = d.runArgs(Job{Variant: Variant{Harness: "claude"}}, "n1")
	if g := strings.Join(args, " "); !strings.Contains(g, "--network halo-gw") {
		t.Errorf("network not honored: %s", g)
	}
}

func TestDockerSettingsOutsideSuiteRejected(t *testing.T) {
	suite, other := t.TempDir(), t.TempDir()
	f := filepath.Join(other, "s.json")
	_ = os.WriteFile(f, []byte("{}"), 0o644)
	d := &DockerRunner{}
	if _, err := d.runArgs(Job{Variant: Variant{Dir: suite}, Settings: f, SettingsDest: "/x"}, "n"); err == nil {
		t.Error("want error for settings outside suite dir")
	}
}

func TestCheckRepoAndRepoDir(t *testing.T) {
	root := t.TempDir()
	task := filepath.Join(root, "task")
	outside := filepath.Join(root, "secret")
	for _, d := range []string{filepath.Join(task, "repo"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(task, "link")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		repo string
		ok   bool
	}{
		{"repo", true},
		{"https://github.com/a/b.git", true},
		{"git@github.com:a/b.git", true},
		{"../secret", false},
		{"repo/../../secret", false},
		{outside, false},
		{"link", false},
		{"file:///etc", false},
		{"ext::sh -c id", false},
		{"ssh://host/x", false},
		{"-oProxy=x", false},
		{"~/.aws", false},
	}
	for _, c := range cases {
		tk := &Task{ID: "t", Repo: c.repo, Dir: task}
		err := checkRepo(c.repo)
		if err == nil && !isRemote(c.repo) {
			_, err = tk.RepoDir()
		}
		if (err == nil) != c.ok {
			t.Errorf("repo %q: ok=%v err=%v", c.repo, c.ok, err)
		}
	}
	// LoadTask rejects file:// outright.
	_ = os.WriteFile(filepath.Join(task, "task.yaml"), []byte("id: t\nrepo: file:///etc\nprompt: p\ncheck: c\n"), 0o644)
	if _, err := LoadTask(task); err == nil {
		t.Error("LoadTask accepted file:// repo")
	}
}

func TestLoadSuiteSettingsContainment(t *testing.T) {
	root := t.TempDir()
	suite := filepath.Join(root, "suites")
	_ = os.Mkdir(suite, 0o755)
	_ = os.WriteFile(filepath.Join(root, "secret.json"), []byte("{}"), 0o644)
	_ = os.WriteFile(filepath.Join(suite, "ok.json"), []byte("{}"), 0o644)
	for settings, ok := range map[string]bool{"ok.json": true, "../secret.json": false, filepath.Join(root, "secret.json"): false} {
		y := "name: s\ntasks: [a]\nvariants:\n- {name: v, harness: claude, settings: " + settings + "}\n"
		p := filepath.Join(suite, "s.yaml")
		_ = os.WriteFile(p, []byte(y), 0o644)
		if _, err := LoadSuite(p); (err == nil) != ok {
			t.Errorf("settings %q: ok=%v err=%v", settings, ok, err)
		}
	}
}

func TestCloneArgs(t *testing.T) {
	got := strings.Join(gitCloneArgs("https://x/y.git", "/d"), " ")
	want := "-c protocol.allow=never -c protocol.https.allow=always -c protocol.ssh.allow=always clone --quiet --depth 1 -- https://x/y.git /d"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

type envSpy struct{ agent, plain int }

func (s *envSpy) Exec(context.Context, Command) (ExecResult, error) {
	s.plain++
	return ExecResult{}, nil
}
func (s *envSpy) ExecAgent(context.Context, Command) (ExecResult, error) {
	s.agent++
	return ExecResult{Stdout: []byte(`{"type":"result"}`)}, nil
}
func (s *envSpy) Close() error { return nil }

type spyRunner struct{ e *envSpy }

func (r spyRunner) Start(context.Context, Job) (Env, error) { return r.e, nil }

func TestSecretsOnlyInAgentStep(t *testing.T) {
	spy := &envSpy{}
	task := &Task{ID: "t", Repo: "r", Prompt: "p", Check: "true", Setup: []string{"a", "b"}}
	RunTrial(context.Background(), spyRunner{spy}, fakeDriver{}, task, Variant{Name: "v", Harness: "fake"}, 0)
	if spy.agent != 1 || spy.plain != 3 { // 2 setup + 1 check via plain Exec
		t.Fatalf("agent=%d plain=%d", spy.agent, spy.plain)
	}
}

func TestDockerExecEnvArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake docker is a #!/bin/sh script, which Windows cannot exec")
	}
	bin := filepath.Join(t.TempDir(), "docker")
	log := bin + ".log"
	_ = os.WriteFile(bin, []byte("#!/bin/sh\necho \"$@\" >> "+log+"\ncase \"$2\" in *:*) mkdir -p \"$3\";; esac # docker cp out creates its destination\n"), 0o755)
	e := &dockerEnv{d: &DockerRunner{Bin: bin}, bin: bin, name: "c", passEnv: []string{"KEY"}, tmp: t.TempDir()}
	_, _ = e.Exec(context.Background(), sh("x"))
	_, _ = e.ExecAgent(context.Background(), sh("y"))
	b, _ := os.ReadFile(log)
	var execs []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasPrefix(l, "exec ") {
			execs = append(execs, l)
		}
	}
	if len(execs) != 2 || strings.Contains(execs[0], "KEY") || !strings.Contains(execs[1], "-e KEY") {
		t.Fatalf("unexpected exec args: %q", execs)
	}
}

// Setup, agent and check each run in a fresh container: the previous one is
// removed (all its processes die) and only /work is carried over; secrets
// reach the agent's container only.
func TestDockerPhasesUseFreshContainers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake docker is a #!/bin/sh script, which Windows cannot exec")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "docker")
	log := bin + ".log"
	_ = os.WriteFile(bin, []byte("#!/bin/sh\necho \"$@\" >> "+log+"\ncase \"$2\" in *:*) mkdir -p \"$3\";; esac # docker cp out creates its destination\n"), 0o755)
	taskDir := filepath.Join(dir, "task")
	if err := os.MkdirAll(filepath.Join(taskDir, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: "t", Repo: "repo", Dir: taskDir, Prompt: "p", Check: "true", Setup: []string{"s1", "s2"}}
	RunTrial(context.Background(), &DockerRunner{Bin: bin, PassEnv: []string{"KEY"}}, fakeDriver{}, task, Variant{Name: "v", Harness: "fake"}, 0)
	b, _ := os.ReadFile(log)
	var verbs, names []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(l)
		verbs = append(verbs, f[0])
		switch f[0] {
		case "run":
			names = append(names, f[4])
		case "exec":
			isAgent := strings.Contains(l, "-e KEY")
			if isAgent != (len(names) == 2) {
				t.Errorf("secrets in wrong container (%d): %s", len(names), l)
			}
		}
	}
	want := "run cp exec exec cp rm run cp exec cp rm run cp exec rm"
	if got := strings.Join(verbs, " "); got != want {
		t.Fatalf("docker calls\n got %s\nwant %s", got, want)
	}
	if len(names) != 3 || names[0] == names[1] || names[1] == names[2] {
		t.Fatalf("containers not fresh per phase: %v", names)
	}
	if !strings.Contains(string(b), "rm -f "+names[1]) || !strings.Contains(string(b), "cp "+names[1]+":/work/. ") {
		t.Fatalf("agent container not snapshotted and removed:\n%s", b)
	}
}
