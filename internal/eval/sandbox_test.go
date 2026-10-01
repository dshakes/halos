package eval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDocker logs every call; the codex sandbox probe exits with probeExit
// (and prints Landlock's failure), everything else succeeds like a stub daemon.
func fakeDocker(t *testing.T, probeExit string) (bin, log string) {
	t.Helper()
	bin, log = fakeDockerCLI(t)
	t.Setenv("FAKE_DOCKER_PROBE_EXIT", probeExit)
	return bin, log
}

func sandboxTask(t *testing.T) *Task {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Task{ID: "t", Repo: "repo", Dir: dir, Prompt: "p", Check: "true"}
}

func TestCodexLandlockPreflight(t *testing.T) {
	codex := Variant{Name: "codex", Harness: "codex", Version: "0.99.0"}
	for _, tc := range []struct {
		name        string
		probeExit   string
		variant     Variant
		unavailable bool
		errSub      string
		probes      int // probe calls for two trials
	}{
		{"no landlock: unmeasurable, probed once", "101", codex, true, "error: sandbox unavailable (Landlock) (docker runner: sandbox unavailable (Landlock): codex probe exit 101: error applying legacy Linux sandbox restrictions: Sandbox(LandlockRestrict))", 1},
		{"landlock ok: trials run, probed once", "0", codex, false, "", 1},
		{"docker failure is infra, not Landlock, and retried", "125", codex, false, "start: docker runner: sandbox preflight", 2},
		{"other harnesses are not probed", "101", Variant{Name: "c", Harness: "claude"}, false, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, log := fakeDocker(t, tc.probeExit)
			r := &DockerRunner{Bin: bin}
			var trials []Trial
			for i := range 2 {
				trials = append(trials, RunTrial(context.Background(), r, fakeDriver{}, sandboxTask(t), tc.variant, i))
			}
			b, _ := os.ReadFile(log)
			calls := string(b)
			if n := strings.Count(calls, " sandbox linux "); n != tc.probes {
				t.Fatalf("probes %d, want %d:\n%s", n, tc.probes, calls)
			}
			for _, tr := range trials {
				if (tr.Unavailable != "") != tc.unavailable || tr.Pass && tc.unavailable || !strings.Contains(tr.Error, tc.errSub) {
					t.Fatalf("trial %+v", tr)
				}
			}
			if tc.unavailable && strings.Contains(calls, "run -d") {
				t.Fatalf("an unmeasurable cell must not start trial containers:\n%s", calls)
			}
			if strings.Contains(calls, "danger-full-access") || strings.Contains(calls, "--dangerously") {
				t.Fatalf("invariant 1: never bypass the sandbox:\n%s", calls)
			}
			if tc.probes > 0 && !strings.Contains(calls, "--cap-drop=ALL --security-opt=no-new-privileges") {
				t.Fatalf("probe must run hardened like a trial:\n%s", calls)
			}
		})
	}
}

// A cell the host cannot measure holds the gate and never reads as 0%.
func TestUnavailableCellHolds(t *testing.T) {
	s := gateSuite(t, Thresholds{})
	var trials []Trial
	for _, task := range []string{"a", "b"} {
		trials = append(trials, arm("base", task, 0.1, 100, true, true, true)...)
		for r := range 3 {
			trials = append(trials, Trial{Task: task, Variant: "cand", Repeat: r, Unavailable: ErrSandboxUnavailable.Error(),
				Error: "error: sandbox unavailable (Landlock): codex probe exit 101"})
		}
	}
	sc, err := BuildScorecard(s, trials, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := sc.Comparisons[0]
	if c.Gate.Verdict != GateHold || sc.Gate.Verdict != GateHold || !strings.Contains(strings.Join(c.Gate.Reasons, "|"), "6/6 trials unmeasurable (sandbox unavailable (Landlock))") {
		t.Fatalf("gate %+v", c.Gate)
	}
	v := sc.Variants[1]
	if v.Unavailable != 6 || v.UnavailableReason != "sandbox unavailable (Landlock)" {
		t.Fatalf("variant %+v", v)
	}
	for _, out := range []string{sc.Markdown(), sc.Table()} {
		rows := 0
		for _, l := range strings.Split(out, "\n") {
			if !strings.HasPrefix(l, "| cand |") && !strings.HasPrefix(l, "cand ") {
				continue
			}
			rows++
			if !strings.Contains(l, "error: sandbox unavailable (Landlock)") && !strings.Contains(l, "unmeasurable") || strings.Contains(l, "0%") || strings.Contains(l, "0.0 pp") {
				t.Fatalf("cand row %q in:\n%s", l, out)
			}
		}
		if rows == 0 {
			t.Fatalf("no cand row in:\n%s", out)
		}
	}
	// Partially unmeasurable control: still hold, stats from measured trials only.
	trials = append(arm("base", "a", 0.1, 100, true, true), Trial{Task: "a", Variant: "base", Repeat: 2, Unavailable: "sandbox unavailable (Landlock)"})
	trials = append(trials, arm("cand", "a", 0.1, 100, true, true, true)...)
	sc, err = BuildScorecard(s, trials, 1)
	if err != nil || sc.Gate.Verdict != GateHold || sc.Variants[0].Pass1 != 1 || sc.Variants[0].CostPerTask != 0.1 {
		t.Fatalf("partial: %+v %v", sc, err)
	}
}

// DefaultSandboxProbes is pinned to a real run (uat-clis): this exact argv, in
// ghcr.io/dshakes/eval-codex:0.99.0 on Docker Desktop (kernel 6.10.14-linuxkit,
// no Landlock), exited 101 with Sandbox(LandlockRestrict). A fake docker
// replays that output; the runner must build the same command and classify it
// as unavailable. (The rc=0 case on a Landlock host is not recorded.)
func TestSandboxProbeMatchesRecordedRun(t *testing.T) {
	rec, err := os.ReadFile(filepath.Join("testdata", "codex", "sandbox-probe-no-landlock.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(rec), "\n")
	recorded := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(lines[0], "$ docker "), "#", 2)[0])
	stderr := strings.Join(lines[2:5], "\n")
	if lines[5] != "rc=101" || !strings.Contains(stderr, "Sandbox(LandlockRestrict)") {
		t.Fatalf("fixture shape changed:\n%s", rec)
	}
	help := string(rec)
	if !strings.Contains(help, "linux    Run a command under Landlock+seccomp") || !strings.Contains(help, "Usage: codex sandbox linux [OPTIONS] [COMMAND]...") ||
		!strings.Contains(help, "--full-auto") || !strings.Contains(help, "network-disabled sandbox") {
		t.Fatal("codex sandbox linux --help no longer documents the probe")
	}
	dir := t.TempDir()
	bin, log := fakeDockerCLI(t)
	errf := filepath.Join(dir, "stderr")
	_ = os.WriteFile(errf, []byte(stderr+"\n"), 0o644)
	t.Setenv("FAKE_DOCKER_STDERR_FILE", errf) // replayed on every call, exit 101
	r := &DockerRunner{Bin: bin}
	err = r.preflight(context.Background(), Variant{Harness: "codex", Version: "0.99.0"})
	if !errors.Is(err, ErrSandboxUnavailable) || !strings.Contains(err.Error(), "Sandbox(LandlockRestrict)") {
		t.Fatalf("recorded no-Landlock output must classify as unavailable: %v", err)
	}
	got, _ := os.ReadFile(log)
	if strings.TrimSpace(string(got)) != recorded {
		t.Fatalf("probe argv drifted from the verified run:\n got %s\nwant %s", strings.TrimSpace(string(got)), recorded)
	}
	if strings.Contains(recorded, "danger-full-access") {
		t.Fatal("invariant 1")
	}
}
