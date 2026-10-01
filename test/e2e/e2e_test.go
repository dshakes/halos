//go:build e2e

// Package e2e drives the real Halos binaries (built fresh by TestMain)
// against a real OCI registry, a mock OIDC issuer and mock LLM upstreams.
//
//	make e2e      # go test -tags e2e ./test/e2e/... -v -timeout 20m
//
// Needs Docker for the registry:2 container, unless HALO_E2E_REGISTRY names a
// running one (CI uses a service container). Every container started here is
// labelled halos-e2e=1 and removed on exit (scripts/e2e.sh also sweeps).
package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	binDir   string // freshly built binaries
	repoRoot string
	registry string // host:port of a plain-HTTP registry:2
)

// binaries built by TestMain: name -> package (+ build tags).
var binaries = map[string][]string{
	"halo":        {"./cmd/halo"},
	"halod":       {"./cmd/halod", "halodtest"}, // halodtest: allows SYD_TEST_TRUST_SELF (unprivileged --root sandbox)
	"halod-prod":  {"./cmd/halod"},              // release build: must refuse the same sandbox
	"halo-proxy":  {"./cmd/halo-proxy"},
	"halo-shadow": {"./cmd/halo-shadow"},
	"halo-server": {"./cmd/halo-server"},
	"mockllm":     {"./deploy/compose/mockllm"},
}

func TestMain(m *testing.M) { os.Exit(mainE2E(m)) }

func mainE2E(m *testing.M) int {
	var err error
	if os.Getenv("HALO_OBS_E2E") == "1" { // scripts/obs-e2e.sh: obs_test.go needs no registry or prebuilt binaries
		return m.Run()
	}
	if repoRoot, err = filepath.Abs("../.."); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if binDir, err = os.MkdirTemp("", "halo-e2e-bin-"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(binDir)
	// halo's signer state (pointers.json) goes under XDG_STATE_HOME: keep it per run.
	if err := os.Setenv("XDG_STATE_HOME", filepath.Join(binDir, "state")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for name, spec := range binaries {
		args := []string{"build", "-o", filepath.Join(binDir, name)}
		if len(spec) > 1 {
			args = append(args, "-tags", spec[1])
		}
		cmd := exec.Command("go", append(args, spec[0])...)
		cmd.Dir, cmd.Stdout, cmd.Stderr = repoRoot, os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: build %s: %v\n", name, err)
			return 1
		}
	}
	registry = os.Getenv("HALO_E2E_REGISTRY")
	if registry == "" {
		id, addr, err := startRegistry()
		if err != nil {
			fmt.Fprintln(os.Stderr, "e2e:", err)
			return 1
		}
		rm := func() { _ = exec.Command("docker", "rm", "-f", id).Run() }
		defer rm()
		sig := make(chan os.Signal, 1) // Ctrl-C: still tear the registry down
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() { <-sig; rm(); os.Exit(130) }()
		registry = addr
	}
	if err := waitHTTP("http://"+registry+"/v2/", 200, 60*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: registry:", err)
		return 1
	}
	return m.Run()
}

func startRegistry() (id, addr string, err error) {
	out, err := exec.Command("docker", "run", "-d", "--rm", "--label", "halos-e2e=1", "-p", "127.0.0.1::5000", "registry:2").Output()
	if err != nil {
		return "", "", fmt.Errorf("docker run registry:2: %w (set HALO_E2E_REGISTRY to use an existing registry)", err)
	}
	id = strings.TrimSpace(string(out))
	port, err := exec.Command("docker", "port", id, "5000/tcp").Output()
	if err != nil {
		_ = exec.Command("docker", "rm", "-f", id).Run()
		return "", "", fmt.Errorf("docker port: %w", err)
	}
	// "127.0.0.1:55012" (first line)
	addr = strings.TrimSpace(strings.SplitN(string(port), "\n", 2)[0])
	return id, addr, nil
}

// ---- process helpers ----

type result struct {
	stdout, stderr string
	code           int
}

func (r result) String() string {
	return fmt.Sprintf("exit=%d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
}

// run executes a built binary to completion. env entries are KEY=VALUE.
func run(t *testing.T, env []string, stdin string, name string, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(binDir, name), args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	r := result{stdout: so.String(), stderr: se.String()}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	case err != nil:
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return r
}

// must runs and fails the test on a non-zero exit.
func must(t *testing.T, env []string, name string, args ...string) result {
	t.Helper()
	r := run(t, env, "", name, args...)
	if r.code != 0 {
		t.Fatalf("%s %s: %s", name, strings.Join(args, " "), r)
	}
	return r
}

// syncBuf is a goroutine-safe log sink for background processes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// start launches a long-running binary, killed at test cleanup; its output is
// dumped if the test failed.
func start(t *testing.T, env []string, name string, args ...string) *syncBuf {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, name), args...)
	cmd.Env = append(os.Environ(), env...)
	log := &syncBuf{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("---- %s output ----\n%s", name, log.String())
		}
	})
	return log
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitHTTP(url string, want int, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last string
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == want {
				return nil
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s: want %d, last %s", url, want, last)
}

func waitUp(t *testing.T, url string, want int) {
	t.Helper()
	if err := waitHTTP(url, want, 20*time.Second); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func replaceIn(t *testing.T, path, old, new string) {
	t.Helper()
	s := readFile(t, path)
	if !strings.Contains(s, old) {
		t.Fatalf("%s: %q not found in:\n%s", path, old, s)
	}
	writeFile(t, path, strings.Replace(s, old, new, 1))
}

// repoName is a registry path unique to this test run.
func repoName(t *testing.T) string {
	return fmt.Sprintf("%s/e2e-%d/%s", registry, time.Now().UnixNano(), strings.ToLower(t.Name()))
}
