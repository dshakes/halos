package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite the shipped unit files from the templates")

// The shipped unit files are the golden files: they must equal the render.
func TestPlanServiceGolden(t *testing.T) {
	for _, tc := range []struct{ goos, exe, golden string }{
		{"linux", "", "../../deploy/packaging/halod.service"}, // deb/rpm/apk: defaultExe is /usr/bin/halod
		{"darwin", "", "packaging/dev.halos.halod.plist"},
	} {
		spec, err := planService(tc.goos, tc.exe)
		if err != nil {
			t.Fatal(err)
		}
		if *updateGolden {
			if err := os.WriteFile(tc.golden, []byte(spec.Content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(tc.golden)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Content != string(want) {
			t.Errorf("%s/%s: render differs from %s (go test ./cmd/halod -run Golden -update)\n%s", tc.goos, tc.exe, tc.golden, spec.Content)
		}
	}
}

func TestPlanServiceErrors(t *testing.T) {
	for _, tc := range []struct{ goos, exe string }{
		{"plan9", ""},
		{"linux", "/x\n[Service]\nExecStart=/bin/sh"},
		{"windows", `C:\a" /RU x`},
	} {
		if _, err := planService(tc.goos, tc.exe); err == nil {
			t.Errorf("planService(%q, %q): want error", tc.goos, tc.exe)
		}
	}
}

func TestPlanServiceWindows(t *testing.T) {
	spec, err := planService("windows", "")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(spec.Install[0], " ")
	for _, w := range []string{"/RU SYSTEM", "/SC ONSTART", `"C:\Program Files\Halos\halod.exe" run --config "C:\Program Files\Halos\etc\halod.yaml"`} {
		if !strings.Contains(got, w) {
			t.Errorf("schtasks args %q missing %q", got, w)
		}
	}
	if spec.Path != "" {
		t.Errorf("windows writes no unit file, got %q", spec.Path)
	}
}

func TestRunService(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, a ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(a, " "))
		return nil, nil
	}
	root := t.TempDir()
	exe := trustedExe(t)
	var out bytes.Buffer
	if err := runService(context.Background(), "linux", root, exe, "install", false, &out, run); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(root, systemdPath)
	if _, err := os.Stat(unit); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, "|"); got != "systemctl daemon-reload" {
		t.Errorf("install without --start ran %q", got)
	}
	calls = nil
	if err := runService(context.Background(), "linux", root, exe, "install", true, &out, run); err != nil {
		t.Fatal(err)
	}
	// restart, not enable --now: a service already running from a previous install applies now.
	if got := strings.Join(calls, "|"); got != "systemctl daemon-reload|systemctl enable halod|systemctl restart halod" {
		t.Errorf("install --start ran %q", got)
	}
	if err := runService(context.Background(), "linux", root, "", "uninstall", false, &out, run); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Errorf("unit not removed: %v", err)
	}
	if err := runService(context.Background(), "linux", root, "", "bogus", false, &out, run); err == nil {
		t.Error("unknown action: want error")
	}
	if err := runService(context.Background(), "windows", root, "", "print", false, &out, run); err == nil {
		t.Error("windows print: want error")
	}
}

// trustedExe is a file in a dir the test user owns (trusted via trustedUID in TestMain).
func trustedExe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "halod")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckExe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership/mode semantics")
	}
	if err := checkExe(trustedExe(t)); err != nil {
		t.Fatalf("trusted exe refused: %v", err)
	}
	if err := checkExe(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing exe accepted")
	}
	// group/other-writable binary
	loose := trustedExe(t)
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkExe(loose); err == nil || !strings.Contains(err.Error(), "group/other-writable") {
		t.Errorf("world-writable exe accepted: %v", err)
	}
	// world-writable parent dir
	dir := filepath.Join(t.TempDir(), "w")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	inLoose := filepath.Join(dir, "halod")
	if err := os.WriteFile(inLoose, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkExe(inLoose); err == nil {
		t.Error("exe in world-writable dir accepted")
	}
	// a trusted-looking symlink to an exe in a loose dir is judged by its target
	link := filepath.Join(t.TempDir(), "halod")
	if err := os.Symlink(inLoose, link); err != nil {
		t.Fatal(err)
	}
	if err := checkExe(link); err == nil {
		t.Error("symlink to untrusted exe accepted")
	}
	// owner is someone other than root
	old := trustedUID
	trustedUID = 4242424
	defer func() { trustedUID = old }()
	if err := checkExe(trustedExe(t)); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("user-owned exe accepted: %v", err)
	}
}

func TestServiceInstallRefusesUntrustedExe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership/mode semantics")
	}
	exe := trustedExe(t)
	if err := os.Chmod(exe, 0o777); err != nil {
		t.Fatal(err)
	}
	var calls int
	run := func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }
	root := t.TempDir()
	err := runService(context.Background(), runtime.GOOS, root, exe, "install", true, io.Discard, run)
	if err == nil || !strings.Contains(err.Error(), "insecure halod binary") {
		t.Fatalf("untrusted --exe accepted: %v", err)
	}
	if calls != 0 {
		t.Errorf("ran %d commands despite refusal", calls)
	}
	if _, serr := os.Stat(filepath.Join(root, systemdPath)); serr == nil {
		t.Error("unit written despite refusal")
	}
}

func TestRunRefusesUntrustedSelf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership/mode semantics")
	}
	old := trustedUID
	trustedUID = 4242424 // the test binary is owned by the test user, not "root"
	defer func() { trustedUID = old }()
	for _, cmd := range []string{"run", "once"} {
		err := run([]string{cmd, "-config", filepath.Join(t.TempDir(), "halod.yaml")}, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "insecure halod binary") {
			t.Errorf("%s: untrusted halod binary accepted: %v", cmd, err)
		}
	}
}

// Re-installing over a loaded daemon or running task must not fail: the stop
// step is best effort (its error is ignored) and runs before registration.
func TestServiceInstallIsIdempotent(t *testing.T) {
	for _, c := range []struct{ goos, stop, install, start string }{
		{"darwin", "launchctl bootout system/dev.halos.halod", "launchctl bootstrap system " + launchdPath, ""},
		{"windows", "schtasks /End /TN Halos", "schtasks /Create", "schtasks /Run /TN Halos"},
	} {
		var calls []string
		run := func(_ context.Context, name string, a ...string) ([]byte, error) {
			cmd := name + " " + strings.Join(a, " ")
			calls = append(calls, cmd)
			if strings.HasPrefix(cmd, c.stop) {
				return []byte("Boot-out failed: 3: No such process"), errors.New("exit status 3")
			}
			return nil, nil
		}
		exe := "/x/halod" // only checked when goos is the running OS
		if c.goos == runtime.GOOS {
			exe = trustedExe(t)
		}
		if err := runService(context.Background(), c.goos, t.TempDir(), exe, "install", true, io.Discard, run); err != nil {
			t.Fatalf("%s: %v", c.goos, err)
		}
		if len(calls) < 2 || !strings.HasPrefix(calls[0], c.stop) || !strings.HasPrefix(calls[1], c.install) {
			t.Errorf("%s: stop must precede install, got %q", c.goos, calls)
		}
		if c.start != "" && calls[len(calls)-1] != c.start {
			t.Errorf("%s: --start must end with %q, got %q", c.goos, c.start, calls)
		}
	}
}
