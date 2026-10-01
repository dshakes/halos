package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite the shipped unit files from the templates")

// The shipped unit files are the golden files: they must equal the render.
func TestPlanServiceGolden(t *testing.T) {
	for _, tc := range []struct{ goos, exe, golden string }{
		{"linux", "", "packaging/halod.service"},
		{"linux", "/usr/bin/halod", "../../deploy/packaging/halod.service"}, // deb/rpm/apk
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
	var out bytes.Buffer
	if err := runService(context.Background(), "linux", root, "", "install", false, &out, run); err != nil {
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
	if err := runService(context.Background(), "linux", root, "", "install", true, &out, run); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, "|"); got != "systemctl daemon-reload|systemctl enable --now halod" {
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
