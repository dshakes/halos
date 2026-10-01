package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Real npm refuses the same file as both --userconfig and --globalconfig
// ("double-loading config"), which broke every codex/gemini-cli install
// (found by scripts/smoke-claude.sh).
func TestNPMInstallDistinctEmptyConfigs(t *testing.T) {
	root := t.TempDir()
	c := nodeCandidates["linux"][0]
	for _, p := range c {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var args []string
	a := &Agent{Root: root, Cfg: Config{OS: "linux"}, Run: func(_ context.Context, _ string, as ...string) ([]byte, error) {
		args = as
		return nil, nil
	}}
	if err := a.npmInstall(context.Background(), t.TempDir(), "/x.tgz"); err != nil {
		t.Fatal(err)
	}
	flag := map[string]string{}
	for i := 0; i+1 < len(args); i++ {
		flag[args[i]] = args[i+1]
	}
	u, g := flag["--userconfig"], flag["--globalconfig"]
	if u == "" || g == "" || u == g {
		t.Fatalf("--userconfig %q --globalconfig %q: must be two distinct files (args %v)", u, g, args)
	}
	for _, f := range []string{u, g} {
		if b, err := os.ReadFile(f); err != nil || len(b) != 0 {
			t.Fatalf("%s: want an existing empty file (%v)", f, err)
		}
	}
}
