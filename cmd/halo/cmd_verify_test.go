package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOnboardVerifyExitCodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub CLI")
	}
	for _, tc := range []struct {
		name     string
		env      map[string]string
		script   string
		wantCode int
		wantOut  string
	}{
		{"all skipped", nil, "echo 2.1.280", exitUnverified, "verified 0 of 1 (1 skipped)"},
		{"one verified", map[string]string{"ANTHROPIC_API_KEY": "sk-test-not-real"}, "echo HALOS_OK", 0, "verified 1 of 1"},
		{"one failed", map[string]string{"ANTHROPIC_API_KEY": "sk-test-not-real"}, "echo nope", exitError, "verified 0 of 1 (1 failed)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\n"+tc.script+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+"/usr/bin:/bin")
			for _, c := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"} {
				t.Setenv(c, tc.env[c])
			}
			code, out, errs := halo(t, "onboard", "verify", "claude-code")
			if code != tc.wantCode || !strings.Contains(out, tc.wantOut) {
				t.Fatalf("exit %d, want %d; want %q in:\n%s%s", code, tc.wantCode, tc.wantOut, out, errs)
			}
		})
	}
}
