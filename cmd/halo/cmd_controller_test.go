package main

import (
	"strings"
	"testing"
)

func TestControllerRunFlags(t *testing.T) {
	_, out, _ := halo(t, "controller", "run", "--help")
	if !strings.Contains(out, "--killswitch-served") || !strings.Contains(out, "--verdicts-file") || strings.Contains(out, "--controller-interval") || strings.Contains(out, "--verdicts ") {
		t.Fatalf("help: %s", out)
	}
	// The deprecated halo-server spelling binds the same interval.
	for _, flag := range []string{"--interval", "--controller-interval"} {
		code, _, errOut := halo(t, "controller", "run", "--policy-dir", example, "--data-dir", t.TempDir(), "--clickhouse", "http://127.0.0.1:1", flag, "5s")
		if code == 0 || !strings.Contains(errOut, "at least 1m") {
			t.Fatalf("%s 5s: %d %s", flag, code, errOut)
		}
	}
}
