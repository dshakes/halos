package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// printWarnings collapses a harness's adapter warnings into a count unless
// verbose, and never touches warnings that carry no harness prefix.
func TestPrintWarningsGroupsByHarness(t *testing.T) {
	var ws []string
	for i := 0; i < 11; i++ {
		ws = append(ws, fmt.Sprintf("gemini-cli/darwin: gemini: setting %d is not supported", i))
	}
	ws = append(ws, "claude-code/darwin: one caveat", "cursor-agent 1.0 is installed but not pinned: do X")

	var b bytes.Buffer
	a := &app{out: &b, errw: &b}
	a.printWarnings(ws, false)
	got := b.String()
	for _, want := range []string{"gemini-cli: 11 adapter warnings", "--verbose", "claude-code/darwin: one caveat", "cursor-agent 1.0 is installed but not pinned: do X"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "setting 3 ") {
		t.Errorf("individual gemini warnings printed without --verbose:\n%s", got)
	}

	b.Reset()
	a.printWarnings(ws, true)
	if n := strings.Count(b.String(), "warning:"); n != len(ws) {
		t.Errorf("verbose printed %d warnings, want %d", n, len(ws))
	}
}

func TestDiffSummary(t *testing.T) {
	diff := "release version:  -> 1\nharness h: added (version 1)\n\n+++ h/darwin /a (new file)\n+x\n+y\n\n--- h/darwin /b\n+++ h/darwin /b\n-old\n+new\n+newer\n\n--- h/darwin /c (removed)\n"
	got := strings.Join(diffSummary(strings.Split(strings.TrimRight(diff, "\n"), "\n")), "\n")
	for _, want := range []string{"summary: 3 file(s) changed", "h/darwin /a (new file): +2 -0", "h/darwin /b: +2 -1", "h/darwin /c (removed): +0 -0"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if diffSummary([]string{"release version: 1 -> 2"}) != nil {
		t.Error("summary for a diff with no files")
	}
}

// halo plan reads "(none)" for a first release's empty side and leads with a
// summary; the JSON diff keeps its original text.
func TestPlanTextSummaryAndNone(t *testing.T) {
	code, out, errOut := halo(t, "plan", "--policy-dir", "../../examples/acme-corp", "--ring", "ring1-canary")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.HasPrefix(out, "summary: ") || !strings.Contains(out, "release version: (none) -> ") {
		t.Fatalf("text plan:\n%.400s", out)
	}
	_, js, _ := halo(t, "plan", "--policy-dir", "../../examples/acme-corp", "--ring", "ring1-canary", "--output", "json")
	if !strings.Contains(js, "release version:  -") || strings.Contains(js, "release version: (none)") {
		t.Fatalf("json diff changed:\n%.300s", js)
	}
}
