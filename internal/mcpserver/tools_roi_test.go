package mcpserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/roi"
)

// roiData writes a 300-developer roster and three merged PRs each.
func roiData(t *testing.T, start time.Time) (roster, store string) {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("login,subject\n")
	var prs []roi.PR
	for i := range 300 {
		fmt.Fprintf(&b, "gh%d,dev%d@acme.com\n", i, i)
		for j := range 3 {
			o := start.Add(time.Duration(24*(i%20)+j) * time.Hour)
			m := o.Add(time.Duration(5+i%7) * time.Hour)
			prs = append(prs, roi.PR{Source: "github", Repo: "acme/api", Number: int64(3*i + j + 1), Author: fmt.Sprintf("gh%d", i), OpenedAt: o, MergedAt: &m, ReviewRounds: 1})
		}
	}
	prs = append(prs, roi.PR{Source: "github", Repo: "acme/api", Number: 9999, Author: "contractor", OpenedAt: start.Add(time.Hour)})
	roster, store = filepath.Join(dir, "roster.csv"), filepath.Join(dir, "prs.jsonl")
	if err := os.WriteFile(roster, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (roi.FileStore{Path: store}).Put(context.Background(), prs); err != nil {
		t.Fatal(err)
	}
	return roster, store
}

func TestROIReportTool(t *testing.T) {
	start := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Hour)
	roster, store := roiData(t, start)

	off, err := call(t, connect(t, Options{PolicyDir: example}), "roi_report", map[string]any{"experiment": "claude-cli-2.1.3xx-ab"})
	if err != nil {
		t.Fatal(err)
	}
	if off["configured"] != false || !strings.Contains(fmt.Sprint(off["next_steps"]), "--roi-identities") {
		t.Fatalf("unconfigured: %v", off)
	}

	cs := connect(t, Options{PolicyDir: example, ROIIdentities: roster, ROIStore: store})
	since := start.Format(time.DateOnly)
	tests := []struct {
		name   string
		args   map[string]any
		design string
		next   string
	}{
		{"experiment", map[string]any{"experiment": "claude-cli-2.1.3xx-ab", "since": since}, roi.DesignRandomized, "contractor"},
		{"rings", map[string]any{"rings": []string{"ring3-ga", "ring1-canary"}, "since": since}, roi.DesignObservational, "associations only"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := call(t, cs, "roi_report", tc.args)
			if err != nil {
				t.Fatal(err)
			}
			rep := out["report"].(map[string]any)
			if rep["design"] != tc.design || len(rep["effects"].([]any)) == 0 {
				t.Fatalf("report %v", rep)
			}
			if !strings.Contains(fmt.Sprint(out["next_steps"]), tc.next) {
				t.Fatalf("next_steps %v lack %q", out["next_steps"], tc.next)
			}
		})
	}
	for name, args := range map[string]map[string]any{
		"unknown experiment":          {"experiment": "nope", "since": since},
		"no since without clickhouse": {"experiment": "claude-cli-2.1.3xx-ab"},
		"both":                        {"experiment": "claude-cli-2.1.3xx-ab", "rings": []string{"ring1-canary", "ring3-ga"}, "since": since},
	} {
		if _, err := call(t, cs, "roi_report", args); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// propose_promotion carries the ROI section (dated from ClickHouse's first
// telemetry) in its preview; it is informational and the verdict stays the
// ClickHouse one.
func TestProposePromotionROISection(t *testing.T) {
	start := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Hour)
	roster, store := roiData(t, start)
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "AS start") {
			fmt.Fprintf(w, `{"n":10,"start":%d,"spend":0}`+"\n", start.Unix())
		}
	}))
	t.Cleanup(ch.Close)
	cs := connect(t, Options{PolicyDir: copyExample(t), AllowWrites: true, ClickHouse: &promote.ClickHouse{URL: ch.URL}, ROIIdentities: roster, ROIStore: store})
	out, err := call(t, cs, "propose_promotion", map[string]any{"experiment": "claude-cli-2.1.3xx-ab", "ring": "ring1-canary", "release": "sha256:abc", "reason": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := out["roi"].(string); !strings.Contains(s, "### Delivery ROI (randomized, informational)") || out["verdict"] == "promote" || out["applied"] != false {
		t.Fatalf("out %v", out)
	}
}
