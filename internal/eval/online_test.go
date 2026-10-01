package eval

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/shadow"
)

type fakePairs []shadow.Pair

func (f fakePairs) Pairs(context.Context) ([]shadow.Pair, error) { return f, nil }

func side(variant, text string, status int) shadow.Side {
	return shadow.Side{Target: shadow.Target{Variant: variant}, Status: status, Response: json.RawMessage(`{"text":"` + text + `"}`)}
}

func pair(id, exp, ctl, cand string) shadow.Pair {
	return shadow.Pair{ID: id, Experiment: exp, Request: json.RawMessage(`{"messages":[]}`),
		Control: side("control", ctl, 200), Candidate: side("sonnet-next", cand, 200)}
}

// scoreByText scores a response 0.9 if it says "good", 0.5 if "ok", else a
// schema-violating reply when it says "garble".
func scoreByText(r LLMRequest) (string, error) {
	switch {
	case strings.Contains(r.Prompt, "garble"):
		return "I think it's fine", nil
	case strings.Contains(r.Prompt, `"good"`):
		return `{"scores": {"correctness": 0.9, "minimality": 0.9}, "rationale": "good"}`, nil
	}
	return `{"scores": {"correctness": 0.5, "minimality": 0.5}, "rationale": "ok"}`, nil
}

func TestRunOnline(t *testing.T) {
	src := fakePairs{
		pair("p1", "sonnet-next-shadow", "ok", "good"),
		pair("p2", "sonnet-next-shadow", "ok", "good"),
		pair("p3", "sonnet-next-shadow", "good", "good"),
		pair("p4", "sonnet-next-shadow", "ok", "garble"), // judge schema failure
		pair("p5", "other", "good", "ok"),
	}
	errored := pair("p6", "sonnet-next-shadow", "ok", "good")
	errored.Candidate.Status, errored.Candidate.Error = 529, "overloaded"
	src = append(src, errored)

	llm := &fakeLLM{reply: scoreByText}
	o := OnlineOptions{Judge: &Judge{LLM: llm, Model: "judge-1"}, Rubric: testRubric(t), Seed: 3}
	rs, err := RunOnline(context.Background(), src, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].Experiment != "other" || rs[1].Experiment != "sonnet-next-shadow" {
		t.Fatalf("results %+v", rs)
	}
	r := rs[1]
	if r.Pairs != 4 || r.Graded != 3 || r.JudgeErrors != 1 || len(r.PairIDs) != 4 {
		t.Fatalf("counts %+v", r)
	}
	if r.CandidateVariant != "sonnet-next" || r.Rubric != "code-quality@1" || r.JudgeModel != "judge-1" {
		t.Fatalf("labels %+v", r)
	}
	// control 0.5,0.5,0.9 ; candidate 0.9 x3 -> delta mean 0.2667, 2 wins + 1 tie.
	if d := r.Candidate - r.Control; d < 0.266 || d > 0.267 || r.WinRate < 0.83 || r.WinRate > 0.84 || r.Delta.CILo < 0 {
		t.Fatalf("scores %+v", r)
	}

	// Sampling is seeded and capped; already-graded pairs are skipped.
	o.Sample, o.Skip = 2, map[string]bool{"p1": true}
	a, _ := RunOnline(context.Background(), src, o)
	b, _ := RunOnline(context.Background(), src, o)
	if strings.Join(a[1].PairIDs, ",") != strings.Join(b[1].PairIDs, ",") || len(a[1].PairIDs) != 2 || strings.Contains(strings.Join(a[1].PairIDs, ","), "p1") {
		t.Fatalf("sample not reproducible or skip ignored: %v vs %v", a[1].PairIDs, b[1].PairIDs)
	}
	if _, err := RunOnline(context.Background(), src, OnlineOptions{}); err == nil {
		t.Fatal("want error without judge")
	}
}

func TestOnlineHistoryAndOTLP(t *testing.T) {
	dir := t.TempDir()
	// Real encrypted pair store round trip.
	key := []byte("0123456789abcdef0123456789abcdef")
	path := filepath.Join(dir, "pairs.jsonl")
	st, err := shadow.NewFileStore(path, shadow.StoreOptions{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []shadow.Pair{pair("a", "e", "ok", "good"), pair("b", "e", "good", "good")} {
		if err := st.Append(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Close()
	if _, err := (FilePairs{Path: path}).Pairs(context.Background()); err == nil {
		t.Fatal("sealed rows without a key must fail, not be skipped")
	}
	o := OnlineOptions{Judge: &Judge{LLM: &fakeLLM{reply: scoreByText}, Model: "judge-1"}, Rubric: testRubric(t)}
	rs, err := RunOnline(context.Background(), FilePairs{Path: path, Keys: [][]byte{key}}, o)
	if err != nil || len(rs) != 1 || rs[0].Graded != 2 {
		t.Fatalf("%+v %v", rs, err)
	}

	hist := filepath.Join(dir, "history.jsonl")
	if err := AppendHistory(hist, HistoryEntry{Time: time.Unix(0, 0), Kind: "online", Online: &rs[0]}); err != nil {
		t.Fatal(err)
	}
	if err := AppendHistory(hist, OfflineHistory(&Scorecard{Suite: "s", Gate: &Gate{Verdict: GateShip}}, time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	seen, err := GradedPairs(hist)
	if err != nil || !seen["a"] || !seen["b"] || len(seen) != 2 {
		t.Fatalf("graded %v %v", seen, err)
	}
	o.Skip = seen
	if again, _ := RunOnline(context.Background(), FilePairs{Path: path, Keys: [][]byte{key}}, o); len(again) != 0 {
		t.Fatalf("history must skip graded pairs: %+v", again)
	}

	var body map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/metrics" {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if err := (&OTLPExporter{URL: srv.URL, Token: "t"}).Export(context.Background(), rs, time.Unix(0, 0), time.Unix(60, 0)); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(body)
	for _, want := range []string{MetricJudgeScore, MetricJudgeDelta, MetricJudgeWinRate, MetricPairsGraded, MetricJudgeErrors,
		`"halo.experiment"`, `"halo.variant"`, `"sonnet-next"`, `"code-quality@1"`, `"aggregationTemporality":1`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("OTLP body missing %s", want)
		}
	}
	if auth != "Bearer t" {
		t.Errorf("auth %q", auth)
	}
	if err := (&OTLPExporter{URL: srv.URL + "/bad"}).Export(context.Background(), rs, time.Unix(0, 0), time.Unix(60, 0)); err == nil {
		t.Error("want HTTP error")
	}
	if !strings.Contains(OnlineTable(rs), "code-quality@1") {
		t.Error("table missing rubric")
	}
}
