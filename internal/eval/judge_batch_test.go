package eval

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const goodReply = `{"scores": {"correctness": 1, "minimality": 1}, "rationale": "ok"}`

// batchServer plays the Batches API: submit, one in-progress poll, then ended
// with results_url. results maps an item index to its JSONL result line body.
func batchServer(t *testing.T, results func(n int) string, resultsHost func(base string) string) (*httptest.Server, *atomic.Int32, *string) {
	t.Helper()
	var polls, realtime atomic.Int32
	var submitted string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages/batches":
			b, _ := io.ReadAll(r.Body)
			submitted = string(b)
			_, _ = w.Write([]byte(`{"id":"msgbatch_1","processing_status":"in_progress"}`))
		case r.URL.Path == "/v1/messages/batches/msgbatch_1":
			status := "in_progress"
			if polls.Add(1) > 1 {
				status = "ended"
			}
			_, _ = fmt.Fprintf(w, `{"id":"msgbatch_1","processing_status":%q,"results_url":%q}`, status, resultsHost(srv.URL)+"/v1/messages/batches/msgbatch_1/results")
		case r.URL.Path == "/v1/messages/batches/msgbatch_1/results":
			_, _ = w.Write([]byte(results(int(polls.Load()))))
		case r.URL.Path == "/v1/messages":
			realtime.Add(1)
			_, _ = w.Write([]byte(`{"content":[{"type":"text","text":` + fmt.Sprintf("%q", goodReply) + `}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &realtime, &submitted
}

func okLine(id string) string {
	return fmt.Sprintf(`{"custom_id":%q,"result":{"type":"succeeded","message":{"content":[{"type":"text","text":%q}],"usage":{"input_tokens":7,"output_tokens":3}}}}`+"\n", id, goodReply)
}

func same(base string) string { return base }

func TestCompleteBatchMapsResultsByCustomID(t *testing.T) {
	// Results arrive out of order and item r1 failed.
	res := okLine("r2") + `{"custom_id":"r1","result":{"type":"errored","error":{"error":{"type":"overloaded_error","message":"busy"}}}}` + "\n" + okLine("r0")
	srv, _, submitted := batchServer(t, func(int) string { return res }, same)
	h := &HTTPLLM{BaseURL: srv.URL, Wire: WireAnthropic, APIKey: "k", PollEvery: time.Millisecond}
	reqs := []LLMRequest{
		{Model: "m", System: strings.Repeat("s", minCacheBytes), Prompt: "a", MaxTokens: 5, CacheSystem: true},
		{Model: "m", System: "s", Prompt: "b", MaxTokens: 5},
		{Model: "m", System: "s", Prompt: "c", MaxTokens: 5},
	}
	got, err := h.CompleteBatch(context.Background(), reqs)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Err != nil || got[0].Text != goodReply || got[0].Usage.InputTokens != 7 || got[0].Tier != TierBatch {
		t.Errorf("item 0: %+v", got[0])
	}
	if got[1].Err == nil || !strings.Contains(got[1].Err.Error(), "overloaded_error") {
		t.Errorf("item 1 want errored, got %+v", got[1])
	}
	if got[2].Err != nil || got[2].Text != goodReply {
		t.Errorf("item 2: %+v", got[2])
	}
	if !strings.Contains(*submitted, `"custom_id":"r2"`) || !strings.Contains(*submitted, `"cache_control":{"type":"ephemeral"}`) {
		t.Errorf("submit body lacks custom_id or cache_control: %.300s", *submitted)
	}
}

func TestCompleteBatchErrors(t *testing.T) {
	t.Run("results_url off gateway host", func(t *testing.T) {
		srv, _, _ := batchServer(t, func(int) string { return "" }, func(string) string { return "https://evil.example" })
		h := &HTTPLLM{BaseURL: srv.URL, Wire: WireAnthropic, PollEvery: time.Millisecond}
		if _, err := h.CompleteBatch(context.Background(), []LLMRequest{{Model: "m"}}); err == nil || !strings.Contains(err.Error(), "not on gateway") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("results_url same host, other scheme", func(t *testing.T) {
		srv, _, _ := batchServer(t, func(int) string { return "" }, func(base string) string { return strings.Replace(base, "http://", "https://", 1) })
		h := &HTTPLLM{BaseURL: srv.URL, Wire: WireAnthropic, PollEvery: time.Millisecond}
		if _, err := h.CompleteBatch(context.Background(), []LLMRequest{{Model: "m"}}); err == nil || !strings.Contains(err.Error(), "not on gateway") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("submit HTTP error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", 500) }))
		defer srv.Close()
		h := &HTTPLLM{BaseURL: srv.URL, Wire: WireAnthropic}
		if _, err := h.CompleteBatch(context.Background(), []LLMRequest{{Model: "m"}}); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancelled while polling", func(t *testing.T) {
		srv, _, _ := batchServer(t, func(int) string { return "" }, same)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h := &HTTPLLM{BaseURL: srv.URL, Wire: WireAnthropic, PollEvery: time.Hour}
		if _, err := h.CompleteBatch(ctx, []LLMRequest{{Model: "m"}}); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("openai wire", func(t *testing.T) {
		if _, err := (&HTTPLLM{Wire: WireOpenAI}).CompleteBatch(context.Background(), nil); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestGradeAllBatchTier(t *testing.T) {
	r := testRubric(t)
	res := okLine("r0") + `{"custom_id":"r1","result":{"type":"expired"}}` + "\n"
	srv, realtime, _ := batchServer(t, func(int) string { return res }, same)
	j := &Judge{LLM: &HTTPLLM{BaseURL: srv.URL, Wire: WireAnthropic, PollEvery: time.Millisecond}, Model: "m", Cache: &JudgeCache{}, Tier: TierBatch}
	got := j.GradeAll(context.Background(), r, [][]Part{in("a"), in("b")})
	if got[0].Err != nil || got[0].Tier != TierBatch || got[0].Verdict.Score != 1 || got[0].Usage.OutputTokens != 3 {
		t.Errorf("item 0: %+v", got[0])
	}
	if got[1].Err == nil || got[1].Tier != TierBatch {
		t.Errorf("item 1 want batch error, got %+v", got[1])
	}
	if realtime.Load() != 0 {
		t.Errorf("realtime calls = %d, want 0", realtime.Load())
	}
	// Item 0 is now cached: a second run is a hit, not a new batch.
	again := j.GradeAll(context.Background(), r, [][]Part{in("a")})
	if !again[0].Verdict.Cached || again[0].Tier != "" {
		t.Errorf("want cache hit, got %+v", again[0])
	}
}

func TestGradeAllFallsBackToRealtime(t *testing.T) {
	r := testRubric(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/messages" {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":` + fmt.Sprintf("%q", goodReply) + `}]}`))
	}))
	defer srv.Close()
	j := &Judge{LLM: &HTTPLLM{BaseURL: srv.URL, Wire: WireAnthropic}, Model: "m", Tier: TierBatch}
	got := j.GradeAll(context.Background(), r, [][]Part{in("a")})
	if got[0].Err != nil || got[0].Tier != TierRealtime {
		t.Fatalf("got %+v", got[0])
	}
}

func TestJudgeConfigTier(t *testing.T) {
	for _, tc := range []struct {
		tier, wire string
		ok         bool
	}{
		{"", WireAnthropic, true}, {TierRealtime, WireOpenAI, true}, {TierBatch, WireAnthropic, true},
		{TierBatch, WireOpenAI, false}, {"bulk", WireAnthropic, false},
	} {
		err := (&JudgeConfig{URL: "https://gw.example", Wire: tc.wire, Model: "m1", Tier: tc.tier}).validate()
		if (err == nil) != tc.ok {
			t.Errorf("tier %q wire %s: err %v, want ok=%v", tc.tier, tc.wire, err, tc.ok)
		}
	}
}
