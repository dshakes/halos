package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestDLPReporter(t *testing.T) {
	var mu sync.Mutex
	var batches []DLPBatch
	status := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b DLPBatch
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		defer mu.Unlock()
		batches = append(batches, b)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	r, err := NewDLPReporter(srv.URL, "tok", 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ev := DLPEvent{Subject: "a", Direction: DLPRequest, Action: "monitor", DLPFinding: DLPFinding{Kind: DLPSecret, Detector: "jwt", Hash: "00000000", Location: "x"}}
	r.Report(ev, ev) // the same finding twice: one event
	other := ev
	other.Hash = "11111111"
	r.Report(other)

	// halo-server down: kept and resent under the same batch id.
	if err := r.FlushNow(context.Background()); err == nil {
		t.Fatal("want error while halo-server is down")
	}
	mu.Lock()
	status = http.StatusOK
	mu.Unlock()
	if err := r.FlushNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || batches[0].Batch != batches[1].Batch || len(batches[1].Events) != 2 {
		t.Fatalf("batches %+v", batches)
	}
	if sent, failed, dropped, deduped := r.Counters(); sent != 2 || failed != 1 || dropped != 0 || deduped != 1 {
		t.Fatalf("counters %d %d %d %d", sent, failed, dropped, deduped)
	}

	// A batch halo-server refuses is dropped, not retried forever.
	mu.Lock()
	status = http.StatusUnprocessableEntity
	mu.Unlock()
	third := ev
	third.Hash = "22222222"
	r.Report(third)
	if err := r.FlushNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, dropped, _ := r.Counters(); dropped != 1 {
		t.Fatalf("refused batch: dropped %d", dropped)
	}

	// After the dedup window the same finding is reported again.
	r.Now = func() time.Time { return time.Now().Add(2 * dlpDedupWindow) }
	r.Report(ev)
	r.mu.Lock()
	n := len(r.queue)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("queue %d after the dedup window", n)
	}

	var nilR *DLPReporter
	nilR.Report(ev)
	if err := nilR.FlushNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDLPReporter("http://example.com/x", "t", 0, nil, false); err == nil {
		t.Fatal("plain http to a remote host must be refused")
	}
}

func TestDLPEventsActions(t *testing.T) {
	rep := &DLPReport{SecretAction: "block", InjectionAction: "monitor", Blocked: DLPSecret,
		Findings: []DLPFinding{{Kind: DLPSecret, Detector: "jwt"}, {Kind: DLPInjection, Detector: DLPInjection}}}
	evs := DLPEvents(rep, DLPEvent{Gateway: "halo-proxy"})
	if len(evs) != 2 || evs[0].Action != "block" || evs[1].Action != "monitor" || evs[0].Direction != DLPRequest || evs[0].Gateway != "halo-proxy" {
		t.Fatalf("%+v", evs)
	}
	rep.Blocked, rep.InjectionAction = DLPInjection, "block"
	if evs := DLPEvents(rep, DLPEvent{}); evs[0].Action != "monitor" || evs[1].Action != "block" {
		t.Fatalf("the secret did not block: %+v", evs)
	}
}
