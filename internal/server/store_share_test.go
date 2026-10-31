package server

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func shareReport(dev, n int, drift ...string) Host {
	if drift == nil {
		drift = []string{}
	}
	return Host{LastSeen: time.Unix(int64(n), 0), Report: Report{
		Time: time.Unix(int64(n), 0), Hostname: fmt.Sprintf("host-%d", dev), User: "dev@example.com",
		Device: fmt.Sprintf("%08x-0000-4000-8000-%012x", dev, dev), Ring: "ring1-ga", Digest: "sha256:" + fmt.Sprintf("%064x", 7),
		Harnesses: map[string]HarnessStatus{"claude-code": {Want: "2.1.0", Installed: "2.1.0"}}, Drift: drift,
	}}
}

// Successive reports from one device share their unchanged values, and a
// changed value is stored as reported (no report is altered by a neighbour).
func TestLogStoreHistorySharesUnchangedValues(t *testing.T) {
	s := NewMemStore()
	for n := range 3 {
		if err := s.Put(shareReport(1, n)); err != nil {
			t.Fatal(err)
		}
	}
	changed := shareReport(1, 3, "settings.json")
	changed.Digest = "sha256:" + fmt.Sprintf("%064x", 8)
	changed.Harnesses = map[string]HarnessStatus{"claude-code": {Want: "2.2.0", Installed: "2.1.0"}}
	if err := s.Put(changed); err != nil {
		t.Fatal(err)
	}

	hist := s.History(shareReport(1, 0).key()) // newest first
	if len(hist) != 4 {
		t.Fatalf("history has %d reports, want 4", len(hist))
	}
	older := hist[1:]
	for i := 1; i < len(older); i++ {
		if reflect.ValueOf(older[i].Harnesses).Pointer() != reflect.ValueOf(older[0].Harnesses).Pointer() {
			t.Errorf("report %d does not share the harness map of its predecessor", i)
		}
		if unsafe.StringData(older[i].Digest) != unsafe.StringData(older[0].Digest) {
			t.Errorf("report %d does not share the digest string of its predecessor", i)
		}
	}
	if got := hist[0]; got.Digest != changed.Digest || got.Harnesses["claude-code"].Want != "2.2.0" || len(got.Drift) != 1 {
		t.Errorf("a changed report was not stored as reported: %+v", got)
	}
	for _, h := range older {
		if h.Digest != "sha256:"+fmt.Sprintf("%064x", 7) || h.Harnesses["claude-code"].Want != "2.1.0" || len(h.Drift) != 0 {
			t.Errorf("an earlier report was altered by a later one: %+v", h)
		}
	}
}

// The history is what dominated halo-server memory: 50 reports per device.
func TestLogStoreHistoryMemory(t *testing.T) {
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	const devices = 400
	before := heap()
	s := NewMemStore()
	for d := range devices {
		for n := range MaxHistory {
			if err := s.Put(shareReport(d, n)); err != nil {
				t.Fatal(err)
			}
		}
	}
	perDevice := float64(heap()-before) / devices
	runtime.KeepAlive(s)
	t.Logf("%.1f KB per device with %d reports", perDevice/1024, MaxHistory)
	if perDevice > 24*1024 { // 46 KB before values were shared
		t.Fatalf("%.1f KB per device with %d reports in history, want under 24 KB", perDevice/1024, MaxHistory)
	}
}
