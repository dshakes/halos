package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/storage"
)

func appendRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// A crash mid-write leaves a torn last line; the next record must not be glued
// onto it (and lost): a revocation written after restart has to survive.
func TestTornLineThenRevokeSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	d, err := openDeviceStore(storage.Dir(dir), 0)
	if err != nil {
		t.Fatal(err)
	}
	tok, dev, err := d.mint(Principal{ID: "u"}, now)
	if err != nil {
		t.Fatal(err)
	}
	d.log.Close()
	appendRaw(t, filepath.Join(dir, "devices.jsonl"), `{"id":"torn","hash":"x`)

	d2, err := openDeviceStore(storage.Dir(dir), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d2.revoke(dev.ID); err != nil {
		t.Fatal(err)
	}
	d2.log.Close()
	d3, err := openDeviceStore(storage.Dir(dir), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d3.log.Close()
	if _, err := d3.lookup(tok, now); err == nil {
		t.Fatal("revocation lost after torn line + restart")
	}
	if len(d3.byID) != 1 {
		t.Fatalf("devices: %v", d3.byID)
	}
}

func TestTornLineRequests(t *testing.T) {
	dir := t.TempDir()
	l, err := openRequestLog(storage.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	_ = l.save(&Request{ID: "a", Status: StatusPending})
	l.log.Close()
	appendRaw(t, filepath.Join(dir, "requests.jsonl"), `{"id":"b","sta`)
	l2, err := openRequestLog(storage.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.save(&Request{ID: "a", Status: StatusDenied}); err != nil {
		t.Fatal(err)
	}
	l2.log.Close()
	l3, err := openRequestLog(storage.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer l3.log.Close()
	if r := l3.byID["a"]; r == nil || r.Status != StatusDenied || len(l3.byID) != 1 {
		t.Fatalf("after torn line: %+v", l3.byID)
	}
}

func TestOpenJSONLReplayError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "requests.jsonl")
	if err := os.WriteFile(p, make([]byte, 2<<20), 0o600); err != nil { // one 2MB "line": over the scanner limit
		t.Fatal(err)
	}
	if _, err := openRequestLog(storage.Dir(dir)); err == nil {
		t.Fatal("want replay error")
	}
}
