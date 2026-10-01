package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotHotReload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	org := testOrg()
	write := func(name string, mt time.Time) {
		org.Name = name
		b, _ := json.Marshal(org)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, mt, mt)
	}
	s := NewSnapshot(p)
	if o, err := s.Get(); err == nil || o != nil {
		t.Fatalf("missing file: %v %v", o, err)
	}
	write("v1", time.Now().Add(-time.Hour))
	s.next = time.Time{}
	o, err := s.Get()
	if err != nil || o.Name != "v1" || o.Gateway.Models["sonnet"].Model == "" || len(o.Rings) != 3 {
		t.Fatalf("v1: %+v %v", o, err)
	}
	write("v2", time.Now())
	s.next = time.Time{}
	if o, _ = s.Get(); o.Name != "v2" {
		t.Fatalf("no reload: %s", o.Name)
	}
	// corrupt: keep last good, report error
	_ = os.WriteFile(p, []byte("{"), 0o600)
	s.next = time.Time{}
	o, err = s.Get()
	if err == nil || o == nil || o.Name != "v2" {
		t.Fatalf("corrupt: %v %v", o, err)
	}
}
