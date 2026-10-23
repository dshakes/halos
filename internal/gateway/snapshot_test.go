package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
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

// A compiled snapshot that never went through `halo validate` still cannot
// activate a security error: a workload rule that pins no tenant, or a unit
// that loosens the baseline. The last good policy keeps serving and the
// refusal is counted.
func TestSnapshotRefusesSecurityErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	s := NewSnapshot(p)
	write := func(o *policy.Org, mt time.Time) {
		b, err := policy.Compile(o)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, mt, mt)
		s.next = time.Time{}
	}
	good := testOrg()
	good.Name = "good"
	write(good, time.Now().Add(-2*time.Hour))
	if o, err := s.Get(); err != nil || o.Name != "good" {
		t.Fatalf("good: %v %v", o, err)
	}
	for i, mod := range []func(o *policy.Org){
		func(o *policy.Org) {
			o.Workloads = &policy.Workloads{Audience: "halos", Issuers: []policy.WorkloadIssuer{{Name: "gh", URL: "https://token.actions.githubusercontent.com"}},
				Rules: []policy.WorkloadRule{{Name: "any-main", Issuer: "gh", Match: map[string]string{"ref": "refs/heads/main"}, Subject: "workload:gh:{repository}"}}}
		},
		func(o *policy.Org) {
			o.Delegation = &policy.Delegation{EnvKeys: []string{"ANTHROPIC_BASE_URL"}}
		},
		func(o *policy.Org) { // an unpinned, plain-http remote agent and an unbounded delegation depth
			o.Agents = &policy.Agents{MaxDepth: 50, Remote: []policy.RemoteAgent{{Name: "x", CardURL: "http://x.example/card", Rings: []string{"ga"}}}}
		},
	} {
		bad := testOrg()
		bad.Name = "bad"
		mod(bad)
		write(bad, time.Now().Add(time.Duration(i-1)*time.Hour))
		o, err := s.Get()
		if err == nil || o == nil || o.Name != "good" {
			t.Fatalf("case %d: security error activated: %v %v", i, o, err)
		}
		if s.Refused() != uint64(i+1) {
			t.Fatalf("case %d: refused %d", i, s.Refused())
		}
	}
}
