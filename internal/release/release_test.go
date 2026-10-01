package release

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

type fakeAdapter struct{ body string }

func (f fakeAdapter) Name() string                       { return "fake" }
func (f fakeAdapter) Capabilities() []harness.Capability { return nil }
func (f fakeAdapter) InstallCommand(v string, os harness.OS) string {
	return "install fake@" + v + " " + string(os)
}
func (f fakeAdapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	return []harness.File{
		{Path: "/etc/fake/z.json", Mode: 0o644, Data: []byte(f.body + "\nring=" + c.Ring + "\n")},
		{Path: "/etc/fake/a.json", Mode: 0o600, Data: []byte("static\n")},
	}, []string{"unsupported: x"}, nil
}

type resolver struct {
	p   *policy.Profile
	err error
}

func (r resolver) ResolveProfile(string) (*policy.Profile, error) { return r.p, r.err }

func init() { harness.Register(fakeAdapter{body: "v1"}) }

func prof(ver string, hs ...string) *policy.Profile {
	p := &policy.Profile{Harnesses: map[string]policy.HarnessSpec{}}
	for _, h := range hs {
		p.Harnesses[h] = policy.HarnessSpec{Version: ver}
	}
	return p
}

func TestBuildDeterministic(t *testing.T) {
	a, err := Build(resolver{p: prof("1.0.0", "fake")}, "p", "canary", Options{Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Build(resolver{p: prof("1.0.0", "fake")}, "p", "canary", Options{Version: "1"})
	if a.Digest != b.Digest || !bytes.Equal(a.Tar, b.Tar) {
		t.Fatal("build not deterministic")
	}
	if got := len(a.Manifest.Harnesses["fake"].Files); got != 3 {
		t.Fatalf("want 3 OSes, got %d", got)
	}
	fs := a.Manifest.Harnesses["fake"].Files["linux"]
	if fs[0].Path != "/etc/fake/a.json" {
		t.Fatalf("files not sorted: %v", fs)
	}
	if len(a.Manifest.Warnings) != 3 || a.Manifest.Harnesses["fake"].InstallCommand["darwin"] != "install fake@1.0.0 darwin" {
		t.Fatalf("warnings/install wrong: %+v", a.Manifest)
	}
	c, _ := Build(resolver{p: prof("1.0.1", "fake")}, "p", "canary", Options{Version: "1"})
	if c.Digest == a.Digest {
		t.Fatal("digest should change with content")
	}
}

func TestBuildErrors(t *testing.T) {
	tests := []struct {
		name string
		r    resolver
		want string
	}{
		{"resolve", resolver{err: errors.New("boom")}, "boom"},
		{"unknown harness", resolver{p: prof("1", "nope")}, "unknown harness"},
	}
	for _, tt := range tests {
		_, err := Build(tt.r, "p", "r", Options{})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v", tt.name, err)
		}
	}
}

func TestOpenRoundTripAndTamper(t *testing.T) {
	r, _ := Build(resolver{p: prof("1.0.0", "fake")}, "p", "canary", Options{})
	o, err := Open(r.Tar)
	if err != nil || o.Digest != r.Digest {
		t.Fatalf("open: %v", err)
	}
	bad := bytes.Replace(r.Tar, []byte("static"), []byte("STATIC"), 1)
	if _, err := Open(bad); err == nil {
		t.Fatal("tampered blob accepted")
	}
	if _, err := Open([]byte("garbage")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestDiff(t *testing.T) {
	a, _ := Build(resolver{p: prof("1.0.0", "fake")}, "p", "r", Options{Version: "1"})
	if d := Diff(a, a); d != "" {
		t.Fatalf("self diff: %q", d)
	}
	b, _ := Build(resolver{p: prof("2.0.0", "fake")}, "p", "canary", Options{Version: "2"})
	d := Diff(a, b)
	for _, want := range []string{"release version: 1 -> 2", "version 1.0.0 -> 2.0.0", "-ring=r", "+ring=canary", "--- fake/linux /etc/fake/z.json"} {
		if !strings.Contains(d, want) {
			t.Errorf("diff missing %q:\n%s", want, d)
		}
	}
}
