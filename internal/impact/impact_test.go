package impact

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/assign"
	"github.com/dshakes/halos/internal/policy"
)

func testOrg(canaryPct, treatment float64, paymentsDeny string) *policy.Org {
	prof := &policy.Profile{Meta: policy.Meta{Name: "base"}, Models: policy.Models{Default: "opus"}}
	return &policy.Org{
		Profiles: map[string]*policy.Profile{"base": prof},
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "ring0"}, Profile: "base", Membership: policy.Membership{Users: []string{"vip@acme"}, Groups: []string{"harness-team"}}},
			{Meta: policy.Meta{Name: "canary"}, Profile: "base", Membership: policy.Membership{Percent: canaryPct}},
			{Meta: policy.Meta{Name: "ga"}, Profile: "base", Membership: policy.Membership{Default: true}},
		},
		Experiments: []*policy.Experiment{{Meta: policy.Meta{Name: "route"}, Status: "running", Axis: policy.AxisTraffic, Rings: []string{"ga"},
			Variants: []policy.Variant{{Name: "ctl", Weight: 100 - treatment, Control: true}, {Name: "new", Weight: treatment}}}},
		Units: []*policy.Unit{{Meta: policy.Meta{Name: "payments"}, Members: policy.UnitMembers{Groups: []string{"payments-eng"}},
			Overlay: policy.Overlay{Permissions: policy.Permissions{Deny: []string{paymentsDeny}}}}},
		Workloads: &policy.Workloads{Rules: []policy.WorkloadRule{{Name: "ci", Subject: "workload:gh:acme/app", Groups: []string{"ci"}}}},
	}
}

// Reference oracles straight from internal/assign (the one hashing source).
func ringBucket(id string) int { return assign.Bucket("halos/rings", id) }

func TestComputeAgainstFixedAssignment(t *testing.T) {
	members := PolicyMembers(2000, testOrg(10, 50, "Bash(rm:*)"))

	// Canary 10% -> 20%: exactly the samples hashed into [1000, 2000) move.
	want := 0
	for _, m := range members {
		if b := ringBucket(m.ID); m.Kind == KindSample && b >= 1000 && b < 2000 {
			want++
		}
	}
	rep := Compute(testOrg(10, 50, "Bash(rm:*)"), testOrg(20, 50, "Bash(rm:*)"), members, 3)
	if got := rep.ByKind[KindSample]; got.Total != 2000 || got.Ring != want || want == 0 {
		t.Fatalf("ring moves = %+v, want %d of 2000", got, want)
	}
	// Leaving ga also leaves its experiment: variant changes cover the movers.
	if got := rep.ByKind[KindSample]; got.Variant != want {
		t.Fatalf("variant changes = %d, want %d (ga movers)", got.Variant, want)
	}
	if rep.ByKind[KindUser].Any != 0 || rep.ByKind[KindAgent].Any != 0 {
		t.Fatalf("pinned users and agents must not move: %+v", rep.ByKind)
	}
	for _, e := range rep.Examples {
		if e.Kind == KindSample { // samples stand for a share; they are never examples
			t.Fatalf("examples: %+v", rep.Examples)
		}
	}

	// Treatment 50% -> 75%: ga members whose pick changes, by assign.Pick.
	rep = Compute(testOrg(10, 50, "Bash(rm:*)"), testOrg(10, 75, "Bash(rm:*)"), members, 0)
	want = 0
	for _, m := range members {
		if m.Kind != KindSample || ringBucket(m.ID) < 1000 {
			continue
		}
		if assign.Pick("route", m.ID, []float64{50, 50}) != assign.Pick("route", m.ID, []float64{25, 75}) {
			want++
		}
	}
	if got := rep.ByKind[KindSample]; got.Variant != want || got.Ring != 0 || got.Settings != 0 || want == 0 {
		t.Fatalf("variant moves = %+v, want %d", got, want)
	}
	if got := rep.ByKind[KindAgent]; got.Variant != 0 {
		t.Fatalf("workloads are not enrolled in experiments: %+v", got)
	}

	// A unit overlay change reaches only that unit's members.
	rep = Compute(testOrg(10, 50, "Bash(rm:*)"), testOrg(10, 50, "Bash(curl:*)"), members, 5)
	for _, u := range rep.ByUnit {
		if (u.Unit == "payments") != (u.Settings > 0) || u.Ring != 0 || u.Variant != 0 {
			t.Fatalf("unit %q: %+v", u.Unit, u.Counts)
		}
	}
	if len(rep.Examples) != 1 || rep.Examples[0].ID != "member-of:payments-eng" || !rep.Examples[0].Settings || rep.Examples[0].Unit != "payments" {
		t.Fatalf("examples: %+v", rep.Examples)
	}
	if txt := rep.Text("main"); !strings.Contains(txt, "payments") || !strings.Contains(txt, "effective settings change") {
		t.Fatalf("text:\n%s", txt)
	}

	// No change, no impact.
	rep = Compute(testOrg(10, 50, "x"), testOrg(10, 50, "x"), members, 5)
	for k, c := range rep.ByKind {
		if c.Any != 0 {
			t.Fatalf("%s changed without a change: %+v", k, c)
		}
	}
}

func TestFleetMembers(t *testing.T) {
	hosts := []FleetHost{
		{Hostname: "a1", User: "al@acme", Device: "d1"},
		{Hostname: "a2", User: "al@acme", Device: "d2"},
		{Hostname: "b1", User: "bo@acme", Device: "d3"},
		{Hostname: "ci", User: ""}, // fleet-token host without a user
	}
	devs := []FleetDevice{{ID: "d1", UserID: "al@acme", Groups: []string{"payments-eng"}}, {ID: "d2", UserID: "al@acme"}, {ID: "d3", UserID: "bo@acme", Revoked: true}}
	ms := FleetMembers(hosts, devs, testOrg(10, 50, "x"))
	kinds := map[string]int{}
	for _, m := range ms {
		kinds[m.Kind]++
		if m.Kind == KindUser && m.ID == "al@acme" && (len(m.Groups) != 1 || m.Groups[0] != "payments-eng") {
			t.Fatalf("user groups are the union of their devices': %+v", m)
		}
	}
	if kinds[KindDevice] != 2 || kinds[KindUser] != 1 || kinds[KindAgent] != 1 {
		t.Fatalf("members: %+v", ms)
	}
	rep := Compute(testOrg(10, 50, "a"), testOrg(10, 50, "b"), ms, 10)
	if rep.ByKind[KindDevice].Settings != 1 || rep.ByKind[KindUser].Settings != 1 {
		t.Fatalf("payments overlay reaches al's payments device and al: %+v", rep.ByKind)
	}
}

func TestCheckoutAt(t *testing.T) {
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	sub := filepath.Join(repo, "policy")
	if err := os.MkdirAll(filepath.Join(sub, "rings"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "rings", "ga.yaml"), []byte("v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("init", "-q")
	git("config", "user.name", "t")
	git("config", "user.email", "t@t")
	git("add", ".")
	git("commit", "-qm", "v1")
	if err := os.WriteFile(filepath.Join(sub, "rings", "ga.yaml"), []byte("v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, cleanup, err := CheckoutAt(context.Background(), sub, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if b, err := os.ReadFile(filepath.Join(dir, "rings", "ga.yaml")); err != nil || string(b) != "v1\n" {
		t.Fatalf("base content %q %v", b, err)
	}
	if b, _ := os.ReadFile(filepath.Join(sub, "rings", "ga.yaml")); string(b) != "v2\n" {
		t.Fatal("working tree touched")
	}
	for _, bad := range []string{"", "--output=/tmp/x", "HEAD:secret", "no-such-ref"} {
		if _, _, err := CheckoutAt(context.Background(), sub, bad); err == nil {
			t.Errorf("ref %q accepted", bad)
		}
	}
}

// TestUntarCapsTheStream: headers count too, so a flood of empty entries is
// refused at the cap rather than read to the end.
func TestUntarCapsTheStream(t *testing.T) {
	defer func(n int64) { maxArchive = n }(maxArchive)
	maxArchive = 8 << 10
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range 64 {
		_ = tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("f%d", i), Mode: 0o600, Typeflag: tar.TypeReg})
	}
	_ = tw.Close()
	if err := untar(&buf, t.TempDir()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("uncapped stream: %v", err)
	}
}

func TestUntarRefusesEscapes(t *testing.T) {
	for _, name := range []string{"../evil.yaml", "/etc/evil.yaml", "a/../../evil.yaml",
		`..\evil.yaml`, `a\..\..\evil.yaml`, `C:\evil.yaml`, `C:evil.yaml`, "rings/ga.yaml:stream", `\\host\share\evil.yaml`} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
		_ = tw.Close()
		if err := untar(&buf, t.TempDir()); err == nil {
			t.Errorf("%s extracted", name)
		}
	}
}
