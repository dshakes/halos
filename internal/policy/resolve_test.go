package policy

import (
	"fmt"
	"github.com/halos-dev/halos/internal/assign"
	"math"
	"testing"
)

func testOrg() *Org {
	return &Org{
		Name: "t",
		Rings: []*Ring{
			{Meta: Meta{Name: "r0"}, Order: 0, Membership: Membership{Groups: []string{"platform"}}},
			{Meta: Meta{Name: "r1"}, Order: 1, Membership: Membership{Percent: 5}},
			{Meta: Meta{Name: "r2"}, Order: 2, Membership: Membership{Percent: 25}},
			{Meta: Meta{Name: "r3"}, Order: 3, Membership: Membership{Default: true}},
		},
	}
}

func TestResolveRingDistribution(t *testing.T) {
	o := testOrg()
	const n = 100000
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		counts[o.ResolveRing(Subject{ID: fmt.Sprintf("user-%d", i)}).Name]++
	}
	want := map[string]float64{"r1": 0.05, "r2": 0.25, "r3": 0.70}
	for name, w := range want {
		if got := float64(counts[name]) / n; math.Abs(got-w) > 0.005 {
			t.Errorf("%s share = %.4f, want %.2f ±0.005", name, got, w)
		}
	}
	if counts["r0"] != 0 {
		t.Errorf("r0 has no group members but got %d users", counts["r0"])
	}
}

func TestResolveRing(t *testing.T) {
	o := testOrg()
	tests := []struct {
		name string
		s    Subject
		want string
	}{
		{"group wins over hash", Subject{ID: "anyone", Groups: []string{"x", "platform"}}, "r0"},
		{"unrelated group falls through", Subject{ID: "anyone", Groups: []string{"x"}}, o.ResolveRing(Subject{ID: "anyone"}).Name},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := o.ResolveRing(tt.s); got == nil || got.Name != tt.want {
				t.Fatalf("got %v, want %s", got, tt.want)
			}
		})
	}

	t.Run("group wins for every hashed user", func(t *testing.T) {
		for i := 0; i < 2000; i++ {
			if r := o.ResolveRing(Subject{ID: fmt.Sprint(i), Groups: []string{"platform"}}); r.Name != "r0" {
				t.Fatalf("user %d -> %s", i, r.Name)
			}
		}
	})
	t.Run("percent rounds to nearest bucket", func(t *testing.T) {
		// 0.57% is 56.99.. buckets in float; truncation used to drop bucket 56.
		o3 := &Org{Rings: []*Ring{
			{Meta: Meta{Name: "canary"}, Membership: Membership{Percent: 0.57}},
			{Meta: Meta{Name: "ga"}, Membership: Membership{Default: true}},
		}}
		want := map[int]string{0: "canary", 56: "canary", 57: "ga"}
		for i := 0; len(want) > 0 && i < 1_000_000; i++ {
			id := fmt.Sprint(i)
			b := assign.Bucket(ringSalt, id)
			if name, ok := want[b]; ok {
				if got := o3.ResolveRing(Subject{ID: id}).Name; got != name {
					t.Fatalf("bucket %d (user %s) -> %s, want %s", b, id, got, name)
				}
				delete(want, b)
			}
		}
		if len(want) > 0 {
			t.Fatalf("no user found for buckets %v", want)
		}
	})
	t.Run("no default ring yields nil for unclaimed users", func(t *testing.T) {
		o2 := &Org{Rings: []*Ring{{Meta: Meta{Name: "only"}, Membership: Membership{Percent: 1}}}}
		var nils int
		for i := 0; i < 1000; i++ {
			if o2.ResolveRing(Subject{ID: fmt.Sprint(i)}) == nil {
				nils++
			}
		}
		if nils < 900 {
			t.Fatalf("expected most users unclaimed, got %d nil", nils)
		}
	})
	t.Run("zero percent ring claims nobody", func(t *testing.T) {
		o2 := &Org{Rings: []*Ring{
			{Meta: Meta{Name: "zero"}},
			{Meta: Meta{Name: "ga"}, Membership: Membership{Default: true}},
		}}
		for i := 0; i < 1000; i++ {
			if o2.ResolveRing(Subject{ID: fmt.Sprint(i)}).Name != "ga" {
				t.Fatal("zero-percent ring claimed a user")
			}
		}
	})
}

func testExperiment() *Experiment {
	return &Experiment{
		Meta:   Meta{Name: "exp"},
		Status: "running",
		Rings:  []string{"r1"},
		Variants: []Variant{
			{Name: "control", Weight: 90, Control: true},
			{Name: "treat", Weight: 10},
		},
	}
}

func TestResolveVariantGating(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Experiment)
		ring   string
	}{
		{"not running", func(e *Experiment) { e.Status = "paused" }, "r1"},
		{"draft", func(e *Experiment) { e.Status = "draft" }, "r1"},
		{"empty status", func(e *Experiment) { e.Status = "" }, "r1"},
		{"ring not enrolled", func(e *Experiment) {}, "r2"},
		{"no variants", func(e *Experiment) { e.Variants = nil }, "r1"},
		{"zero weights", func(e *Experiment) { e.Variants[0].Weight, e.Variants[1].Weight = 0, 0 }, "r1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := testExperiment()
			tt.mutate(e)
			if v := e.ResolveVariant(Subject{ID: "u"}, tt.ring); v != nil {
				t.Fatalf("got %v, want nil", v.Name)
			}
		})
	}
}

func TestResolveVariantStickyAndDistribution(t *testing.T) {
	e := testExperiment()
	const n = 100000
	treat := 0
	for i := 0; i < n; i++ {
		s := Subject{ID: fmt.Sprintf("user-%d", i)}
		v := e.ResolveVariant(s, "r1")
		if v == nil {
			t.Fatal("nil variant")
		}
		if i < 2000 && e.ResolveVariant(s, "r1") != v {
			t.Fatal("not sticky")
		}
		if v.Name == "treat" {
			treat++
		}
	}
	if got := float64(treat) / n; math.Abs(got-0.10) > 0.005 {
		t.Errorf("treatment share = %.4f, want 0.10 ±0.005", got)
	}
}

func TestResolveVariantSalt(t *testing.T) {
	a, b := testExperiment(), testExperiment()
	b.Name = "other"
	c := testExperiment()
	c.Salt = "exp" // explicit salt equal to name behaves like the default
	diff := 0
	for i := 0; i < 5000; i++ {
		s := Subject{ID: fmt.Sprint(i)}
		if a.ResolveVariant(s, "r1").Name != b.ResolveVariant(s, "r1").Name {
			diff++
		}
		if a.ResolveVariant(s, "r1").Name != c.ResolveVariant(s, "r1").Name {
			t.Fatal("explicit salt == name must match default")
		}
	}
	if diff == 0 {
		t.Fatal("different experiment names should decorrelate assignment")
	}
}
