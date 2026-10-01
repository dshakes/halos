package bundle

import (
	"context"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2/content/memory"

	"github.com/halos-dev/halos/internal/policy"
	"github.com/halos-dev/halos/internal/release"
)

func expOrg(status string) *policy.Org {
	p := func(n, v string) *policy.Profile {
		return &policy.Profile{Meta: policy.Meta{Name: n}, Harnesses: map[string]policy.HarnessSpec{"bundletest": {Version: v}}}
	}
	return &policy.Org{
		Name:     "acme",
		Profiles: map[string]*policy.Profile{"base": p("base", "1.0.0"), "next": p("next", "2.0.0")},
		Rings:    []*policy.Ring{{Meta: policy.Meta{Name: "ga"}, Profile: "base"}, {Meta: policy.Meta{Name: "other"}, Profile: "base"}},
		Experiments: []*policy.Experiment{{
			Meta: policy.Meta{Name: "cli"}, Type: policy.ExperimentAB, Axis: policy.AxisClient, Status: status, Rings: []string{"ga"},
			Variants: []policy.Variant{{Name: "control", Weight: 1, Profile: "base"}, {Name: "treatment", Weight: 1, Profile: "next"}},
		}},
	}
}

func buildRing(t *testing.T, status, ver string) (*release.Release, []*release.Release) {
	t.Helper()
	rel, vs, err := release.BuildRing(expOrg(status), "ga", release.Options{Version: ver, Org: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	return rel, vs
}

func TestPublishPromoteRefreshRing(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	const ctl, trt = "ga.x-cli.control", "ga.x-cli.treatment"
	pull := func(ch string) (*release.Release, Pointer) {
		t.Helper()
		rel, p, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: ch, Now: time.Now()})
		if err != nil {
			t.Fatalf("pull %s: %v", ch, err)
		}
		return rel, p
	}

	r1, v1 := buildRing(t, "running", "1.0.0")
	if _, chans, err := PublishRing(ctx, store, r1, v1, s, "ga", nil); err != nil || strings.Join(chans, ",") != ctl+","+trt {
		t.Fatalf("publish: %v %v", chans, err)
	}
	for _, ch := range []string{ctl, trt} {
		rel, p := pull(ch)
		if p.Ring != ch || rel.Manifest.Experiment != "cli" || rel.Manifest.Version != "1.0.0-x-cli."+strings.TrimPrefix(ch, "ga.x-cli.") {
			t.Fatalf("%s serves %+v", ch, rel.Manifest)
		}
	}
	if rel, _ := pull("ga"); rel.Digest != r1.Digest {
		t.Fatal("ring not published")
	}

	// 1.1.0: experiment paused -> ring release lists no channels; old channels stay (unused).
	r2, v2 := buildRing(t, "paused", "1.1.0")
	if _, chans, err := PublishRing(ctx, store, r2, v2, s, "ga", nil); err != nil || len(chans) != 0 {
		t.Fatalf("publish paused: %v %v", chans, err)
	}
	_, trtBefore := pull(trt)

	// rollback to 1.0.0: ring AND both channels re-pointed, seqs increase.
	ps, err := PromoteRing(ctx, store, Source{Version: "1.0.0"}, "ga", s, nil)
	if err != nil || len(ps) != 3 || ps[0].Ring != "ga" || ps[0].Digest != r1.Digest {
		t.Fatalf("rollback: %v %+v", err, ps)
	}
	if rel, p := pull(trt); p.Seq <= trtBefore.Seq || rel.Manifest.Version != "1.0.0-x-cli.treatment" {
		t.Fatalf("treatment channel after rollback: seq %d (was %d) %s", p.Seq, trtBefore.Seq, rel.Manifest.Version)
	}

	// refresh: ring + every channel its current release routes to.
	ps, err = RefreshRing(ctx, store, "ga", s, nil)
	if err != nil || len(ps) != 3 || ps[1].Ring != ctl || ps[2].Ring != trt {
		t.Fatalf("refresh: %v %+v", err, ps)
	}

	// promote across rings: channels stay with the ring they were built for.
	ps, err = PromoteRing(ctx, store, Source{Ring: "ga"}, "other", s, nil)
	if err != nil || len(ps) != 1 {
		t.Fatalf("cross-ring promote: %v %+v", err, ps)
	}
}

func TestChannelBindingRefusals(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	r1, v1 := buildRing(t, "running", "1.0.0")
	tests := []struct {
		name string
		do   func() error
		want string
	}{
		{"variant on the ring", func() error { _, err := Publish(ctx, store, v1[1], s, "ga"); return err }, "may only be served on channel"},
		{"variant on another channel", func() error { _, err := Publish(ctx, store, v1[1], s, "ga.x-cli.control"); return err }, "may only be served on channel"},
		{"missing variant", func() error { _, _, err := PublishRing(ctx, store, r1, v1[:1], s, "ga", nil); return err }, "no variant release"},
		{"foreign variant", func() error {
			_, ov := buildRing(t, "running", "2.0.0") // same channel, other ring version
			_, _, err := PublishRing(ctx, store, r1, []*release.Release{v1[0], ov[1]}, s, "ga", nil)
			return err
		}, "not listed by the ring release manifest"},
		{"ring release on the wrong ring", func() error { _, _, err := PublishRing(ctx, store, r1, v1, s, "other", nil); return err }, "lists experiments for ring ga"},
		{"tag too long", func() error {
			_, err := Publish(ctx, store, mkRel(t, strings.Repeat("9", 130), "ga"), s)
			return err
		}, "not a valid OCI tag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.do()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error ~%q, got %v", tt.want, err)
			}
		})
	}
	// A ring pointer that names a variant release is refused by PullRing (a
	// publisher bug or a key-holder mistake must not reach devices).
	if _, _, err := PublishRing(ctx, store, r1, v1, s, "ga", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := PromoteRing(ctx, store, Source{Version: "1.0.0-x-cli.treatment"}, "ga", s, nil); err == nil {
		t.Fatal("promoted a variant release onto the ring")
	}
	if _, _, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: "ga.x-cli.treatment", Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
}
