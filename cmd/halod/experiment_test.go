package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

const (
	pinControl   = "2.1.280"
	pinTreatment = "2.1.312"
	chTreatment  = "canary.x-cli-upgrade.treatment"
)

// expOrg: ring canary (default) runs client-axis experiment cli-upgrade,
// control pinned at 2.1.280, treatment at 2.1.312.
func expOrg(status string) *policy.Org {
	p := func(n, v string) *policy.Profile {
		return &policy.Profile{Meta: policy.Meta{Name: n}, Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: v}}}
	}
	return &policy.Org{
		Name:     "acme",
		Profiles: map[string]*policy.Profile{"base": p("base", pinControl), "next": p("next", pinTreatment)},
		Rings:    []*policy.Ring{{Meta: policy.Meta{Name: "canary"}, Profile: "base", Membership: policy.Membership{Default: true}}},
		Experiments: []*policy.Experiment{{
			Meta: policy.Meta{Name: "cli-upgrade"}, Type: policy.ExperimentAB, Axis: policy.AxisClient, Status: status, Rings: []string{"canary"},
			Variants: []policy.Variant{{Name: "control", Weight: 1, Control: true, Profile: "base"}, {Name: "treatment", Weight: 1, Profile: "next"}},
		}},
	}
}

func (e *env) publishRing(t *testing.T, ver, status string) {
	t.Helper()
	mu.Lock()
	files = func(string) []harness.File {
		return []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`"` + ver + `"`)}}
	}
	mu.Unlock()
	rel, vs, err := release.BuildRing(expOrg(status), "canary", release.Options{Version: ver, Org: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bundle.PublishRing(context.Background(), e.store, rel, vs, e.sign, "canary", nil); err != nil {
		t.Fatal(err)
	}
}

// userIn finds a subject the gateway assigns to the "treatment" variant.
func userIn(t *testing.T) string {
	t.Helper()
	org := expOrg("running")
	for i := 0; i < 1000; i++ {
		u := fmt.Sprintf("dev%d@acme.com", i)
		if gateway.Decide(org, gateway.RequestInfo{UserID: u}).Variant == "treatment" {
			return u
		}
	}
	t.Fatalf("no user hashes to treatment")
	return ""
}

func pinOf(e *env) string {
	s := e.read(settings)
	if i := strings.Index(s, `"requiredMaximumVersion":"`); i >= 0 {
		return strings.SplitN(s[i+len(`"requiredMaximumVersion":"`):], `"`, 2)[0]
	}
	return s
}

// halod picks exactly the variant the gateway attributes, for 10k synthetic
// users: both go through policy.Experiment.ResolveVariant with the same salt
// and weights (halod reads them from the signed manifest).
func TestVariantSelectionMatchesGateway(t *testing.T) {
	e := newEnv(t)
	e.publishRing(t, "1", "running")
	ctx := context.Background()
	src, _ := e.a.Open(ctx)
	org := expOrg("running")
	rel, p, err := bundle.PullRing(ctx, src, e.a.Verifier, bundle.RingOptions{Org: "acme", Ring: "canary", Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for i := 0; i < 10000; i++ {
		u := fmt.Sprintf("user-%d@acme.com", i)
		var st Status
		marks := map[string]PointerMark{"canary": {Seq: p.Seq, Digest: p.Digest}}
		got, err := e.a.selectVariant(ctx, src, &st, State{}, "canary", u, rel, marks, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		d := gateway.Decide(org, gateway.RequestInfo{UserID: u})
		if st.Experiment != d.Experiment || st.Variant != d.Variant || got.Manifest.Variant != d.Variant {
			t.Fatalf("%s: halod %s/%s (release %s), gateway %s/%s", u, st.Experiment, st.Variant, got.Manifest.Variant, d.Experiment, d.Variant)
		}
		if marks[policy.ChannelName("canary", "cli-upgrade", d.Variant)].Seq == 0 {
			t.Fatalf("%s: channel pointer not recorded: %v", u, marks)
		}
		count[d.Variant]++
	}
	if c := count["treatment"]; c < 4700 || c > 5300 {
		t.Fatalf("50/50 split skewed: %v", count)
	}
}

func TestExperimentApplyLifecycle(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.a.Install = false
	e.publishRing(t, "1", "running")

	t.Run("unknown subject stays on the ring release", func(t *testing.T) {
		st, err := e.a.Once(ctx)
		if !errors.Is(err, errNoSubject) || st.ErrorCode != "no_subject_for_experiment" || st.Variant != "" {
			t.Fatalf("err=%v status=%+v", err, st)
		}
		if pinOf(e) != pinControl {
			t.Fatalf("ring release not applied: %s", e.read(settings))
		}
	})

	e.a.Cfg.Subject = userIn(t)
	st, err := e.a.Once(ctx)
	if err != nil || st.Experiment != "cli-upgrade" || st.Variant != "treatment" || pinOf(e) != pinTreatment {
		t.Fatalf("treatment not applied: %v %+v %s", err, st, e.read(settings))
	}
	s := e.a.loadState()
	if s.Pointers["canary"].Seq == 0 || s.Pointers[chTreatment].Digest != s.Digest || s.Subject != e.a.Cfg.Subject {
		t.Fatalf("state %+v", s)
	}

	t.Run("replayed channel pointer refused", func(t *testing.T) {
		old, _ := e.store.Resolve(ctx, bundle.PointerTag(chTreatment))
		e.publishRing(t, "2", "running")
		if _, err := e.a.Once(ctx); err != nil {
			t.Fatal(err)
		}
		applied := e.read(settings)
		cur, _ := e.store.Resolve(ctx, bundle.PointerTag(chTreatment))
		if err := e.store.Tag(ctx, old, bundle.PointerTag(chTreatment)); err != nil {
			t.Fatal(err)
		}
		if _, err := e.a.Once(ctx); err == nil || !strings.Contains(err.Error(), "rollback/replay refused") || e.read(settings) != applied {
			t.Fatalf("replay accepted: %v", err)
		}
		if err := e.store.Tag(ctx, cur, bundle.PointerTag(chTreatment)); err != nil { // operator restores
			t.Fatal(err)
		}
	})

	t.Run("channel pointer signed by another key refused", func(t *testing.T) {
		applied, good := e.read(settings), e.a.loadState()
		evil := memory.New()
		priv, _, _ := bundle.GenerateKeyPair()
		es, _ := bundle.ParseEd25519Signer(priv)
		rel, vs, _ := release.BuildRing(expOrg("running"), "canary", release.Options{Version: "9", Org: "acme"})
		if _, _, err := bundle.PublishRing(ctx, evil, rel, vs, es, "canary", nil); err != nil {
			t.Fatal(err)
		}
		// copy the foreign pointer + release over the genuine channel
		for _, tag := range []string{bundle.PointerTag(chTreatment), bundle.VersionTag("9-x-cli-upgrade.treatment")} {
			if err := copyTag(ctx, evil, e.store, tag); err != nil {
				t.Fatal(err)
			}
		}
		_, err := e.a.Once(ctx)
		if err == nil || !strings.Contains(err.Error(), "channel "+chTreatment) || !strings.Contains(err.Error(), "keeping last-good") {
			t.Fatalf("foreign channel pointer accepted: %v", err)
		}
		if e.read(settings) != applied || e.a.loadState().Digest != good.Digest {
			t.Fatal("tampered channel changed the applied release")
		}
	})

	t.Run("paused experiment converges to the ring release", func(t *testing.T) {
		e2 := newEnv(t)
		e2.a.Install, e2.a.Cfg.Subject = false, userIn(t)
		e2.publishRing(t, "1", "running")
		if _, err := e2.a.Once(ctx); err != nil || pinOf(e2) != pinTreatment {
			t.Fatalf("setup: %v", err)
		}
		e2.publishRing(t, "2", "paused")
		st, err := e2.a.Once(ctx)
		if err != nil || st.Variant != "" || pinOf(e2) != pinControl {
			t.Fatalf("paused: %v %+v %s", err, st, e2.read(settings))
		}
		if e2.a.loadState().Pointers[chTreatment].Seq == 0 {
			t.Fatal("channel anti-rollback mark must survive leaving the experiment")
		}
	})
}

func copyTag(ctx context.Context, src, dst oras.Target, tag string) error {
	_, err := oras.Copy(ctx, src, tag, dst, tag, oras.DefaultCopyOptions)
	return err
}
