package bundle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/release"
)

// A registry-level attacker can move any tag. Promote must follow the source
// ring's SIGNED pointer, and rollback must get the version it asked for.
func TestPromoteRollbackIgnoreRetaggedTags(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, _ := keys(t)
	r1, r2 := mkRel(t, "1", "ga"), mkRel(t, "2", "ga")
	for _, r := range []*release.Release{r1, r2} {
		if _, err := Publish(ctx, store, r, s, "canary"); err != nil {
			t.Fatal(err)
		}
	}
	d1, err := store.Resolve(ctx, VersionTag("1"))
	if err != nil {
		t.Fatal(err)
	}
	// attacker: ring-canary and v2 now name the older, genuinely signed v1
	for _, tag := range []string{RingTag("canary"), VersionTag("2")} {
		if err := store.Tag(ctx, d1, tag); err != nil {
			t.Fatal(err)
		}
	}

	var announced []string
	o := &PointerOptions{BeforeSign: func(p Pointer, ver string) { announced = append(announced, p.Ring+"="+ver+"@"+p.Digest) }}
	ps, err := PromoteRing(ctx, store, Source{Ring: "canary"}, "ga", s, o)
	if err != nil || ps[0].Digest != r2.Digest {
		t.Fatalf("promote followed the retagged ring tag: %v %+v", err, ps)
	}
	if strings.Join(announced, ",") != "ga=2@"+r2.Digest {
		t.Fatalf("BeforeSign: %v", announced)
	}

	tests := []struct {
		name string
		src  Source
		o    *PointerOptions
		want string
	}{
		{"retagged version", Source{Version: "2"}, nil, "registry retag refused"},
		{"expect-digest mismatch", Source{Ring: "canary"}, &PointerOptions{ExpectDigest: r1.Digest}, "expected " + r1.Digest},
		{"no source", Source{}, nil, "exactly one"},
		{"two sources", Source{Ring: "canary", Version: "1"}, nil, "exactly one"},
		{"bad digest", Source{Manifest: "sha256:nope"}, nil, "manifest digest"},
		{"source ring without pointer", Source{Ring: "nope"}, nil, "no signed pointer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PromoteRing(ctx, store, tt.src, "ga", s, tt.o); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error ~%q, got %v", tt.want, err)
			}
		})
	}
	// by content address and by honest version: fine (memory.Store only
	// resolves tags; a real registry resolves digest references natively)
	if err := store.Tag(ctx, d1, d1.Digest.String()); err != nil {
		t.Fatal(err)
	}
	if ps, err := PromoteRing(ctx, store, Source{Manifest: d1.Digest.String()}, "ga", s, &PointerOptions{ExpectDigest: r1.Digest}); err != nil || ps[0].Digest != r1.Digest {
		t.Fatalf("rollback by digest: %v %+v", err, ps)
	}
	if ps, err := PromoteRing(ctx, store, Source{Version: "1"}, "ga", s, nil); err != nil || ps[0].Digest != r1.Digest {
		t.Fatalf("rollback by version: %v %+v", err, ps)
	}
}

// A replayed (older, validly signed) pointer served before refresh must not be
// laundered into a fresh one.
func TestRefreshRefusesReplayedPointer(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, _ := keys(t)
	st, err := LoadPointerState(filepath.Join(t.TempDir(), "halos", "pointers.json"), "reg/acme")
	if err != nil {
		t.Fatal(err)
	}
	withState := &PointerOptions{State: st}
	r1, r2 := mkRel(t, "1", "ga"), mkRel(t, "2", "ga")
	if _, _, err := PublishRing(ctx, store, r1, nil, s, "ga", withState); err != nil {
		t.Fatal(err)
	}
	old, err := store.Resolve(ctx, PointerTag("ga"))
	if err != nil {
		t.Fatal(err)
	}
	withState.now = time.Now().Add(2 * time.Second) // strictly newer seq than the first write
	if _, _, err := PublishRing(ctx, store, r2, nil, s, "ga", withState); err != nil {
		t.Fatal(err)
	}
	withState.now = time.Time{}
	cur, err := store.Resolve(ctx, PointerTag("ga"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, old, PointerTag("ga")); err != nil { // attacker replays p1
		t.Fatal(err)
	}
	reloaded, err := LoadPointerState(st.path, "reg/acme") // state survives the process
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		do   func() error
		want string
	}{
		{"refresh with state", func() error { _, err := RefreshRing(ctx, store, "ga", s, &PointerOptions{State: reloaded}); return err }, "replayed/rolled-back pointer refused"},
		{"refresh stateless with expect-digest", func() error {
			_, err := RefreshRing(ctx, store, "ga", s, &PointerOptions{ExpectDigest: r2.Digest})
			return err
		}, "expected " + r2.Digest},
		{"promote from replayed ring", func() error {
			_, err := PromoteRing(ctx, store, Source{Ring: "ga"}, "other", s, withState)
			return err
		}, "replayed"},
		{"rollback over replayed pointer", func() error {
			_, err := PromoteRing(ctx, store, Source{Version: "2"}, "ga", s, withState)
			return err
		}, "replayed"},
		{"publish over replayed pointer", func() error {
			_, _, err := PublishRing(ctx, store, mkRel(t, "3", "ga"), nil, s, "ga", withState)
			return err
		}, "replayed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.do(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error ~%q, got %v", tt.want, err)
			}
		})
	}
	if _, err := store.Resolve(ctx, VersionTag("3")); err == nil {
		t.Fatal("refused publish still pushed v3 (preflight must run first)")
	}

	// genuine pointer restored: refresh works and advances the state
	if err := store.Tag(ctx, cur, PointerTag("ga")); err != nil {
		t.Fatal(err)
	}
	before, _ := st.Mark("ga")
	ps, err := RefreshRing(ctx, store, "ga", s, &PointerOptions{State: st, ExpectDigest: r2.Digest})
	if err != nil || ps[0].Digest != r2.Digest {
		t.Fatalf("refresh: %v %+v", err, ps)
	}
	if m, _ := st.Mark("ga"); m.Seq != ps[0].Seq || m.Seq <= before.Seq || m.Digest != r2.Digest {
		t.Fatalf("state not advanced: %+v (was %+v)", m, before)
	}
}

func TestRefreshRefusesExpiredPointer(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, _ := keys(t)
	stale := &PointerOptions{now: time.Now().Add(-DefaultPointerTTL - time.Hour)}
	if _, _, err := PublishRing(ctx, store, mkRel(t, "1", "ga"), nil, s, "ga", stale); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshRing(ctx, store, "ga", s, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("refreshed an expired pointer: %v", err)
	}
	if _, err := PromoteRing(ctx, store, Source{Ring: "ga"}, "other", s, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("promoted from an expired pointer: %v", err)
	}
	// recovery: an explicit version is still allowed
	if _, err := PromoteRing(ctx, store, Source{Version: "1"}, "ga", s, nil); err != nil {
		t.Fatalf("explicit rollback over expired pointer: %v", err)
	}
}

func TestWriteRefusesForeignOrg(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, _ := keys(t)
	if _, err := Publish(ctx, store, mkRel(t, "1", "ga"), s, "ga"); err != nil {
		t.Fatal(err)
	}
	evil, err := release.Build(res{}, "p", "ga", release.Options{Version: "2", Org: "evil"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(ctx, store, evil, s); err != nil { // same key, other org, no ring
		t.Fatal(err)
	}
	if _, err := PromoteRing(ctx, store, Source{Version: "2"}, "ga", s, nil); err == nil || !strings.Contains(err.Error(), `for org "acme"`) {
		t.Fatalf("cross-org promote: %v", err)
	}
}

func TestPointerStateCheck(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadPointerState(filepath.Join(dir, "p.json"), "reg/a")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.record("ga", Pointer{Seq: 10, Digest: "d10"}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		cur   Pointer
		found bool
		want  string // "" = accepted
	}{
		{"same pointer", Pointer{Seq: 10, Digest: "d10"}, true, ""},
		{"newer (another signer)", Pointer{Seq: 11, Digest: "d11"}, true, ""},
		{"older seq", Pointer{Seq: 9, Digest: "d10"}, true, "replayed"},
		{"same seq other digest", Pointer{Seq: 10, Digest: "dX"}, true, "wrote"},
		{"pointer gone", Pointer{}, false, "no pointer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := st.check("ga", tt.cur, tt.found)
			if (tt.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
		})
	}
	if err := st.check("canary", Pointer{Seq: 1}, true); err != nil {
		t.Fatalf("unrecorded ring: %v", err)
	}
	other, err := LoadPointerState(st.path, "reg/b") // other repo: separate marks
	if err != nil {
		t.Fatal(err)
	}
	if err := other.check("ga", Pointer{Seq: 1}, true); err != nil {
		t.Fatalf("scope leak: %v", err)
	}
	if err := os.WriteFile(st.path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPointerState(st.path, "reg/a"); err == nil || !strings.Contains(err.Error(), "parse pointer state") {
		t.Fatalf("corrupt state: %v", err)
	}
	if _, err := LoadPointerState(filepath.Join(dir, "missing.json"), "reg/a"); err != nil {
		t.Fatalf("missing state is empty: %v", err)
	}
}

// A state file with no record of a served pointer (new runner, evicted cache)
// must not silently disable replay protection.
func TestContinuityUnknownPointerNeedsAdoption(t *testing.T) {
	st, err := LoadPointerState(filepath.Join(t.TempDir(), "pointers.json"), "repo")
	if err != nil {
		t.Fatal(err)
	}
	served := Pointer{Ring: "ga", Seq: 7, Digest: "sha256:aa"}
	if err := (PointerOptions{State: st}).continuity("ga", served, true); err == nil || !strings.Contains(err.Error(), "--adopt-existing") {
		t.Fatalf("unknown served pointer accepted: %v", err)
	}
	if err := (PointerOptions{State: st, AdoptExisting: true}).continuity("ga", served, true); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if err := (PointerOptions{State: st, ExpectDigest: "sha256:aa"}).continuity("ga", served, true); err != nil {
		t.Fatalf("pinned by expect-digest: %v", err)
	}
	if err := (PointerOptions{State: st}).continuity("ga", Pointer{}, false); err != nil {
		t.Fatalf("first publish of a new ring: %v", err)
	}
}

// ADR-0008 (8c): seq = max(served+1, unix now), also with signer state.
func TestPointerSeqIsMaxOfServedPlusOneAndNow(t *testing.T) {
	ctx := context.Background()
	s, v := keys(t)
	st, err := LoadPointerState(filepath.Join(t.TempDir(), "pointers.json"), "reg/acme")
	if err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]*PointerOptions{"stateless": {}, "with state": {State: st}} {
		t.Run(name, func(t *testing.T) {
			store := memory.New()
			t0 := time.Unix(2_000_000_000, 0)
			steps := []struct {
				now  time.Time
				want uint64
			}{
				{t0, 2_000_000_000},                       // no pointer yet: now
				{t0, 2_000_000_001},                       // clock not past served: served+1
				{t0.Add(-time.Hour), 2_000_000_002},       // clock went back: still served+1
				{t0.Add(time.Hour), 2_000_000_000 + 3600}, // clock ahead: now
			}
			for i, step := range steps {
				o.now = step.now
				if _, _, err := PublishRing(ctx, store, mkRel(t, "1", "ga"), nil, s, "ga", o); err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
				p, found, err := ReadPointer(ctx, store, "ga", v)
				if err != nil || !found || p.Seq != step.want {
					t.Fatalf("step %d: seq %d (found %v, err %v), want %d", i, p.Seq, found, err, step.want)
				}
			}
		})
	}
}

// ADR-0008 addendum (8n): a failed state save after the push says so.
func TestPointerStateSaveFailureReportsPublished(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, _ := keys(t)
	dir := t.TempDir()
	st, err := LoadPointerState(filepath.Join(dir, "sub", "pointers.json"), "reg/acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub"), nil, 0o600); err != nil { // parent is a file: save fails
		t.Fatal(err)
	}
	_, _, err = PublishRing(ctx, store, mkRel(t, "1", "ga"), nil, s, "ga", &PointerOptions{State: st})
	if err == nil || !strings.Contains(err.Error(), "was published but the signer state was not updated") {
		t.Fatalf("got %v", err)
	}
	if _, err := store.Resolve(ctx, PointerTag("ga")); err != nil {
		t.Fatalf("pointer should be on the registry: %v", err)
	}
}
