package bundle

import (
	"context"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// TestStageCandidate: a pointerless publish plus a channel publish leave
// every ring pointer where it was; the channel pointer names the variant.
func TestStageCandidate(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	if _, found, err := ServedPointer(ctx, store, s, "ga"); err != nil || found {
		t.Fatalf("unpublished ring: found=%v err=%v", found, err)
	}
	base := mkRel(t, "1", "ga")
	if _, err := Publish(ctx, store, base, s, "ga"); err != nil {
		t.Fatal(err)
	}
	cand := mkRel(t, "cand", "ga")
	if already, err := Stage(ctx, store, cand, s); err != nil || already { // no rings: no pointer
		t.Fatalf("stage: %v %v", already, err)
	}
	time.Sleep(1100 * time.Millisecond) // a re-push would get a new manifest creation time
	if already, err := Stage(ctx, store, cand, s); err != nil || !already {
		t.Fatalf("re-stage the same release: %v %v", already, err)
	}
	other := mkRel(t, "cand", "canary") // same label, different bytes
	if _, err := Stage(ctx, store, other, s); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("different release under the same label: %v", err)
	}
	vr, err := release.Build(res{}, "p", "canary", release.Options{Version: "cand-x-up.next", Org: "acme", Experiment: "up", Variant: "next"})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := PublishChannel(ctx, store, vr, s, nil)
	if err != nil || ch != policy.ChannelName("canary", "up", "next") {
		t.Fatalf("channel %q: %v", ch, err)
	}
	if p, found, err := ServedPointer(ctx, store, s, "ga"); err != nil || !found || p.Digest != base.Digest {
		t.Fatalf("ga moved: %+v %v %v", p, found, err)
	}
	if _, found, _ := ReadPointer(ctx, store, "canary", v); found {
		t.Fatal("canary ring pointer written")
	}
	if p, found, err := ReadPointer(ctx, store, ch, v); err != nil || !found || p.Digest != vr.Digest {
		t.Fatalf("channel pointer %+v %v %v", p, found, err)
	}
	if again, err := PublishChannel(ctx, store, vr, s, nil); err != nil || again != ch { // re-run: already staged, no re-push
		t.Fatalf("re-publish the same channel release: %v", err)
	}
	if _, err := PublishChannel(ctx, store, cand, s, nil); err == nil || !strings.Contains(err.Error(), "variant release") {
		t.Fatalf("ring release on a channel: %v", err)
	}
}
