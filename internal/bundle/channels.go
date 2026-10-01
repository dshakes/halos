package bundle

import (
	"context"
	"fmt"
	"regexp"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/halos-dev/halos/internal/policy"
	"github.com/halos-dev/halos/internal/release"
)

// Client-axis experiment channels. A ring release whose manifest lists
// client-axis experiments is published together with one variant release per
// variant, each behind its own signed pointer on channel
// policy.ChannelName(ring, experiment, variant) (tag "ring-<channel>.pointer").
// A channel pointer is an ordinary pointer whose Ring field is the channel
// name, so it is bound to org + channel exactly as a ring pointer is bound to
// org + ring, and halod keeps a separate anti-rollback mark per channel.
// Ring-wide operations (PublishRing, PromoteRing, RefreshRing) move the ring
// and all of its channels together so they never drift apart.

// tagRe is the OCI distribution-spec tag grammar.
var tagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

func checkTag(tag string) error {
	if !tagRe.MatchString(tag) {
		return fmt.Errorf("bundle: %q is not a valid OCI tag (at most 128 chars of [A-Za-z0-9._-]); shorten the ring, experiment, variant or release version", tag)
	}
	return nil
}

// checkChannel refuses to serve a variant release anywhere but its own channel.
func checkChannel(m release.Manifest, ring string) error {
	if m.Experiment == "" {
		return nil
	}
	if want := policy.ChannelName(m.Ring, m.Experiment, m.Variant); ring != want {
		return fmt.Errorf("bundle: release %s is variant %s/%s of ring %s and may only be served on channel %s, not %s",
			m.Version, m.Experiment, m.Variant, m.Ring, want, ring)
	}
	return nil
}

// PublishRing publishes a ring release and its variant releases (as built by
// release.BuildRing): every variant on its channel first, then the ring, so a
// device never sees a ring manifest naming a channel that is not yet
// published. Everything is checked before anything is pushed: the variants
// must be exactly the channels rel's manifest lists for ring. Returns the ring
// release's descriptor and the channels written.
func PublishRing(ctx context.Context, dst oras.Target, rel *release.Release, variants []*release.Release, s Signer, ring string, opts *PointerOptions) (ocispec.Descriptor, []string, error) {
	if rel.Manifest.Experiment != "" {
		return ocispec.Descriptor{}, nil, fmt.Errorf("bundle: %s is a variant release, not a ring release", rel.Manifest.Version)
	}
	if len(rel.Manifest.Experiments) > 0 && rel.Manifest.Ring != ring {
		return ocispec.Descriptor{}, nil, fmt.Errorf("bundle: release lists experiments for ring %s, not %s", rel.Manifest.Ring, ring)
	}
	channels := rel.Manifest.Channels(ring)
	want := map[string]bool{}
	for _, ch := range channels {
		want[ch] = true
	}
	for _, v := range variants {
		m := v.Manifest
		ch := policy.ChannelName(m.Ring, m.Experiment, m.Variant)
		if m.Experiment == "" || m.Ring != ring || m.Org != rel.Manifest.Org || !want[ch] ||
			m.Version != release.VariantVersion(rel.Manifest.Version, ring, m.Experiment, m.Variant) {
			return ocispec.Descriptor{}, nil, fmt.Errorf("bundle: variant release %s (%s/%s) is not listed by the ring release manifest", m.Version, m.Experiment, m.Variant)
		}
		delete(want, ch)
	}
	if len(want) > 0 {
		return ocispec.Descriptor{}, nil, fmt.Errorf("bundle: ring release names %d channel(s) with no variant release", len(want))
	}
	o := opts.get()
	vf, err := verifierFor(s)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}
	for _, name := range append([]string{ring}, channels...) { // refuse before any pointer moves
		if _, err := preflight(ctx, dst, vf, o, name, rel.Manifest.Org); err != nil {
			return ocispec.Descriptor{}, nil, err
		}
	}
	for _, v := range variants {
		ch := policy.ChannelName(v.Manifest.Ring, v.Manifest.Experiment, v.Manifest.Variant)
		if _, err := publish(ctx, dst, v, s, o, ch); err != nil {
			return ocispec.Descriptor{}, nil, fmt.Errorf("bundle: publish channel %s: %w", ch, err)
		}
	}
	desc, err := publish(ctx, dst, rel, s, o, ring)
	return desc, channels, err
}

// PromoteRing points ring at the release from names (verified with s's key)
// and, if that release was built for ring, points each of its channels at the
// variant release published with it (tag v<release.VariantVersion>, whose
// signed manifest must match). Every release is fetched and verified, and
// every pointer about to be replaced passes preflight, before any pointer is
// written. Rollback is PromoteRing to an older version: ring and channels
// return to that snapshot together, each with a higher seq. Returns the ring
// pointer first, then one per channel (Pointer.Ring is the channel).
func PromoteRing(ctx context.Context, t oras.Target, from Source, ring string, s Signer, opts *PointerOptions) ([]Pointer, error) {
	o := opts.get()
	v, err := verifierFor(s)
	if err != nil {
		return nil, err
	}
	rel, md, err := resolveSource(ctx, t, v, o, from)
	if err != nil {
		return nil, err
	}
	if err := checkChannel(rel.Manifest, ring); err != nil {
		return nil, err
	}
	jobs := []pointerJob{{ring, rel, md}}
	if rel.Manifest.Ring == ring {
		for _, e := range rel.Manifest.Experiments {
			for _, va := range e.Variants {
				ver := release.VariantVersion(rel.Manifest.Version, ring, e.Name, va.Name)
				vd, err := t.Resolve(ctx, VersionTag(ver))
				if err != nil {
					return nil, fmt.Errorf("bundle: variant release for channel %s: resolve %s: %w", va.Channel, VersionTag(ver), err)
				}
				vr, err := fetchRelease(ctx, t, vd, v, DefaultMaxLayerSize)
				if err != nil {
					return nil, fmt.Errorf("bundle: variant release %s: %w", VersionTag(ver), err)
				}
				m := vr.Manifest
				if va.Channel != policy.ChannelName(ring, e.Name, va.Name) || m.Version != ver || m.Org != rel.Manifest.Org ||
					m.Experiment != e.Name || m.Variant != va.Name || m.Ring != ring {
					return nil, fmt.Errorf("bundle: %s is not variant %s/%s of release %s", VersionTag(ver), e.Name, va.Name, rel.Manifest.Version)
				}
				jobs = append(jobs, pointerJob{va.Channel, vr, vd})
			}
		}
	}
	return writePointers(ctx, t, s, v, o, jobs)
}

type pointerJob struct {
	ring string // ring or channel
	rel  *release.Release
	desc ocispec.Descriptor
}

// writePointers preflights every job, then writes channels before the ring
// (jobs[0]) so a device never sees a ring naming an unmoved channel. Returns
// the ring pointer first.
func writePointers(ctx context.Context, t oras.Target, s Signer, v Verifier, o PointerOptions, jobs []pointerJob) ([]Pointer, error) {
	for _, j := range jobs {
		if _, err := preflight(ctx, t, v, o, j.ring, j.rel.Manifest.Org); err != nil {
			return nil, err
		}
	}
	out := make([]Pointer, len(jobs))
	for i := len(jobs) - 1; i >= 0; i-- {
		p, err := writePointer(ctx, t, s, o, jobs[i].ring, jobs[i].rel, jobs[i].desc)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}

// RefreshRing re-signs ring's pointer and the pointer of every channel its
// current release routes to (same releases, higher seq, new expiry). Each
// served pointer must be unexpired and pass the state check (and the ring's
// must name opts.ExpectDigest, if set), and each release is re-verified,
// before anything is written. Returns the ring pointer first.
func RefreshRing(ctx context.Context, t oras.Target, ring string, s Signer, opts *PointerOptions) ([]Pointer, error) {
	o := opts.get()
	v, err := verifierFor(s)
	if err != nil {
		return nil, err
	}
	current := func(name string) (pointerJob, error) {
		p, err := currentPointer(ctx, t, v, o, name)
		if err != nil {
			return pointerJob{}, err
		}
		d, err := p.releaseDesc()
		if err != nil {
			return pointerJob{}, err
		}
		rel, err := fetchRelease(ctx, t, d, v, DefaultMaxLayerSize)
		if err != nil {
			return pointerJob{}, fmt.Errorf("bundle: ring %s release: %w", name, err)
		}
		if rel.Digest != p.Digest || rel.Manifest.Org != p.Org {
			return pointerJob{}, fmt.Errorf("bundle: ring %s release %s does not match its pointer", name, rel.Digest)
		}
		return pointerJob{name, rel, d}, nil
	}
	rj, err := current(ring)
	if err != nil {
		return nil, err
	}
	if o.ExpectDigest != "" && rj.rel.Digest != o.ExpectDigest {
		return nil, fmt.Errorf("bundle: ring %s serves release %s, expected %s: refusing to refresh", ring, rj.rel.Digest, o.ExpectDigest)
	}
	jobs := []pointerJob{rj}
	for _, ch := range rj.rel.Manifest.Channels(ring) {
		j, err := current(ch)
		if err != nil {
			return nil, fmt.Errorf("bundle: refresh channel %s: %w", ch, err)
		}
		jobs = append(jobs, j)
	}
	return writePointers(ctx, t, s, v, o, jobs)
}

// PointerChannels fetches and verifies the release p names and returns the
// channels it routes p.Ring's devices to. Read-only (dashboards).
func PointerChannels(ctx context.Context, src oras.ReadOnlyTarget, v Verifier, p Pointer) ([]string, error) {
	d, err := p.releaseDesc()
	if err != nil {
		return nil, err
	}
	rel, err := fetchRelease(ctx, src, d, v, DefaultMaxLayerSize)
	if err != nil {
		return nil, err
	}
	if rel.Digest != p.Digest || rel.Manifest.Org != p.Org {
		return nil, fmt.Errorf("bundle: release %s does not match ring %s's pointer", rel.Digest, p.Ring)
	}
	return rel.Manifest.Channels(p.Ring), nil
}
