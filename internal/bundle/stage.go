package bundle

import (
	"context"
	"errors"
	"fmt"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// PublishChannel publishes one client-axis variant release on its own
// channel (policy.ChannelName of its manifest) with the same preflight and
// signer-state checks as a ring pointer. No ring pointer moves: devices reach
// the channel only once a ring release lists the experiment (PublishRing),
// so this pre-stages a canary without exposing anyone. Returns the channel.
func PublishChannel(ctx context.Context, dst oras.Target, v *release.Release, s Signer, opts *PointerOptions) (string, error) {
	m := v.Manifest
	if m.Experiment == "" || m.Variant == "" {
		return "", errors.New("bundle: PublishChannel needs a variant release (manifest experiment and variant set)")
	}
	ch := policy.ChannelName(m.Ring, m.Experiment, m.Variant)
	if already, err := staged(ctx, dst, v, s); err != nil || already {
		return ch, err // ponytail: staged with its pointer; a run that died between the two needs a new label
	}
	_, err := publish(ctx, dst, v, s, opts.get(), ch)
	return ch, err
}

// ServedPointer reads and verifies (with s's public key) the pointer ring
// currently serves. found is false when the ring was never published.
func ServedPointer(ctx context.Context, src oras.ReadOnlyTarget, s Signer, ring string) (p Pointer, found bool, err error) {
	v, err := verifierFor(s)
	if err != nil {
		return Pointer{}, false, err
	}
	return ReadPointer(ctx, src, ring, v)
}

// Stage pushes, signs and tags rel as v<version> with no pointer. Re-staging
// the same release is a no-op (a new OCI manifest would carry a new creation
// time and trip tag immutability); a v-tag naming a different release is an
// error. It reports whether rel was already there.
func Stage(ctx context.Context, dst oras.Target, rel *release.Release, s Signer) (already bool, err error) {
	if already, err := staged(ctx, dst, rel, s); err != nil || already {
		return already, err
	}
	_, err = Publish(ctx, dst, rel, s)
	return false, err
}

// staged reports whether v<version> already names rel (verified with s's
// key); a tag naming another release is an error.
func staged(ctx context.Context, dst oras.Target, rel *release.Release, s Signer) (bool, error) {
	tag := VersionTag(rel.Manifest.Version)
	if _, err := dst.Resolve(ctx, tag); err == nil {
		v, err := verifierFor(s)
		if err != nil {
			return false, err
		}
		cur, err := Pull(ctx, dst, tag, v)
		if err != nil {
			return false, err
		}
		if cur.Digest != rel.Digest {
			return false, fmt.Errorf("bundle: tag %s already names release %s, not %s; release tags are immutable (choose another version label)", tag, cur.Digest, rel.Digest)
		}
		return true, nil
	} else if !errors.Is(err, errdef.ErrNotFound) {
		return false, fmt.Errorf("bundle: resolve %s: %w", tag, err)
	}
	return false, nil
}
