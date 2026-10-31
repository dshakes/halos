// Package bundle publishes and pulls signed release bundles as OCI artifacts.
//
// Layout: artifactType application/vnd.halos.release.v1+tar; config blob
// is manifest.json; one layer is the bundle tar. The signature covers the tar
// digest and is stored in a manifest annotation. Immutable release tags are
// "v<version>". Which release a ring serves is decided by a signed ring pointer
// ("ring-<name>.pointer", see pointer.go); the plain "ring-<name>" tag is kept
// for humans and tooling only and is never trusted by halod.
package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/dshakes/halos/internal/release"
)

const (
	ArtifactType    = "application/vnd.halos.release.v1+tar"
	ConfigMediaType = "application/vnd.halos.release.config.v1+json"
	LayerMediaType  = "application/vnd.halos.release.layer.v1.tar"
	AnnSignature    = "dev.halos.signature"
	AnnSigType      = "dev.halos.signature.type"
)

// RingTag / VersionTag name the tags Publish writes.
func RingTag(ring string) string   { return "ring-" + ring }
func VersionTag(ver string) string { return "v" + ver }

// Publish pushes rel, signs it, tags it v<version> (immutable: an existing
// tag pointing elsewhere is an error), and writes a signed pointer (plus the
// informational ring-<name> tag) for each ring given. s must be ed25519 or a
// MultiSigner whose first signer is ed25519; further signers (cosign) are
// stored as co-signatures. Registries must also enforce tag immutability.
// Publish is stateless; PublishRing takes PointerOptions.
func Publish(ctx context.Context, dst oras.Target, rel *release.Release, s Signer, rings ...string) (ocispec.Descriptor, error) {
	return publish(ctx, dst, rel, s, PointerOptions{}, rings...)
}

func publish(ctx context.Context, dst oras.Target, rel *release.Release, s Signer, o PointerOptions, rings ...string) (ocispec.Descriptor, error) {
	if rel.Manifest.Version == "" {
		return ocispec.Descriptor{}, errors.New("bundle: release has no version")
	}
	v, err := verifierFor(s)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if len(rings) > 0 && rel.Manifest.Org == "" {
		return ocispec.Descriptor{}, errors.New("bundle: release has no org; ring pointers are org-scoped")
	}
	mj, err := json.Marshal(rel.Manifest)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	cfg := content.NewDescriptorFromBytes(ConfigMediaType, mj)
	layer := content.NewDescriptorFromBytes(LayerMediaType, rel.Tar)
	if layer.Digest.String() != rel.Digest {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: release digest %s != tar digest %s", rel.Digest, layer.Digest)
	}
	vt := VersionTag(rel.Manifest.Version)
	if err := checkTag(vt); err != nil {
		return ocispec.Descriptor{}, err
	}
	for _, r := range rings {
		if err := checkTag(PointerTag(r)); err != nil {
			return ocispec.Descriptor{}, err
		}
		if err := checkChannel(rel.Manifest, r); err != nil {
			return ocispec.Descriptor{}, err
		}
	}
	// ECDSA signatures are randomized, so re-signing the same release makes a
	// new manifest that trips tag immutability: a v-tag already naming exactly
	// this release (same config and layer) with a signature our key verifies
	// is reused as-is instead.
	desc, reused, err := alreadyPublished(ctx, dst, vt, cfg, layer, v)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if !reused {
		if desc, err = pushRelease(ctx, dst, s, rel, mj, cfg, layer, vt); err != nil {
			return ocispec.Descriptor{}, err
		}
	}
	if rel.Attestations != nil {
		if err := pushAttestations(ctx, dst, desc, rel, s); err != nil {
			return ocispec.Descriptor{}, err
		}
	}
	for _, r := range rings {
		if _, err := writePointer(ctx, dst, s, o, r, rel, desc); err != nil {
			return ocispec.Descriptor{}, err
		}
	}
	return desc, nil
}

// alreadyPublished reports whether tag vt names a halos release manifest
// with exactly cfg and layer whose signature v verifies; it returns that
// manifest. Anything else (absent, different, unverifiable) is false, and
// pushRelease's immutability check decides.
func alreadyPublished(ctx context.Context, dst oras.Target, vt string, cfg, layer ocispec.Descriptor, v Verifier) (ocispec.Descriptor, bool, error) {
	cur, err := dst.Resolve(ctx, vt)
	if errors.Is(err, errdef.ErrNotFound) {
		return ocispec.Descriptor{}, false, nil
	}
	if err != nil {
		return ocispec.Descriptor{}, false, fmt.Errorf("bundle: resolve %s: %w", vt, err)
	}
	m, err := fetchManifest(ctx, dst, cur)
	if err != nil {
		return ocispec.Descriptor{}, false, nil //nolint:nilerr // not reusable; pushRelease reports the conflict
	}
	if m.ArtifactType != ArtifactType || m.Config.Digest != cfg.Digest || len(m.Layers) != 1 ||
		m.Layers[0].Digest != layer.Digest || m.Layers[0].Size != layer.Size || m.Layers[0].MediaType != LayerMediaType {
		return ocispec.Descriptor{}, false, nil
	}
	if verifyManifest(ctx, m, v, layer.Digest.String()) != nil {
		return ocispec.Descriptor{}, false, nil
	}
	return cur, true, nil
}

// pushRelease signs rel, pushes its blobs and manifest and tags it vt.
func pushRelease(ctx context.Context, dst oras.Target, s Signer, rel *release.Release, mj []byte, cfg, layer ocispec.Descriptor, vt string) (ocispec.Descriptor, error) {
	ann, err := signAnnotations(ctx, s, rel.Digest, false)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: sign %s: %w", rel.Digest, err)
	}
	// A fixed created stamp keeps the manifest content-addressed: oras otherwise
	// stamps the push time, so an idempotent republish across a second boundary
	// gets a new digest and trips the immutable-tag check.
	ann[ocispec.AnnotationCreated] = "1970-01-01T00:00:00Z"
	for _, d := range []struct {
		desc ocispec.Descriptor
		data []byte
	}{{cfg, mj}, {layer, rel.Tar}} {
		if err := pushIfMissing(ctx, dst, d.desc, d.data); err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("bundle: push blob %s: %w", d.desc.Digest, err)
		}
	}
	desc, err := oras.PackManifest(ctx, dst, oras.PackManifestVersion1_1, ArtifactType, oras.PackManifestOptions{
		ConfigDescriptor:    &cfg,
		Layers:              []ocispec.Descriptor{layer},
		ManifestAnnotations: ann,
	})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: pack manifest: %w", err)
	}
	if cur, err := dst.Resolve(ctx, vt); err == nil && cur.Digest != desc.Digest {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: tag %s already points at %s; release tags are immutable", vt, cur.Digest)
	} else if err != nil && !errors.Is(err, errdef.ErrNotFound) {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: resolve %s: %w", vt, err)
	}
	if err := dst.Tag(ctx, desc, vt); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: tag %s: %w", vt, err)
	}
	return desc, nil
}

func pushIfMissing(ctx context.Context, dst oras.Target, d ocispec.Descriptor, data []byte) error {
	if ok, err := dst.Exists(ctx, d); err == nil && ok {
		return nil
	}
	return dst.Push(ctx, d, bytes.NewReader(data))
}

// Pull fetches tag and verifies the signature over the tar digest with v
// before downloading the layer (capped at DefaultMaxLayerSize). It proves
// authenticity only, not freshness or ring scope: halod must use PullRing. A
// nil verifier is refused so unverified content can never be returned.
func Pull(ctx context.Context, src oras.ReadOnlyTarget, tag string, v Verifier) (*release.Release, error) {
	if v == nil {
		return nil, errors.New("bundle: refusing to pull without a verifier")
	}
	md, err := src.Resolve(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("bundle: resolve %s: %w", tag, err)
	}
	rel, err := fetchRelease(ctx, src, md, v, DefaultMaxLayerSize)
	if err != nil {
		return nil, fmt.Errorf("bundle: %s: %w", tag, err)
	}
	return rel, nil
}

// ParseRef splits "host/repo:tag" into repo and tag ("" if absent).
func ParseRef(ref string) (repo, tag string) {
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}
