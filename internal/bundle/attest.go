package bundle

import (
	"context"
	"errors"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"

	"github.com/dshakes/halos/internal/release"
)

// A release's AI-BOM and provenance (ADR-0028) are one OCI referrer of its
// release manifest: two layers, signed by the release signer over a
// domain-separated statement naming the release and both layer digests. They
// stay out of the release tar so its digest is content-only, and out of the
// release manifest so halods that predate them still pull it.
const (
	AttestationArtifactType = "application/vnd.halos.attestations.v1+json"
	attestationDomain       = "halos.attestations.v1 "
	maxAttestationLayer     = 4 << 20
)

func attestationStatement(releaseDigest, bom, prov string) string {
	return attestationDomain + releaseDigest + " " + bom + " " + prov
}

// pushAttestations stores rel.Attestations as a signed referrer of subject.
func pushAttestations(ctx context.Context, dst oras.Target, subject ocispec.Descriptor, rel *release.Release, s Signer) error {
	a := rel.Attestations
	bom := content.NewDescriptorFromBytes(release.BOMMediaType, a.BOM)
	prov := content.NewDescriptorFromBytes(release.ProvenanceMediaType, a.Provenance)
	stmt := attestationStatement(rel.Digest, bom.Digest.String(), prov.Digest.String())
	ann, err := signAnnotations(ctx, s, stmt, false)
	if err != nil {
		return fmt.Errorf("bundle: sign attestations: %w", err)
	}
	ann[ocispec.AnnotationCreated] = "1970-01-01T00:00:00Z"
	for _, d := range []struct {
		desc ocispec.Descriptor
		data []byte
	}{{bom, a.BOM}, {prov, a.Provenance}} {
		if err := pushIfMissing(ctx, dst, d.desc, d.data); err != nil {
			return fmt.Errorf("bundle: push attestation blob %s: %w", d.desc.Digest, err)
		}
	}
	if _, err := oras.PackManifest(ctx, dst, oras.PackManifestVersion1_1, AttestationArtifactType, oras.PackManifestOptions{
		Subject: &subject, Layers: []ocispec.Descriptor{bom, prov}, ManifestAnnotations: ann,
	}); err != nil {
		return fmt.Errorf("bundle: pack attestations: %w", err)
	}
	return nil
}

// PullAttestations pulls tag's release (signature-verified with v, like Pull)
// and every attestation referrer of it whose signature verifies with v and
// whose content describes the release (release.VerifyAttestations). It fails
// when none does.
func PullAttestations(ctx context.Context, src oras.ReadOnlyGraphTarget, tag string, v Verifier) (*release.Release, []*release.Attestations, error) {
	if v == nil {
		return nil, nil, errors.New("bundle: refusing to pull without a verifier")
	}
	md, err := src.Resolve(ctx, tag)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: resolve %s: %w", tag, err)
	}
	rel, err := fetchRelease(ctx, src, md, v, DefaultMaxLayerSize)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: %s: %w", tag, err)
	}
	refs, err := registry.Referrers(ctx, src, md, AttestationArtifactType)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: list attestations of %s: %w", tag, err)
	}
	var out []*release.Attestations
	var errs []error
	for _, d := range refs {
		a, err := fetchAttestation(ctx, src, d, rel, v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.Digest, err))
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("bundle: %s has no attestation that verifies: %w", tag, errors.Join(append(errs, errors.New("none found"))...))
	}
	return rel, out, nil
}

func fetchAttestation(ctx context.Context, src oras.ReadOnlyTarget, d ocispec.Descriptor, rel *release.Release, v Verifier) (*release.Attestations, error) {
	m, err := fetchManifest(ctx, src, d)
	if err != nil {
		return nil, err
	}
	if m.ArtifactType != AttestationArtifactType || len(m.Layers) != 2 ||
		m.Layers[0].MediaType != release.BOMMediaType || m.Layers[1].MediaType != release.ProvenanceMediaType {
		return nil, errors.New("not a halos attestation manifest")
	}
	if err := verifyManifest(ctx, m, v, attestationStatement(rel.Digest, m.Layers[0].Digest.String(), m.Layers[1].Digest.String())); err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	var blobs [2][]byte
	for i, l := range m.Layers {
		if l.Size <= 0 || l.Size > maxAttestationLayer {
			return nil, fmt.Errorf("layer size %d out of range", l.Size)
		}
		if blobs[i], err = content.FetchAll(ctx, src, l); err != nil { // verifies size and digest
			return nil, fmt.Errorf("fetch %s: %w", l.Digest, err)
		}
	}
	a := &release.Attestations{BOM: blobs[0], Provenance: blobs[1]}
	if err := release.VerifyAttestations(rel, a.BOM, a.Provenance); err != nil {
		return nil, err
	}
	return a, nil
}
