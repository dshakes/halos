package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/dshakes/halos/internal/release"
)

// Signed ring pointers (TUF-lite). A ring tag alone is unauthenticated: whoever
// controls the registry could retag it to an older signed release or to one
// built for another ring. The pointer is a signed statement
// {org, ring, digest, seq, issuedAt, expiresAt} stored as its own OCI artifact
// under tag "ring-<name>.pointer". halod trusts the pointer, never the ring tag:
// it checks org/ring against its config, refuses seq regressions (freshness),
// refuses expired pointers, and only then fetches the release it names.
// Rollback is a NEW pointer with a higher seq naming an older digest.
const (
	PointerArtifactType   = "application/vnd.halos.pointer.v1"
	PointerConfigType     = "application/vnd.halos.pointer.v1+json"
	DefaultPointerTTL     = 7 * 24 * time.Hour
	DefaultMaxLayerSize   = 256 << 20
	maxManifestSize       = 1 << 20
	maxPointerPayloadSize = 16 << 10
	pointerDomain         = "halos.pointer.v1 " // domain separation from release signatures
)

// PointerTag is the tag holding ring's signed pointer.
func PointerTag(ring string) string { return RingTag(ring) + ".pointer" }

// Pointer is the signed ring -> release statement.
type Pointer struct {
	Org    string `json:"org"`
	Ring   string `json:"ring"`
	Digest string `json:"digest"` // release tar digest (what the release signature covers)
	// Manifest/ManifestSize address the release's OCI manifest by content, so
	// halod never resolves a mutable tag to find it.
	Manifest     string    `json:"manifest"`
	ManifestSize int64     `json:"manifestSize"`
	Seq          uint64    `json:"seq"`
	IssuedAt     time.Time `json:"issuedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

func pointerStatement(payload []byte) string {
	return pointerDomain + digest.FromBytes(payload).String()
}

// MultiSigner signs with its first signer (the one halod verifies; must be
// ed25519) and records every other signer (e.g. Cosign) as a co-signature on
// the release manifest.
type MultiSigner []Signer

func (m MultiSigner) Type() string {
	if len(m) == 0 {
		return ""
	}
	return m[0].Type()
}

func (m MultiSigner) Sign(ctx context.Context, d string) ([]byte, error) {
	if len(m) == 0 {
		return nil, errors.New("bundle: empty MultiSigner")
	}
	return m[0].Sign(ctx, d)
}

// verifierFor derives the ed25519 verifier from s. Publishing requires an
// ed25519 primary signer because halod can only verify ed25519 (it never shells
// out to cosign as root); cosign may be added as a co-signer via MultiSigner.
func verifierFor(s Signer) (Verifier, error) {
	switch t := s.(type) {
	case Ed25519Signer:
		return Ed25519Verifier{Key: t.Key.Public().(ed25519.PublicKey)}, nil
	case MultiSigner:
		if len(t) > 0 {
			return verifierFor(t[0])
		}
	}
	return nil, fmt.Errorf("bundle: primary signer must be ed25519 (got %q); halod cannot verify cosign-only releases, add cosign as a co-signer instead", s.Type())
}

// ReadPointer fetches and verifies ring's pointer. found=false (nil error)
// means no pointer exists yet.
func ReadPointer(ctx context.Context, src oras.ReadOnlyTarget, ring string, v Verifier) (p Pointer, found bool, err error) {
	if v == nil {
		return p, false, errors.New("bundle: refusing to read pointer without a verifier")
	}
	pd, err := src.Resolve(ctx, PointerTag(ring))
	if errors.Is(err, errdef.ErrNotFound) {
		return p, false, nil
	}
	if err != nil {
		return p, false, fmt.Errorf("bundle: resolve %s: %w", PointerTag(ring), err)
	}
	m, err := fetchManifest(ctx, src, pd)
	if err != nil {
		return p, true, err
	}
	if m.ArtifactType != PointerArtifactType || m.Config.MediaType != PointerConfigType {
		return p, true, fmt.Errorf("bundle: %s is not a halos pointer (artifactType %q)", PointerTag(ring), m.ArtifactType)
	}
	if m.Config.Size > maxPointerPayloadSize {
		return p, true, fmt.Errorf("bundle: pointer payload %d bytes exceeds %d", m.Config.Size, maxPointerPayloadSize)
	}
	sig, err := signatureFor(m, v)
	if err != nil {
		return p, true, fmt.Errorf("bundle: pointer %s: %w", ring, err)
	}
	payload, err := content.FetchAll(ctx, src, m.Config) // size already capped; verifies digest
	if err != nil {
		return p, true, fmt.Errorf("bundle: fetch pointer payload: %w", err)
	}
	if err := v.Verify(ctx, pointerStatement(payload), sig); err != nil {
		return p, true, fmt.Errorf("bundle: verify pointer %s: %w", ring, err)
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return p, true, fmt.Errorf("bundle: parse pointer %s: %w", ring, err)
	}
	if p.Ring != ring {
		return p, true, fmt.Errorf("bundle: pointer under %s is signed for ring %q", PointerTag(ring), p.Ring)
	}
	return p, true, nil
}

// PointerOptions are the signer-side guards every pointer write runs. The
// zero value (or nil) is stateless: writes still refuse foreign-org pointers,
// and refresh/promote-from-ring still refuse expired pointers, but a replayed
// unexpired pointer is only caught by State or ExpectDigest.
type PointerOptions struct {
	// State remembers the pointers this signer wrote; a served pointer older
	// than (or forked from) the recorded one is refused, and every write is recorded.
	State *PointerState
	// ExpectDigest, if set, is the release digest the operation must act on:
	// the source release of a promote/rollback, the ring's current release on refresh.
	ExpectDigest string
	// AdoptExisting lets a signer whose State has no record for a ring take
	// over the pointer the registry serves (first run with a new or evicted
	// state file). Without it, or an ExpectDigest naming the served release,
	// such a pointer is refused: a missing state file must not silently turn
	// replay protection off.
	AdoptExisting bool
	// BeforeSign is called with each pointer, and the version of the release
	// it names, just before it is signed.
	BeforeSign func(p Pointer, version string)
	now        time.Time // tests; zero = time.Now()
}

func (o *PointerOptions) get() PointerOptions {
	if o == nil {
		return PointerOptions{}
	}
	return *o
}

func (o PointerOptions) clock() time.Time {
	if o.now.IsZero() {
		return time.Now()
	}
	return o.now
}

// continuity applies the signer-state checks. A served pointer the state has
// no record of is only trusted when the operator said so (AdoptExisting) or
// pinned it (ExpectDigest == its digest).
func (o PointerOptions) continuity(ring string, cur Pointer, found bool) error {
	if o.State == nil {
		return nil
	}
	if _, known := o.State.Mark(ring); !known && found && !o.AdoptExisting && o.ExpectDigest != cur.Digest {
		return fmt.Errorf("bundle: ring %s already has a pointer (seq %d, digest %s) but %s has no record of it: "+
			"restore the signer state file, or confirm this pointer with --expect-digest %s or --adopt-existing (first run / evicted cache)",
			ring, cur.Seq, cur.Digest, o.State.path, cur.Digest)
	}
	return o.State.check(ring, cur, found)
}

// releaseDesc addresses the release p names by content.
func (p Pointer) releaseDesc() (ocispec.Descriptor, error) {
	d, err := digest.Parse(p.Manifest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: pointer manifest digest: %w", err)
	}
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: d, Size: p.ManifestSize}, nil
}

// preflight reads ring's served pointer before we overwrite it: it must verify,
// pass the state continuity check, and belong to org.
func preflight(ctx context.Context, t oras.ReadOnlyTarget, v Verifier, o PointerOptions, ring, org string) (Pointer, error) {
	cur, found, err := ReadPointer(ctx, t, ring, v)
	if err != nil { // a tampered/foreign pointer must not silently reset seq
		return Pointer{}, fmt.Errorf("bundle: existing pointer for ring %s is invalid; refusing to overwrite: %w", ring, err)
	}
	if err := o.continuity(ring, cur, found); err != nil {
		return Pointer{}, err
	}
	if found && cur.Org != org {
		return Pointer{}, fmt.Errorf("bundle: ring %s pointer is for org %q; refusing to point it at a release for org %q", ring, cur.Org, org)
	}
	return cur, nil
}

// currentPointer reads ring's pointer for re-use (refresh, promote from ring):
// it must exist, pass the state check and be unexpired. Re-signing an expired
// pointer would launder a replayed one into a fresh one.
func currentPointer(ctx context.Context, t oras.ReadOnlyTarget, v Verifier, o PointerOptions, ring string) (Pointer, error) {
	p, found, err := ReadPointer(ctx, t, ring, v)
	if err != nil {
		return p, err
	}
	if !found {
		return p, fmt.Errorf("bundle: ring %s has no signed pointer (%s)", ring, PointerTag(ring))
	}
	if err := o.continuity(ring, p, true); err != nil {
		return p, err
	}
	if !o.clock().Before(p.ExpiresAt) {
		return p, fmt.Errorf("bundle: pointer for ring %s (seq %d, digest %s) expired at %s and may be a replay; refusing to re-sign it: point the ring at an explicit release version instead",
			ring, p.Seq, p.Digest, p.ExpiresAt.Format(time.RFC3339))
	}
	return p, nil
}

// writePointer signs and pushes a pointer for ring -> rel with seq =
// max(current+1, recorded+1, unix now) (a replayed older pointer tag cannot
// make us reuse a seq), records it in o.State, and moves the (informational)
// ring-<name> tag along with it. rel must already be verified.
func writePointer(ctx context.Context, t oras.Target, s Signer, o PointerOptions, ring string, rel *release.Release, relDesc ocispec.Descriptor) (Pointer, error) {
	org := rel.Manifest.Org
	if org == "" {
		return Pointer{}, errors.New("bundle: release has no org; ring pointers are org-scoped")
	}
	if err := checkTag(PointerTag(ring)); err != nil {
		return Pointer{}, err
	}
	v, err := verifierFor(s)
	if err != nil {
		return Pointer{}, err
	}
	cur, err := preflight(ctx, t, v, o, ring, org)
	if err != nil {
		return Pointer{}, err
	}
	now := o.clock().UTC().Truncate(time.Second)
	seq := max(cur.Seq+1, uint64(now.Unix())) //nolint:gosec // Unix time is positive
	if o.State != nil {
		if m, ok := o.State.Mark(ring); ok {
			seq = max(seq, m.Seq+1)
		}
	}
	p := Pointer{
		Org: org, Ring: ring, Digest: rel.Digest, Manifest: relDesc.Digest.String(), ManifestSize: relDesc.Size,
		Seq: seq, IssuedAt: now, ExpiresAt: now.Add(DefaultPointerTTL),
	}
	if o.BeforeSign != nil {
		o.BeforeSign(p, rel.Manifest.Version)
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return Pointer{}, err
	}
	sig, err := s.Sign(ctx, pointerStatement(payload))
	if err != nil {
		return Pointer{}, fmt.Errorf("bundle: sign pointer %s: %w", ring, err)
	}
	cfg := content.NewDescriptorFromBytes(PointerConfigType, payload)
	if err := pushIfMissing(ctx, t, cfg, payload); err != nil {
		return Pointer{}, fmt.Errorf("bundle: push pointer: %w", err)
	}
	pd, err := oras.PackManifest(ctx, t, oras.PackManifestVersion1_1, PointerArtifactType, oras.PackManifestOptions{
		ConfigDescriptor:    &cfg,
		ManifestAnnotations: map[string]string{AnnSignature: base64.StdEncoding.EncodeToString(sig), AnnSigType: s.Type()},
	})
	if err != nil {
		return Pointer{}, fmt.Errorf("bundle: pack pointer: %w", err)
	}
	if err := t.Tag(ctx, pd, PointerTag(ring)); err != nil {
		return Pointer{}, fmt.Errorf("bundle: tag %s: %w", PointerTag(ring), err)
	}
	if o.State != nil {
		if err := o.State.record(ring, p); err != nil {
			return p, fmt.Errorf("bundle: pointer %s seq %d was published but the signer state was not updated: %w", ring, p.Seq, err)
		}
	}
	if err := t.Tag(ctx, relDesc, RingTag(ring)); err != nil {
		return Pointer{}, fmt.Errorf("bundle: tag %s: %w", RingTag(ring), err)
	}
	return p, nil
}

// Source names the release a ring is pointed at. Set exactly one field. None
// of them trusts a mutable tag on its own: a ring source follows that ring's
// signed pointer, a version source must carry that version in its signed
// manifest, and a manifest source is a content address.
type Source struct {
	Ring     string // the release Ring's signed pointer names (promote)
	Version  string // tag v<Version> (rollback)
	Manifest string // the release's OCI manifest digest (rollback by digest)
}

func (src Source) String() string {
	switch {
	case src.Ring != "":
		return "ring " + src.Ring
	case src.Version != "":
		return VersionTag(src.Version)
	}
	return src.Manifest
}

// resolveSource fetches and verifies the release src names.
func resolveSource(ctx context.Context, t oras.Target, v Verifier, o PointerOptions, src Source) (*release.Release, ocispec.Descriptor, error) {
	var md ocispec.Descriptor
	var err error
	n := 0
	for _, f := range []string{src.Ring, src.Version, src.Manifest} {
		if f != "" {
			n++
		}
	}
	if n != 1 {
		return nil, md, errors.New("bundle: source must name exactly one of ring, version or manifest digest")
	}
	var p Pointer
	switch {
	case src.Ring != "":
		if p, err = currentPointer(ctx, t, v, o, src.Ring); err != nil {
			return nil, md, fmt.Errorf("bundle: source %w", err)
		}
		if md, err = p.releaseDesc(); err != nil {
			return nil, md, err
		}
	case src.Version != "":
		if md, err = t.Resolve(ctx, VersionTag(src.Version)); err != nil {
			return nil, md, fmt.Errorf("bundle: resolve %s: %w", VersionTag(src.Version), err)
		}
	default:
		d, perr := digest.Parse(src.Manifest)
		if perr != nil {
			return nil, md, fmt.Errorf("bundle: manifest digest %q: %w", src.Manifest, perr)
		}
		if md, err = t.Resolve(ctx, d.String()); err != nil {
			return nil, md, fmt.Errorf("bundle: resolve %s: %w", d, err)
		}
		if md.Digest != d {
			return nil, md, fmt.Errorf("bundle: registry resolved %s to %s", d, md.Digest)
		}
	}
	rel, err := fetchRelease(ctx, t, md, v, DefaultMaxLayerSize)
	if err != nil {
		return nil, md, fmt.Errorf("bundle: %s: %w", src, err)
	}
	switch {
	case src.Ring != "" && (rel.Digest != p.Digest || rel.Manifest.Org != p.Org):
		return nil, md, fmt.Errorf("bundle: release %s (org %q) does not match ring %s's signed pointer (digest %s, org %q)", rel.Digest, rel.Manifest.Org, src.Ring, p.Digest, p.Org)
	case src.Version != "" && rel.Manifest.Version != src.Version:
		return nil, md, fmt.Errorf("bundle: tag %s names a signed release of version %q (digest %s): registry retag refused", VersionTag(src.Version), rel.Manifest.Version, rel.Digest)
	case o.ExpectDigest != "" && rel.Digest != o.ExpectDigest:
		return nil, md, fmt.Errorf("bundle: %s is release %s, expected %s", src, rel.Digest, o.ExpectDigest)
	}
	return rel, md, nil
}

// RingOptions are halod's freshness/scope requirements for PullRing.
type RingOptions struct {
	Org, Ring string
	// MinSeq/LastDigest are the last applied pointer for this ring (zero on first run).
	MinSeq     uint64
	LastDigest string
	Now        time.Time
	// MaxLayerSize caps the release tar; 0 = DefaultMaxLayerSize.
	MaxLayerSize int64
}

// PullRing is halod's entry point: verify the ring pointer (signature, org,
// ring, seq, expiry), then fetch the release it names by content address,
// verify its signature BEFORE downloading the layer, cap the layer size, and
// check the digest. Nothing unverified is returned.
func PullRing(ctx context.Context, src oras.ReadOnlyTarget, v Verifier, o RingOptions) (*release.Release, Pointer, error) {
	p, found, err := ReadPointer(ctx, src, o.Ring, v)
	if err != nil {
		return nil, p, err
	}
	if !found {
		return nil, p, fmt.Errorf("bundle: ring %s has no signed pointer (%s)", o.Ring, PointerTag(o.Ring))
	}
	switch {
	case p.Org != o.Org:
		return nil, p, fmt.Errorf("bundle: pointer is for org %q, want %q", p.Org, o.Org)
	case p.Seq < o.MinSeq:
		return nil, p, fmt.Errorf("bundle: pointer seq %d older than applied seq %d (rollback/replay refused)", p.Seq, o.MinSeq)
	case p.Seq == o.MinSeq && o.LastDigest != "" && p.Digest != o.LastDigest:
		return nil, p, fmt.Errorf("bundle: pointer seq %d reused for a different digest", p.Seq)
	case !o.Now.Before(p.ExpiresAt):
		return nil, p, fmt.Errorf("bundle: pointer for ring %s expired at %s", o.Ring, p.ExpiresAt.Format(time.RFC3339))
	}
	d, err := digest.Parse(p.Manifest)
	if err != nil {
		return nil, p, fmt.Errorf("bundle: pointer manifest digest: %w", err)
	}
	maxLayer := o.MaxLayerSize
	if maxLayer <= 0 {
		maxLayer = DefaultMaxLayerSize
	}
	rel, err := fetchRelease(ctx, src, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: d, Size: p.ManifestSize}, v, maxLayer)
	if err != nil {
		return nil, p, err
	}
	if rel.Digest != p.Digest {
		return nil, p, fmt.Errorf("bundle: release digest %s != pointer digest %s", rel.Digest, p.Digest)
	}
	if rel.Manifest.Org != p.Org {
		return nil, p, fmt.Errorf("bundle: release built for org %q, pointer says %q", rel.Manifest.Org, p.Org)
	}
	if err := checkChannel(rel.Manifest, o.Ring); err != nil {
		return nil, p, err
	}
	return rel, p, nil
}

func fetchManifest(ctx context.Context, src oras.ReadOnlyTarget, d ocispec.Descriptor) (ocispec.Manifest, error) {
	var m ocispec.Manifest
	if d.Size <= 0 || d.Size > maxManifestSize {
		return m, fmt.Errorf("bundle: manifest %s size %d out of range", d.Digest, d.Size)
	}
	mb, err := content.FetchAll(ctx, src, d)
	if err != nil {
		return m, fmt.Errorf("bundle: fetch manifest %s: %w", d.Digest, err)
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		return m, fmt.Errorf("bundle: parse OCI manifest: %w", err)
	}
	return m, nil
}

// signatureFor picks the signature matching v's type: the primary one, or a
// co-signature stored under AnnSignature+"."+type.
func signatureFor(m ocispec.Manifest, v Verifier) ([]byte, error) {
	enc := m.Annotations[AnnSignature+"."+v.Type()]
	if enc == "" {
		if t := m.Annotations[AnnSigType]; t != v.Type() {
			return nil, fmt.Errorf("signature type %q, verifier expects %q", t, v.Type())
		}
		enc = m.Annotations[AnnSignature]
	}
	sig, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("missing or malformed signature")
	}
	return sig, nil
}

// fetchRelease verifies the signature over the layer digest named in the
// (small, size-capped) manifest before fetching the layer, rejects layers over
// maxLayer, then fetches with a size-limited, digest-verifying reader.
func fetchRelease(ctx context.Context, src oras.ReadOnlyTarget, md ocispec.Descriptor, v Verifier, maxLayer int64) (*release.Release, error) {
	m, err := fetchManifest(ctx, src, md)
	if err != nil {
		return nil, err
	}
	if m.ArtifactType != ArtifactType || len(m.Layers) != 1 || m.Layers[0].MediaType != LayerMediaType {
		return nil, fmt.Errorf("bundle: %s is not a halos release (artifactType %q)", md.Digest, m.ArtifactType)
	}
	sig, err := signatureFor(m, v)
	if err != nil {
		return nil, fmt.Errorf("bundle: release %s: %w", md.Digest, err)
	}
	layer := m.Layers[0]
	if err := layer.Digest.Validate(); err != nil {
		return nil, fmt.Errorf("bundle: layer digest: %w", err)
	}
	if err := v.Verify(ctx, layer.Digest.String(), sig); err != nil {
		return nil, fmt.Errorf("bundle: verify %s: %w", md.Digest, err)
	}
	if layer.Size <= 0 || layer.Size > maxLayer {
		return nil, fmt.Errorf("bundle: layer size %d exceeds limit %d", layer.Size, maxLayer)
	}
	rc, err := src.Fetch(ctx, layer)
	if err != nil {
		return nil, fmt.Errorf("bundle: fetch layer %s: %w", layer.Digest, err)
	}
	defer func() { _ = rc.Close() }()          // best effort
	tarData, err := content.ReadAll(rc, layer) // reads exactly layer.Size, verifies digest
	if err != nil {
		return nil, fmt.Errorf("bundle: read layer %s: %w", layer.Digest, err)
	}
	if digest.FromBytes(tarData) != layer.Digest {
		return nil, errors.New("bundle: layer digest mismatch")
	}
	rel, err := release.Open(tarData)
	if err != nil {
		return nil, fmt.Errorf("bundle: open release: %w", err)
	}
	return rel, nil
}
