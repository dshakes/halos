package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/delivery/devcontainer"
	"github.com/dshakes/halos/internal/delivery/mdm"
	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// dialRegistry opens a registry repo ("host/org/name"); tests replace it.
var dialRegistry = func(repo string, plainHTTP bool) (oras.Target, error) {
	return bundle.Repository(repo, plainHTTP)
}

type regFlags struct {
	registry            string
	plainHTTP           bool
	key, cosign, pubkey string
	keyless             bool
}

func (r *regFlags) add(c *cobra.Command, sign, verify bool) {
	c.Flags().StringVar(&r.registry, "registry", "", "registry repo, e.g. ghcr.io/acme/halos")
	c.Flags().BoolVar(&r.plainHTTP, "plain-http", false, "use HTTP instead of HTTPS (local registries)")
	if sign {
		c.Flags().StringVar(&r.key, "key", "", "ed25519 private key PEM (create one with: halo keys generate)")
		c.Flags().StringVar(&r.cosign, "cosign-key", "", "cosign key reference (file or KMS URI); co-signs alongside --key")
		c.Flags().BoolVar(&r.keyless, "cosign-keyless", false, "cosign keyless (Fulcio+Rekor): uploads the release digest to the public transparency log")
	}
	if verify {
		c.Flags().StringVar(&r.pubkey, "pubkey", "", "ed25519 public key PEM to verify with")
		if !sign {
			c.Flags().StringVar(&r.cosign, "cosign-key", "", "cosign public key reference to verify with")
		}
	}
}

func (r *regFlags) target() (oras.Target, error) {
	if r.registry == "" {
		return nil, errors.New("--registry is required")
	}
	repo, _ := bundle.ParseRef(r.registry)
	return dialRegistry(repo, r.plainHTTP)
}

// ptrFlags are the signer-side pointer guards (see bundle.PointerOptions).
type ptrFlags struct {
	stateFile, expectDigest string
	adoptExisting           bool
}

const stateHelp = "signer state file recording the last pointer written per registry repo and ring; a registry serving an older pointer\n" +
	"(replay) is refused. Default $XDG_STATE_HOME/halos/pointers.json (~/.local/state/halos/pointers.json). CI: cache this file between runs"

func (p *ptrFlags) add(c *cobra.Command, expect string) {
	c.Flags().StringVar(&p.stateFile, "state-file", "", stateHelp)
	c.Flags().BoolVar(&p.adoptExisting, "adopt-existing", false,
		"trust pointers the registry already serves that the state file has no record of (first run, or an evicted CI cache);\n"+
			"without it such a pointer is refused unless --expect-digest names it")
	if expect != "" {
		c.Flags().StringVar(&p.expectDigest, "expect-digest", "", expect)
	}
}

// signed collects the release version of every pointer about to be signed.
type signed map[string]string

// options loads the signer state for rf's registry repo and announces each
// pointer (to stderr, so --output json stays parseable) before it is signed.
func (a *app) pointerOptions(rf *regFlags, pf *ptrFlags) (*bundle.PointerOptions, signed, error) {
	path := pf.stateFile
	if path == "" {
		var err error
		if path, err = bundle.DefaultPointerStatePath(); err != nil {
			return nil, nil, err
		}
	}
	repo, _ := bundle.ParseRef(rf.registry)
	st, err := bundle.LoadPointerState(path, repo)
	if err != nil {
		return nil, nil, err
	}
	vers := signed{}
	return &bundle.PointerOptions{State: st, ExpectDigest: pf.expectDigest, AdoptExisting: pf.adoptExisting, BeforeSign: func(p bundle.Pointer, ver string) {
		vers[p.Ring] = ver
		fmt.Fprintf(a.errw, "Signing ring %s \u2192 version %s (digest %s, seq %d)\n", p.Ring, ver, p.Digest, p.Seq)
	}}, vers, nil
}

func (r *regFlags) signer() (bundle.Signer, error) {
	if r.key == "" {
		if r.cosign != "" || r.keyless {
			return nil, errors.New("halod verifies ed25519; add --key (cosign can only co-sign)")
		}
		return nil, errors.New("a signing key is required: --key")
	}
	pem, err := os.ReadFile(r.key)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	ed, err := bundle.ParseEd25519Signer(pem)
	if err != nil {
		return nil, err
	}
	if r.cosign == "" && !r.keyless {
		return ed, nil
	}
	return bundle.MultiSigner{ed, bundle.Cosign{Key: r.cosign, Keyless: r.keyless}}, nil
}

func (r *regFlags) verifier() (bundle.Verifier, error) {
	switch {
	case r.pubkey != "" && r.cosign != "":
		return nil, errors.New("use only one of --pubkey and --cosign-key")
	case r.cosign != "":
		return bundle.Cosign{Key: r.cosign}, nil
	case r.pubkey != "":
		pem, err := os.ReadFile(r.pubkey)
		if err != nil {
			return nil, fmt.Errorf("read public key: %w", err)
		}
		return bundle.ParseEd25519Verifier(pem)
	}
	return nil, errors.New("a verification key is required: --pubkey or --cosign-key")
}

func (a *app) cmdRelease() *cobra.Command {
	c := &cobra.Command{Use: "release", Short: "Build, publish and promote releases"}

	var ring, out, ver, dir string
	var noArt bool
	build := &cobra.Command{
		Use:         "build",
		Annotations: policyDirAnno,
		Short:       "Build a release tarball for a ring",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if dir, err = policyDir(cmd, args); err != nil {
				return err
			}
			rel, err := a.buildRelease(dir, ring, ver)
			if err != nil {
				return err
			}
			if rel, err = a.resolveArtifacts(cmd.Context(), rel, noArt); err != nil {
				return err
			}
			if err := writeFile(out, rel.Tar, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", out, err)
			}
			return a.emit(map[string]string{"file": out, "digest": rel.Digest, "version": rel.Manifest.Version, "ring": ring}, func() {
				fmt.Fprintf(a.out, "%s %s (%s)\n", a.green("built"), out, rel.Digest)
			})
		},
	}
	build.Flags().StringVar(&ring, "ring", "", "ring to build (required)")
	build.Flags().StringVarP(&out, "out", "o", "release.tar", "output tarball")
	build.Flags().StringVar(&ver, "release-version", "0.0.0-dev", "release version label")
	build.Flags().BoolVar(&noArt, "no-artifacts", false, noArtHelp)
	_ = build.MarkFlagRequired("ring")

	var pRing, pVer string
	var pNoArt bool
	var pf regFlags
	var ppf ptrFlags
	publish := &cobra.Command{
		Use:         "publish",
		Annotations: policyDirAnno,
		Short:       "Build, sign and push a ring release (and its client-axis experiment channels); tags v<version> and ring-<ring>",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := pf.signer()
			if err != nil {
				return err
			}
			t, err := pf.target()
			if err != nil {
				return err
			}
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			rel, variants, err := a.buildRing(dir, pRing, pVer)
			if err != nil {
				return err
			}
			if err := a.refusePinned(dir, pRing, rel.Digest); err != nil {
				return err
			}
			if rel, err = a.resolveArtifacts(cmd.Context(), rel, pNoArt); err != nil {
				return err
			}
			for i := 0; i < len(variants) && !pNoArt; i++ { // --no-artifacts: warned once above
				if variants[i], err = a.resolveArtifacts(cmd.Context(), variants[i], false); err != nil {
					return err
				}
			}
			o, _, err := a.pointerOptions(&pf, &ppf)
			if err != nil {
				return err
			}
			desc, channels, err := bundle.PublishRing(cmd.Context(), t, rel, variants, s, pRing, o)
			if err != nil {
				return fmt.Errorf("publish %s: %w", pf.registry, err)
			}
			tags := []string{bundle.VersionTag(pVer), bundle.RingTag(pRing)}
			for _, v := range variants {
				tags = append(tags, bundle.VersionTag(v.Manifest.Version))
			}
			for _, ch := range channels {
				tags = append(tags, bundle.RingTag(ch))
			}
			return a.emit(map[string]any{"registry": pf.registry, "digest": rel.Digest, "manifest": desc.Digest.String(),
				"tags": strings.Join(tags, ","), "channels": channels}, func() {
				fmt.Fprintf(a.out, "%s %s tags %s, %s (%s)\n", a.green("published"), pf.registry,
					bundle.VersionTag(pVer), bundle.RingTag(pRing), rel.Digest)
				for _, v := range variants {
					fmt.Fprintf(a.out, "  %s experiment %s variant %s: tags %s, %s (%s)\n", a.green("channel"), v.Manifest.Experiment, v.Manifest.Variant,
						bundle.VersionTag(v.Manifest.Version), bundle.RingTag(policyChannel(v)), v.Digest)
				}
			})
		},
	}
	publish.Flags().StringVar(&pRing, "ring", "", "ring to publish (required)")
	publish.Flags().StringVar(&pVer, "release-version", "", "release version, becomes tag v<version> (required)")
	publish.Flags().BoolVar(&pNoArt, "no-artifacts", false, noArtHelp)
	pf.add(publish, true, false)
	ppf.add(publish, "")
	_ = publish.MarkFlagRequired("ring")
	_ = publish.MarkFlagRequired("release-version")

	var from, to string
	var prf regFlags
	var pp ptrFlags
	promote := &cobra.Command{
		Use:   "promote",
		Short: "Point --to-ring at the release --from-ring's signed pointer names; experiment channels stay with the ring they were built for",
		Long: "The source release is taken from --from-ring's signed pointer (signature, ring, org, expiry and\n" +
			"--state-file continuity checked), never from the unauthenticated ring-<name> tag.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.retag(cmd.Context(), &prf, &pp, bundle.Source{Ring: from}, to, "promoted")
		},
	}
	promote.Flags().StringVar(&from, "from-ring", "", "source ring (required)")
	promote.Flags().StringVar(&to, "to-ring", "", "destination ring (required)")
	prf.add(promote, true, false)
	pp.add(promote, "refuse unless --from-ring serves this release digest (sha256:...)")
	_ = promote.MarkFlagRequired("from-ring")
	_ = promote.MarkFlagRequired("to-ring")

	c.AddCommand(build, publish, promote, a.cmdRefresh())
	return c
}

const noArtHelp = "skip resolving vendor install artifacts (offline builds); halod will not install CLIs without them unless allowShellInstall"

// newResolver is replaced by tests to point at an httptest server.
var newResolver = func() release.ArtifactResolver { return release.ArtifactResolver{} }

// resolveArtifacts pins verified install artifacts into the release (network).
func (a *app) resolveArtifacts(ctx context.Context, rel *release.Release, skip bool) (*release.Release, error) {
	if skip {
		fmt.Fprintln(a.errw, "warning: --no-artifacts: halod will not install CLIs from this release unless allowShellInstall is set")
		return rel, nil
	}
	out, err := newResolver().Resolve(ctx, rel)
	if err != nil {
		return nil, fmt.Errorf("resolve artifacts (use --no-artifacts to build offline): %w", err)
	}
	return out, nil
}

func policyChannel(v *release.Release) string {
	return policy.ChannelName(v.Manifest.Ring, v.Manifest.Experiment, v.Manifest.Variant)
}

// emitPointers reports the ring pointer (ps[0]) and any channel pointers after it.
func (a *app) emitPointers(verb, ring string, ps []bundle.Pointer, vers signed) error {
	p := ps[0]
	var chans []map[string]any
	for _, c := range ps[1:] {
		chans = append(chans, map[string]any{"channel": c.Ring, "version": vers[c.Ring], "seq": c.Seq, "digest": c.Digest, "expiresAt": c.ExpiresAt})
	}
	return a.emit(map[string]any{"ring": ring, "version": vers[ring], "seq": p.Seq, "digest": p.Digest, "expiresAt": p.ExpiresAt, "channels": chans}, func() {
		for _, p := range ps {
			fmt.Fprintf(a.out, "%s %s %s: version %s, seq %d, digest %s, expires %s\n", a.green("ok"), verb, bundle.RingTag(p.Ring), vers[p.Ring], p.Seq, p.Digest, p.ExpiresAt.Format(time.RFC3339))
		}
	})
}

// retag points ring (and, when the release was built for ring, each of its
// client-axis experiment channels) at the release src names.
func (a *app) retag(ctx context.Context, rf *regFlags, pf *ptrFlags, src bundle.Source, ring, verb string) error {
	s, err := rf.signer()
	if err != nil {
		return err
	}
	t, err := rf.target()
	if err != nil {
		return err
	}
	o, vers, err := a.pointerOptions(rf, pf)
	if err != nil {
		return err
	}
	ps, err := bundle.PromoteRing(ctx, t, src, ring, s, o)
	if err != nil {
		return fmt.Errorf("%s -> %s: %w", src, bundle.RingTag(ring), err)
	}
	return a.emitPointers(verb, ring, ps, vers)
}

func (a *app) cmdRefresh() *cobra.Command {
	var ring string
	var rf regFlags
	var pf ptrFlags
	c := &cobra.Command{
		Use:   "refresh",
		Short: "Re-sign a ring's pointer and its experiment channel pointers (same releases, new seq and expiry)",
		Long: "Pointers expire after 7 days and halod then refuses the ring. Run refresh on a schedule\n" +
			"well inside that window (e.g. daily); see .github/workflows/refresh-pointers.yml.example.\n" +
			"The pointers of every client-axis experiment channel the ring's current release routes to\n" +
			"are refreshed too.\n\n" +
			"Refresh re-signs what the registry serves, so it refuses anything that could be a replayed\n" +
			"old pointer: an expired pointer (recover with: halo rollback --to <version>), and, via the\n" +
			"--state-file, a pointer older than the last one this signer wrote. The state file lives at\n" +
			"$XDG_STATE_HOME/halos/pointers.json by default; in CI, cache it between runs, or pass\n" +
			"--expect-digest with the release digest the ring must be serving.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := rf.signer()
			if err != nil {
				return err
			}
			t, err := rf.target()
			if err != nil {
				return err
			}
			o, vers, err := a.pointerOptions(&rf, &pf)
			if err != nil {
				return err
			}
			ps, err := bundle.RefreshRing(cmd.Context(), t, ring, s, o)
			if err != nil {
				return fmt.Errorf("refresh %s: %w", ring, err)
			}
			return a.emitPointers("refreshed", ring, ps, vers)
		},
	}
	c.Flags().StringVar(&ring, "ring", "", "ring to refresh (required)")
	rf.add(c, true, false)
	pf.add(c, "refuse unless the ring currently serves this release digest (sha256:...); the stateless replay guard for CI")
	_ = c.MarkFlagRequired("ring")
	return c
}

func (a *app) cmdRollback() *cobra.Command {
	var ring, to string
	var rf regFlags
	var pf ptrFlags
	c := &cobra.Command{
		Use:   "rollback",
		Short: "Point a ring (and its experiment channels) back at an earlier signed release (version or manifest digest)",
		Long: "--to <version> resolves tag v<version> and refuses the release unless its signed manifest\n" +
			"carries that version (a retagged v-tag is refused); --to sha256:<manifest digest> is content-addressed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			src := bundle.Source{Version: strings.TrimPrefix(to, "v")}
			if strings.HasPrefix(to, "sha256:") {
				src = bundle.Source{Manifest: to}
			}
			return a.retag(cmd.Context(), &rf, &pf, src, ring, "rolled back")
		},
	}
	c.Flags().StringVar(&ring, "ring", "", "ring to roll back (required)")
	c.Flags().StringVar(&to, "to", "", "release version or sha256 manifest digest (required)")
	rf.add(c, true, false)
	pf.add(c, "refuse unless --to names this release digest (sha256:...)")
	_ = c.MarkFlagRequired("ring")
	_ = c.MarkFlagRequired("to")
	return c
}

func (a *app) cmdKeys() *cobra.Command {
	keys := &cobra.Command{Use: "keys", Short: "Signing key management"}
	var dir, name string
	gen := &cobra.Command{
		Use:   "generate",
		Short: "Generate an ed25519 signing key pair (PEM)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			priv, pub := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
			privPEM, pubPEM, err := bundle.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("generate key pair: %w", err)
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create %s: %w", dir, err)
			}
			// O_EXCL: never overwrite (or race) an existing key.
			if err := createExcl(priv, privPEM, 0o600); err != nil {
				return err
			}
			if err := createExcl(pub, pubPEM, 0o644); err != nil {
				_ = os.Remove(priv) // we just created it; don't leave half a pair
				return err
			}
			return a.emit(map[string]string{"private": priv, "public": pub}, func() {
				fmt.Fprintf(a.out, "%s %s (keep secret)\n%s %s\n", a.green("private"), priv, a.green("public "), pub)
			})
		},
	}
	gen.Flags().StringVar(&dir, "out", ".", "output directory")
	gen.Flags().StringVar(&name, "name", "halo", "file base name")
	keys.AddCommand(gen)
	return keys
}

// createExcl writes a new file, failing if p already exists.
func createExcl(p string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; refusing to overwrite", p)
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", p, err)
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("write %s: %w", p, werr)
	}
	if mode&0o077 == 0 { // private key: owner-only DACL on Windows
		if err := fsutil.RestrictToOwner(p); err != nil {
			return fmt.Errorf("create %s: %w", p, err)
		}
	}
	return nil
}

func (a *app) cmdPlan() *cobra.Command {
	var ring, against, ver string
	var rf regFlags
	c := &cobra.Command{
		Use:         "plan",
		Annotations: policyDirAnno,
		Short:       "Diff the release a ring would get against a previous release",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			cur, err := a.buildRelease(dir, ring, ver)
			if err != nil {
				return err
			}
			prev, err := a.openBaseline(cmd.Context(), against, ring, &rf)
			if err != nil {
				return err
			}
			diff := release.Diff(prev, cur)
			bumps := versionBumps(prev, cur)
			return a.emit(map[string]any{"changed": diff != "", "from": prev.Digest, "to": cur.Digest, "versions": bumps, "diff": diff}, func() {
				if diff == "" {
					fmt.Fprintln(a.out, "no changes vs", against)
					return
				}
				for _, l := range strings.Split(strings.TrimRight(diff, "\n"), "\n") {
					switch {
					case strings.HasPrefix(l, "+"):
						l = a.green(l)
					case strings.HasPrefix(l, "-"):
						l = a.red(l)
					}
					fmt.Fprintln(a.out, l)
				}
				fmt.Fprintln(a.out, a.bold("\nversion changes:"))
				for _, b := range bumps {
					fmt.Fprintln(a.out, " ", b)
				}
			})
		},
	}
	c.Flags().StringVar(&ring, "ring", "", "ring to plan (required)")
	c.Flags().StringVar(&against, "against", "", "release.tar or registry ref host/org/name[:tag] (required)")
	c.Flags().StringVar(&ver, "release-version", "0.0.0-dev", "release version label")
	rf.add(c, false, true)
	_ = c.MarkFlagRequired("ring")
	_ = c.MarkFlagRequired("against")
	return c
}

func (a *app) openBaseline(ctx context.Context, against, ring string, rf *regFlags) (*release.Release, error) {
	if st, err := os.Stat(against); err == nil && st.Mode().IsRegular() {
		data, err := os.ReadFile(against)
		if err != nil {
			return nil, err
		}
		rel, err := release.Open(data)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", against, err)
		}
		return rel, nil
	}
	v, err := rf.verifier()
	if err != nil {
		return nil, fmt.Errorf("--against %q is not a file, so it is treated as a registry ref: %w", against, err)
	}
	repo, tag := bundle.ParseRef(against)
	if tag == "" {
		tag = bundle.RingTag(ring)
	}
	t, err := dialRegistry(repo, rf.plainHTTP)
	if err != nil {
		return nil, err
	}
	rel, err := bundle.Pull(ctx, t, tag, v)
	if err != nil {
		return nil, fmt.Errorf("pull %s:%s: %w", repo, tag, err)
	}
	return rel, nil
}

func versionBumps(prev, cur *release.Release) []string {
	seen := map[string]bool{}
	var names []string
	for _, m := range []map[string]release.HarnessEntry{prev.Manifest.Harnesses, cur.Manifest.Harnesses} {
		for n := range m {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	out := []string{}
	for _, n := range names {
		p, hadP := prev.Manifest.Harnesses[n]
		c, hadC := cur.Manifest.Harnesses[n]
		switch {
		case !hadP:
			out = append(out, fmt.Sprintf("%s: added at %s", n, c.Version))
		case !hadC:
			out = append(out, fmt.Sprintf("%s: removed (was %s)", n, p.Version))
		case p.Version != c.Version:
			out = append(out, fmt.Sprintf("%s: %s -> %s", n, p.Version, c.Version))
		default:
			out = append(out, fmt.Sprintf("%s: %s (unchanged)", n, c.Version))
		}
	}
	return out
}

// parseHalodSHA256 turns "darwin/arm64=<hex>" entries into the mdm map.
func parseHalodSHA256(entries []string) (map[string]string, error) {
	m := map[string]string{}
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("--halod-sha256 %q: want <os>/<arch>=<hex>", e)
		}
		m[k] = v
	}
	return m, nil
}

func (a *app) cmdExport() *cobra.Command {
	var out, registry, pubkey, dlURL, ring, org string
	var plainHTTP bool
	var sha []string
	c := &cobra.Command{Use: "export", Short: "Export a signed release for a delivery channel"}

	// pull fetches the release the ring's SIGNED POINTER names (exactly what
	// halod applies: pointer signature, --org, ring and expiry are checked, then
	// the release signature), never whatever a mutable ring tag points at.
	// The returned Verifier accepts only that exact release object, so
	// exporters cannot be handed anything unverified.
	pull := func(ctx context.Context, pem []byte) (*release.Release, mdm.Verifier, error) {
		switch {
		case ring == "":
			return nil, nil, errors.New("--ring is required")
		case org == "":
			return nil, nil, errors.New("--org is required: the ring's signed pointer must be for this org")
		}
		v, err := bundle.ParseEd25519Verifier(pem)
		if err != nil {
			return nil, nil, fmt.Errorf("parse --pubkey: %w", err)
		}
		repo, tag := bundle.ParseRef(registry)
		if tag != "" {
			return nil, nil, fmt.Errorf("--registry %q must not name a tag: export follows ring %s's signed pointer", registry, ring)
		}
		t, err := dialRegistry(repo, plainHTTP)
		if err != nil {
			return nil, nil, err
		}
		rel, _, err := bundle.PullRing(ctx, t, v, bundle.RingOptions{Org: org, Ring: ring, Now: time.Now()})
		if err != nil {
			return nil, nil, fmt.Errorf("pull ring %s from %s: %w", ring, repo, err)
		}
		return rel, func(r *release.Release) error {
			if r != rel {
				return errors.New("release was not the one verified by bundle.PullRing")
			}
			return nil
		}, nil
	}
	// common validates and reads the flags every channel needs.
	common := func() (pem []byte, repo string, shas map[string]string, err error) {
		if registry == "" {
			return nil, "", nil, errors.New("--registry is required")
		}
		if pubkey == "" {
			return nil, "", nil, errors.New("--pubkey is required (ed25519 public key PEM, embedded inline)")
		}
		if pem, err = os.ReadFile(pubkey); err != nil {
			return nil, "", nil, fmt.Errorf("read public key: %w", err)
		}
		if shas, err = parseHalodSHA256(sha); err != nil {
			return nil, "", nil, err
		}
		repo, _ = bundle.ParseRef(registry)
		return pem, repo, shas, nil
	}
	write := func(files map[string][]byte) error {
		names := make([]string, 0, len(files))
		for n, data := range files {
			mode := os.FileMode(0o644)
			if strings.HasSuffix(n, ".sh") {
				mode = 0o755
			}
			if err := writeFile(safeJoin(out, n), data, mode); err != nil {
				return err
			}
			names = append(names, safeJoin(out, n))
		}
		sort.Strings(names)
		return a.emit(map[string]any{"files": names}, func() {
			for _, n := range names {
				fmt.Fprintln(a.out, a.green("write"), n)
			}
		})
	}

	dc := &cobra.Command{
		Use: "devcontainer", Short: "Dev Container Feature source with org defaults baked in", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pem, repo, shas, err := common()
			if err != nil {
				return err
			}
			// The feature installs halod on linux only, as "amd64=<hex>,arm64=<hex>".
			la, lr := shas["linux/amd64"], shas["linux/arm64"]
			if la == "" || lr == "" {
				return errors.New("devcontainer needs --halod-sha256 linux/amd64=<hex> and linux/arm64=<hex>")
			}
			o := devcontainer.Options{Registry: repo, Org: org, Ring: ring, PubKeyPEM: string(pem), HalodSHA256: "amd64=" + la + ",arm64=" + lr}
			var rel *release.Release
			var v mdm.Verifier
			if ring != "" { // ring given: also pull and verify the release it points at
				if rel, v, err = pull(cmd.Context(), pem); err != nil {
					return err
				}
			}
			files, err := devcontainer.Export(rel, o, v)
			if err != nil {
				return err
			}
			return write(files)
		},
	}

	halodOpts := func(rel *release.Release, pem []byte, repo string, shas map[string]string) mdm.HalodOptions {
		return mdm.HalodOptions{Registry: repo, Org: rel.Manifest.Org, Ring: ring, PubKeyPEM: string(pem), DownloadURL: dlURL, HalodSHA256: shas}
	}
	jamf := &cobra.Command{
		Use: "jamf", Short: "Jamf/Kandji .mobileconfig plus halod postinstall", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pem, repo, shas, err := common()
			if err != nil {
				return err
			}
			rel, v, err := pull(cmd.Context(), pem)
			if err != nil {
				return err
			}
			b, err := mdm.ExportJamf(rel, v)
			if err != nil {
				return err
			}
			post, err := mdm.JamfPostinstall(halodOpts(rel, pem, repo, shas))
			if err != nil {
				return err
			}
			return write(map[string][]byte{"halos.mobileconfig": b, "postinstall.sh": post})
		},
	}
	intune := &cobra.Command{
		Use: "intune", Short: "Intune PowerShell script writing the Claude Code registry policy", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pem, repo, shas, err := common()
			if err != nil {
				return err
			}
			rel, v, err := pull(cmd.Context(), pem)
			if err != nil {
				return err
			}
			b, err := mdm.ExportIntune(rel, halodOpts(rel, pem, repo, shas), v)
			if err != nil {
				return err
			}
			return write(map[string][]byte{"halos-intune.ps1": b})
		},
	}
	pf := c.PersistentFlags()
	pf.StringVar(&registry, "registry", "", "registry repo the release is pulled from (required)")
	pf.StringVar(&ring, "ring", "", "ring to export (required for jamf/intune)")
	pf.StringVar(&org, "org", "", "org name; pins the org the ring's signed pointer must carry (required with --ring)")
	pf.StringVar(&pubkey, "pubkey", "", "ed25519 public key PEM: verifies the release and is embedded inline (required)")
	pf.BoolVar(&plainHTTP, "plain-http", false, "use HTTP instead of HTTPS (local registries)")
	pf.StringSliceVar(&sha, "halod-sha256", nil, "sha256 of the halod binary as <os>/<arch>=<hex>; repeatable or comma-separated")
	pf.StringVar(&out, "out", "halo-export", "output directory")
	pf.StringVar(&dlURL, "download-url", "", "https halod download URL ({os}/{arch} substituted; jamf/intune)")
	c.AddCommand(dc, jamf, intune)
	return c
}
