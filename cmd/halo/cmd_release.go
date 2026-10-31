package main

import (
	"cmp"
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
	"github.com/dshakes/halos/internal/impact"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/signer"
)

// dialRegistry opens a registry repo ("host/org/name"); tests replace it.
var dialRegistry = func(repo string, plainHTTP bool) (oras.Target, error) {
	return bundle.Repository(repo, plainHTTP)
}

type regFlags struct {
	registry       string
	plainHTTP      bool
	key, keyURI    string
	coKeyURI       string
	cosign, pubkey string
	keyless        bool
}

func (r *regFlags) add(c *cobra.Command, sign, verify bool) {
	c.Flags().StringVar(&r.registry, "registry", "", "registry repo, e.g. ghcr.io/acme/halos")
	c.Flags().BoolVar(&r.plainHTTP, "plain-http", false, "use HTTP instead of HTTPS (local registries)")
	if sign {
		c.Flags().StringVar(&r.key, "key", "", "ed25519 or ECDSA P-256 private key PEM (create one with: halo keys generate)")
		c.Flags().StringVar(&r.keyURI, "key-uri", "", "signing key by URI instead of --key: file://PATH, awskms://KEY?region=R, exec:///SIGNER (see halo keys public)")
		c.Flags().StringVar(&r.coKeyURI, "co-key-uri", "", "second key (other algorithm) that co-signs releases and pointers while rotating, so halods that trust only it keep verifying")
		c.Flags().StringVar(&r.cosign, "cosign-key", "", "cosign key reference (file or KMS URI); co-signs alongside --key")
		c.Flags().BoolVar(&r.keyless, "cosign-keyless", false, "cosign keyless (Fulcio+Rekor): uploads the release digest to the public transparency log")
	}
	if verify {
		c.Flags().StringVar(&r.pubkey, "pubkey", "", "ed25519 or ECDSA P-256 public key PEM to verify with")
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

func (r *regFlags) signer(ctx context.Context) (bundle.Signer, error) {
	var uri string
	switch {
	case r.key != "" && r.keyURI != "":
		return nil, errors.New("use only one of --key and --key-uri")
	case r.key != "":
		uri = "file://" + r.key
	case r.keyURI != "":
		uri = r.keyURI
	case r.cosign != "" || r.keyless:
		return nil, errors.New("halod verifies ed25519 or ECDSA P-256; add --key or --key-uri (cosign can only co-sign)")
	default:
		return nil, errors.New("a signing key is required: --key or --key-uri")
	}
	ks, err := signer.Open(ctx, uri, signer.Options{})
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	ms := bundle.MultiSigner{ks}
	if r.coKeyURI != "" {
		co, err := signer.Open(ctx, r.coKeyURI, signer.Options{})
		if err != nil {
			return nil, fmt.Errorf("--co-key-uri: %w", err)
		}
		if co.Type() == ks.Type() {
			return nil, fmt.Errorf("--co-key-uri is %s like the signing key: a co-signing key must use the other algorithm (halods read one signature per algorithm)", co.Type())
		}
		ms = append(ms, co)
	}
	if r.cosign != "" || r.keyless {
		ms = append(ms, bundle.Cosign{Key: r.cosign, Keyless: r.keyless})
	}
	if len(ms) == 1 {
		return ks, nil
	}
	return ms, nil
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
		return bundle.ParseVerifier(pem)
	}
	return nil, errors.New("a verification key is required: --pubkey or --cosign-key")
}

func (a *app) cmdRelease() *cobra.Command {
	c := &cobra.Command{Use: "release", Short: "Build, publish and promote releases"}

	var ring, out, ver, dir string
	var noArt, strict bool
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
			rel, org, err := a.buildRelease(cmd.Context(), dir, ring, ver, strict)
			if err != nil {
				return err
			}
			if rel, err = a.resolveArtifacts(cmd.Context(), rel, noArt); err != nil {
				return err
			}
			if err := a.attest(dir, org, rel); err != nil {
				return err
			}
			bomFile, provFile := attestationFiles(out)
			for _, w := range []struct {
				path string
				data []byte
			}{{out, rel.Tar}, {bomFile, rel.Attestations.BOM}, {provFile, rel.Attestations.Provenance}} {
				if err := writeFile(w.path, w.data, 0o644); err != nil {
					return fmt.Errorf("write %s: %w", w.path, err)
				}
			}
			return a.emit(map[string]string{"file": out, "digest": rel.Digest, "version": rel.Manifest.Version, "ring": ring, "bom": bomFile, "provenance": provFile}, func() {
				fmt.Fprintf(a.out, "%s %s (%s); AI-BOM %s, provenance %s\n", a.green("built"), out, rel.Digest, bomFile, provFile)
			})
		},
	}
	build.Flags().BoolVar(&strict, "strict", false, strictHelp)
	build.Flags().StringVar(&ring, "ring", "", "ring to build (required)")
	build.Flags().StringVarP(&out, "out", "o", "release.tar", "output tarball")
	build.Flags().StringVar(&ver, "release-version", "0.0.0-dev", "release version label")
	build.Flags().BoolVar(&noArt, "no-artifacts", false, noArtHelp)

	var pRing, pVer string
	var pNoArt, pStrict bool
	var pf regFlags
	var ppf ptrFlags
	publish := &cobra.Command{
		Use:         "publish",
		Annotations: policyDirAnno,
		Short:       "Build, sign and push a ring release (and its client-axis experiment channels); tags v<version> and ring-<ring>",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := pf.signer(cmd.Context())
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
			rel, variants, org, err := a.buildRing(cmd.Context(), dir, pRing, pVer, pStrict)
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
			for _, r := range append([]*release.Release{rel}, variants...) {
				if err := a.attest(dir, org, r); err != nil {
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
	publish.Flags().BoolVar(&pStrict, "strict", false, strictHelp)
	pf.add(publish, true, false)
	ppf.add(publish, "")
	_ = publish.MarkFlagRequired("release-version")

	var from, to string
	var prf regFlags
	var pp ptrFlags
	promote := &cobra.Command{
		Use:         "promote",
		Annotations: policyDirAnno,
		Short:       "Point --to-ring at the release --from-ring's signed pointer names; experiment channels stay with the ring they were built for",
		Long: "The source release is taken from --from-ring's signed pointer (signature, ring, org, expiry and\n" +
			"--state-file continuity checked), never from the unauthenticated ring-<name> tag.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, r := range []struct{ flag, v string }{{"from-ring", from}, {"to-ring", to}} {
				if r.v == "" {
					return a.needRing(cmd, r.flag)
				}
			}
			return a.retag(cmd.Context(), &prf, &pp, bundle.Source{Ring: from}, to, "promoted")
		},
	}
	promote.Flags().StringVar(&from, "from-ring", "", "source ring (required)")
	promote.Flags().StringVar(&to, "to-ring", "", "destination ring (required)")
	prf.add(promote, true, false)
	pp.add(promote, "refuse unless --from-ring serves this release digest (sha256:...)")

	c.AddCommand(build, publish, promote, a.cmdRefresh(), a.cmdReleaseBOM())
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
	s, err := rf.signer(ctx)
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
		Use:         "refresh",
		Annotations: policyDirAnno,
		Short:       "Re-sign a ring's pointer and its experiment channel pointers (same releases, new seq and expiry)",
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
			if ring == "" {
				return a.needRing(cmd, "ring")
			}
			s, err := rf.signer(cmd.Context())
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
	return c
}

func (a *app) cmdRollback() *cobra.Command {
	var ring, to string
	var rf regFlags
	var pf ptrFlags
	c := &cobra.Command{
		Use:         "rollback",
		Annotations: policyDirAnno,
		Short:       "Point a ring (and its experiment channels) back at an earlier signed release (version or manifest digest)",
		Long: "--to <version> resolves tag v<version> and refuses the release unless its signed manifest\n" +
			"carries that version (a retagged v-tag is refused); --to sha256:<manifest digest> is content-addressed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ring == "" { // rollback never defaults a ring
				return a.needRing(cmd, "ring")
			}
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
	_ = c.MarkFlagRequired("to")
	return c
}

func (a *app) cmdKeys() *cobra.Command {
	keys := &cobra.Command{Use: "keys", Short: "Signing key management"}
	var dir, name string
	var force bool
	gen := &cobra.Command{
		Use:   "generate",
		Short: "Generate an ed25519 signing key pair (PEM)",
		Long: "Writes <name>.key (private, 0600) and <name>.pub. Without --out the pair goes to the per-user config\n" +
			"directory (<user config dir>/halos/keys, 0700), never the current directory: that is often a policy repo,\n" +
			"where `git add -A` would commit the private key. A private key is refused inside a git work tree\n" +
			"unless --force.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dirMode := os.FileMode(0o755)
			if !cmd.Flags().Changed("out") {
				cfg, err := os.UserConfigDir()
				if err != nil {
					return fmt.Errorf("no per-user config directory to keep the key in (%w): pass --out DIR", err)
				}
				dir, dirMode = filepath.Join(cfg, "halos", "keys"), 0o700
			}
			if root, ok := gitWorkTree(dir); ok && !force {
				return fmt.Errorf("%s is inside the git work tree %s: a committed signing key lets anyone sign releases. "+
					"Write it elsewhere (--out DIR outside the repo; the default is the per-user config directory) "+
					"or pass --force if you will git-ignore it", dir, root)
			}
			priv, pub := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
			privPEM, pubPEM, err := bundle.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("generate key pair: %w", err)
			}
			if err := os.MkdirAll(dir, dirMode); err != nil {
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
	gen.Flags().StringVar(&dir, "out", "", "output directory (default: <user config dir>/halos/keys)")
	gen.Flags().StringVar(&name, "name", "halo", "file base name")
	gen.Flags().BoolVar(&force, "force", false, "write the key even inside a git work tree (git-ignore it yourself)")
	keys.AddCommand(gen, a.cmdKeysPublic())
	return keys
}

// cmdKeysPublic exports a signing key's public half (PKIX PEM) for halod's
// pubKeys, killSwitch.pubkey, the portal and --pubkey: the only way to get it
// for a KMS or HSM key, whose private half never leaves the device.
func (a *app) cmdKeysPublic() *cobra.Command {
	var uri, out string
	c := &cobra.Command{
		Use:   "public",
		Short: "Export the public key (PEM) and key id of a signing key: file://, awskms:// or exec://",
		Long: "Opens the key the URI names and prints its public key as PKIX PEM, plus its algorithm and key id\n" +
			"(the fingerprint halod logs and revokedKeys takes). Key URIs:\n" +
			"  file://PATH (or PATH)                 PKCS#8 PEM ed25519 or ECDSA P-256 private key\n" +
			"  awskms://KEY[?region=R&fips=true]     AWS KMS SIGN_VERIFY key, ECC_NIST_P256 or ECC_NIST_EDWARDS25519;\n" +
			"                                        KEY is a key id, key ARN, alias/<name> or alias ARN; needs kms:GetPublicKey\n" +
			"  exec:///ABS/PATH[?arg=A&key=ID]       external signer (halos.signer.v1 JSON protocol over stdin/stdout)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if uri == "" {
				return errors.New("--key-uri is required")
			}
			ks, err := signer.Open(cmd.Context(), uri, signer.Options{})
			if err != nil {
				return err
			}
			pv, ok := ks.Verifier().(bundle.PublicKeyVerifier)
			if !ok {
				return fmt.Errorf("%s has no exportable public key", signer.Scheme(uri))
			}
			pemOut, err := bundle.MarshalPublicKeyPEM(pv)
			if err != nil {
				return err
			}
			if out != "" {
				if err := createExcl(out, pemOut, 0o644); err != nil {
					return err
				}
			}
			res := map[string]string{"algorithm": ks.Type(), "keyId": bundle.KeyID(pv), "backend": signer.Scheme(uri), "publicKey": string(pemOut)}
			if out != "" {
				res["file"] = out
			}
			return a.emit(res, func() {
				if out == "" {
					fmt.Fprint(a.out, string(pemOut))
				}
				fmt.Fprintf(a.errw, "algorithm %s, key id %s\n", ks.Type(), bundle.KeyID(pv))
			})
		},
	}
	c.Flags().StringVar(&uri, "key-uri", "", "signing key URI (file://, awskms://, exec://)")
	c.Flags().StringVar(&out, "out", "", "also write the PEM to this file (refuses to overwrite)")
	return c
}

// gitWorkTree reports the nearest enclosing directory of dir (which need not
// exist yet) that holds a .git entry: a work tree, or a worktree or submodule
// whose .git is a file.
func gitWorkTree(dir string) (string, bool) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d, true
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", false
		}
		d = parent
	}
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
	var ring, against, ver, diffBase string
	var rf regFlags
	var sf serverFlags
	c := &cobra.Command{
		Use:         "plan",
		Annotations: policyDirAnno,
		Short:       "Diff the release each ring (or --ring) would get against a previous release, and with --diff who is affected",
		Long: "Without --ring every ring is planned. --diff <git ref> diffs against the policy at that ref (the\n" +
			"releases it builds, unless --against is set) and previews the impact: how many users, devices and\n" +
			"agents change ring, experiment variant or effective settings, by org unit, with examples. The\n" +
			"population is halo-server's enrolled fleet with --server (or HALO_SERVER) and HALO_SESSION, else a\n" +
			"policy-only estimate. Assignment uses the same hashing as the fleet (internal/assign).\n" +
			"A --diff base whose supply-chain artifacts cannot be fetched or verified is an error (fix access, or\n" +
			"pass --against with a built release); a ring the base cannot build otherwise diffs as a first release.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := policyDir(cmd, args)
			if err != nil {
				return err
			}
			baseDir := ""
			if diffBase != "" {
				d, cleanup, err := impact.CheckoutAt(cmd.Context(), dir, diffBase)
				if err != nil {
					return err
				}
				defer cleanup()
				baseDir = d
			}
			rings := []string{ring}
			if ring == "" {
				if rings, err = a.ringNames(dir); err != nil {
					return err
				}
			}
			var plans []map[string]any
			var texts []func()
			for _, rg := range rings {
				p, text, err := a.planRing(cmd, dir, baseDir, rg, against, ver, &rf)
				if err != nil {
					return err
				}
				plans, texts = append(plans, p), append(texts, text)
			}
			var rep *impact.Report
			if diffBase != "" {
				if rep, err = a.planImpact(cmd, dir, baseDir, sf); err != nil {
					return err
				}
			}
			out := map[string]any{"rings": plans}
			if ring != "" {
				out = plans[0] // one ring: the shape it has always had
			}
			if rep != nil {
				out["impact"] = rep
			}
			return a.emit(out, func() {
				for i, text := range texts {
					if ring == "" {
						fmt.Fprintf(a.out, "%s %s\n", a.bold("ring"), a.bold(rings[i]))
					}
					text()
					if ring == "" {
						fmt.Fprintln(a.out)
					}
				}
				if rep != nil {
					fmt.Fprint(a.out, rep.Text(diffBase))
				}
			})
		},
	}
	c.Flags().StringVar(&ring, "ring", "", "ring to plan (default: every ring)")
	c.Flags().StringVar(&against, "against", "", "release.tar or registry ref host/org/name[:tag] (default: the --diff policy's release, else none: the first release)")
	c.Flags().StringVar(&ver, "release-version", "0.0.0-dev", "release version label")
	c.Flags().StringVar(&diffBase, "diff", "", "git ref of the policy to compare with (e.g. main): release diffs from it, plus the impact preview")
	sf.add(c, "for the impact preview over the enrolled fleet")
	rf.add(c, false, true)
	return c
}

// planRing diffs ring's release against --against, else the base policy's
// release for the ring (baseDir), else nothing (a first release).
func (a *app) planRing(cmd *cobra.Command, dir, baseDir, ring, against, ver string, rf *regFlags) (map[string]any, func(), error) {
	cur, _, err := a.buildRelease(cmd.Context(), dir, ring, ver, false)
	if err != nil {
		return nil, nil, err
	}
	prev := &release.Release{} // no --against: the first release, so everything is new
	switch {
	case against != "":
		if prev, err = a.openBaseline(cmd.Context(), against, ring, rf); err != nil {
			return nil, nil, err
		}
	case baseDir != "":
		if b, _, err := a.buildRelease(cmd.Context(), baseDir, ring, ver, false); err == nil {
			prev = b
		} else if errors.Is(err, errSupplyChain) {
			// Diffing against an empty release would show every setting as new.
			return nil, nil, fmt.Errorf("ring %s at the --diff base: %w; the diff needs the base's artifacts: fix access to it (network, git or registry credentials), or diff against a built release with --against", ring, err)
		} else {
			fmt.Fprintf(a.errw, "%s ring %s at the --diff base does not build (%v); diffing against an empty release\n", a.yellow("warning:"), ring, err)
		}
	}
	diff := release.Diff(prev, cur)
	bumps := versionBumps(prev, cur)
	return map[string]any{"ring": ring, "changed": diff != "", "from": prev.Digest, "to": cur.Digest, "versions": bumps, "diff": diff}, func() {
		if diff == "" {
			fmt.Fprintln(a.out, "no changes vs", cmp.Or(against, "the --diff base"))
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
	}, nil
}

// ringNames lists the policy's rings in order.
func (a *app) ringNames(dir string) ([]string, error) {
	org, err := a.loadValid(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range org.Rings {
		out = append(out, r.Name)
	}
	if len(out) == 0 {
		return nil, errors.New("policy defines no rings")
	}
	return out, nil
}

// planImpact previews who the change from baseDir's policy to dir's affects:
// the enrolled fleet when a halo-server is configured, else a policy estimate.
func (a *app) planImpact(cmd *cobra.Command, dir, baseDir string, sf serverFlags) (*impact.Report, error) {
	cur, err := a.loadValid(dir)
	if err != nil {
		return nil, err
	}
	base, err := a.load(baseDir)
	if err != nil {
		return nil, fmt.Errorf("policy at the --diff base: %w", err)
	}
	srv, session, err := sf.resolve()
	if err != nil {
		return nil, err
	}
	var members []impact.Member
	source := "policy"
	if srv != "" {
		var fleet struct {
			Hosts []impact.FleetHost `json:"hosts"`
		}
		var devs []impact.FleetDevice
		if err := sessionJSON(cmd.Context(), srv, session, "GET", "/api/v1/fleet", nil, &fleet); err != nil {
			return nil, fmt.Errorf("impact: %w", err)
		}
		if err := sessionJSON(cmd.Context(), srv, session, "GET", "/api/v1/devices", nil, &devs); err != nil {
			return nil, fmt.Errorf("impact: %w", err)
		}
		members, source = impact.FleetMembers(fleet.Hosts, devs, base, cur), "fleet"
	} else {
		members = impact.PolicyMembers(impactSamples, base, cur)
	}
	rep := impact.Compute(base, cur, members, impactExamples)
	rep.Source = source
	return &rep, nil
}

// impactSamples is the hashed sample size of a policy-only estimate (0.1%
// resolution at 1000; ring and variant cuts are 0.01%, so smaller shares
// show as an approximate percentage).
const (
	impactSamples  = 1000
	impactExamples = 8
)

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
		v, err := bundle.ParseVerifier(pem)
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
