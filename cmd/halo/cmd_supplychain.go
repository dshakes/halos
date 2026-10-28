package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/supplychain"
)

// Agent supply chain (ADR-0028): fetch and verify extension artifacts for a
// release build, attach the AI-BOM and provenance, and the `halo artifact`
// and `halo release bom` commands.

// gitRun runs git for artifact fetches; nil runs the git on PATH.
var gitRun supplychain.GitRunner

const strictHelp = "treat supply-chain scan findings as errors (same as supplyChain.scan: enforce)"

// strictScan applies --strict: scan findings become errors.
func strictScan(org *policy.Org, strict bool) {
	if !strict {
		return
	}
	if org.SupplyChain == nil {
		org.SupplyChain = &policy.SupplyChain{}
	}
	org.SupplyChain.Scan = policy.ScanEnforce
}

// errSupplyChain wraps every resolveSupplyChain failure (fetch, digest or
// signature), so callers can tell it from other build errors.
var errSupplyChain = errors.New("supply chain")

// resolveSupplyChain fetches git and oci artifacts into org (each checked
// against its pinned digest) and verifies every declared signature. Release
// builds run it; `halo validate` stays offline and scans path artifacts only.
func (a *app) resolveSupplyChain(ctx context.Context, dir string, org *policy.Org) error {
	sc := org.SupplyChain
	if sc == nil {
		return nil
	}
	if org.ArtifactContent == nil {
		org.ArtifactContent = map[string]*policy.ArtifactContent{}
	}
	for _, art := range sc.Artifacts {
		c := org.ArtifactContent[art.Name]
		if art.Remote() && (c == nil || c.Files == nil) {
			t, err := fetchArtifact(ctx, art)
			if err != nil {
				return fmt.Errorf("%w: artifact %s: %w", errSupplyChain, art.Name, err)
			}
			if got := t.Digest(); got != art.Digest {
				return fmt.Errorf("%w: artifact %s (%s): content digest %s does not match the pinned %s", errSupplyChain, art.Name, art.Source(), got, art.Digest)
			}
			c = &policy.ArtifactContent{Files: t}
			org.ArtifactContent[art.Name] = c
		}
		if art.Signature == nil || c == nil || c.Files == nil {
			continue
		}
		if err := verifyArtifactSig(ctx, dir, sc, art, c.Files.Digest()); err != nil {
			return fmt.Errorf("%w: artifact %s: %w", errSupplyChain, art.Name, err)
		}
		c.Signer = art.Signature.Identity
	}
	return nil
}

func fetchArtifact(ctx context.Context, art policy.Artifact) (supplychain.Tree, error) {
	if g := art.Git; g != nil {
		return supplychain.FetchGit(ctx, g.URL, g.Commit, g.Path, gitRun)
	}
	repo, dgst, err := supplychain.SplitOCIRef(art.OCI)
	if err != nil {
		return nil, err
	}
	t, err := dialRegistry(repo, false)
	if err != nil {
		return nil, err
	}
	return supplychain.FetchOCI(ctx, t, dgst)
}

// verifyArtifactSig checks art's signature over digest with its trusted
// identity, through the same verifiers releases use (internal/bundle).
func verifyArtifactSig(ctx context.Context, dir string, sc *policy.SupplyChain, art policy.Artifact, digest string) error {
	i := slices.IndexFunc(sc.TrustedIdentities, func(id policy.TrustedIdentity) bool { return id.Name == art.Signature.Identity })
	if i < 0 {
		return fmt.Errorf("signature identity %q is not in supplyChain.trustedIdentities", art.Signature.Identity)
	}
	id := sc.TrustedIdentities[i]
	raw, err := os.ReadFile(inRepo(dir, art.Signature.File))
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	var v bundle.Verifier
	sig := raw
	if id.PublicKey != "" {
		pem, err := os.ReadFile(inRepo(dir, id.PublicKey))
		if err != nil {
			return fmt.Errorf("identity %s: read public key: %w", id.Name, err)
		}
		if v, err = bundle.ParseEd25519Verifier(pem); err != nil {
			return fmt.Errorf("identity %s: %w", id.Name, err)
		}
		if sig, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err != nil {
			return fmt.Errorf("signature %s is not base64: %w", art.Signature.File, err)
		}
	} else {
		key := id.CosignKey
		if !strings.Contains(key, "://") && !filepath.IsAbs(key) {
			key = inRepo(dir, key)
		}
		v = bundle.Cosign{Key: key}
	}
	if err := v.Verify(ctx, digest, sig); err != nil {
		return fmt.Errorf("signature by %s over %s does not verify: %w", id.Name, digest, err)
	}
	return nil
}

func inRepo(dir, rel string) string { return filepath.Join(dir, filepath.FromSlash(rel)) }

// attest sets rel's AI-BOM and provenance (release.Attest) from the policy
// repo's git state, when dir is in a git work tree.
func (a *app) attest(dir string, org *policy.Org, rel *release.Release) error {
	o := release.AttestOptions{HalosVersion: version}
	git := func(args ...string) string {
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	if o.PolicyCommit = git("rev-parse", "HEAD"); o.PolicyCommit != "" {
		o.PolicyDirty = git("status", "--porcelain", "--", ".") != ""
		o.PolicyRepo = redactURL(git("config", "--get", "remote.origin.url"))
	}
	att, err := release.Attest(rel, org, o)
	if err != nil {
		return err
	}
	rel.Attestations = att
	return nil
}

// redactURL drops credentials from a remote URL (https://user:token@host/...).
func redactURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.User != nil {
		u.User = nil
		return u.String()
	}
	return s
}

// attestationFiles are where `halo release build -o out` writes the BOM and
// provenance next to the tar.
func attestationFiles(out string) (bom, prov string) {
	return out + ".bom.cdx.json", out + ".intoto.json"
}

func (a *app) cmdArtifact() *cobra.Command {
	c := &cobra.Command{Use: "artifact", Short: "Digest, scan and sign agent extension artifacts (skills, plugins, hooks, commands, agents; ADR-0028)"}
	digest := &cobra.Command{
		Use:   "digest <path>",
		Short: "Print the artifact digest of a file or directory, to pin it in supplyChain.artifacts[].digest",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			t, err := supplychain.ReadPath(args[0])
			if err != nil {
				return err
			}
			return a.emit(map[string]any{"digest": t.Digest(), "files": t.Sums()}, func() { fmt.Fprintln(a.out, t.Digest()) })
		},
	}
	scan := &cobra.Command{
		Use:   "scan <path>",
		Short: "Run the supply-chain static scan over a file or directory (exit 2 on findings)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			t, err := supplychain.ReadPath(args[0])
			if err != nil {
				return err
			}
			fs := supplychain.Scan(t)
			if err := a.emit(map[string]any{"digest": t.Digest(), "findings": fs}, func() {
				for _, f := range fs {
					fmt.Fprintln(a.out, a.yellow("finding"), f)
				}
				if len(fs) == 0 {
					fmt.Fprintln(a.out, a.green("OK")+": no findings ("+t.Digest()+")")
				}
			}); err != nil {
				return err
			}
			if len(fs) > 0 {
				return &exitErr{code: exitValidation}
			}
			return nil
		},
	}
	var key, out string
	sign := &cobra.Command{
		Use:   "sign <path>",
		Short: "Sign an artifact's digest with an ed25519 key (base64 signature for supplyChain.artifacts[].signature.file)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := supplychain.ReadPath(args[0])
			if err != nil {
				return err
			}
			pem, err := os.ReadFile(key)
			if err != nil {
				return fmt.Errorf("read signing key: %w", err)
			}
			s, err := bundle.ParseEd25519Signer(pem)
			if err != nil {
				return err
			}
			sig, err := s.Sign(cmd.Context(), t.Digest())
			if err != nil {
				return err
			}
			enc := base64.StdEncoding.EncodeToString(sig) + "\n"
			if out == "" {
				_, err = fmt.Fprint(a.out, enc)
				return err
			}
			return writeFile(out, []byte(enc), 0o644)
		},
	}
	sign.Flags().StringVar(&key, "key", "", "ed25519 private key PEM (halo keys generate)")
	sign.Flags().StringVarP(&out, "out", "o", "", "write the signature here instead of stdout")
	_ = sign.MarkFlagRequired("key")
	c.AddCommand(digest, scan, sign)
	return c
}

func (a *app) cmdReleaseBOM() *cobra.Command {
	var prov bool
	var rf regFlags
	c := &cobra.Command{
		Use:   "bom <release.tar | host/org/name:tag>",
		Short: "Print and verify a release's CycloneDX AI-BOM (or --provenance, its in-toto SLSA provenance)",
		Long: "A local release.tar is checked against the release.tar.bom.cdx.json and release.tar.intoto.json\n" +
			"that `halo release build` wrote beside it (not signed). A registry ref is pulled with --pubkey or\n" +
			"--cosign-key: the release signature, the attestation signature and their content must all verify.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rel, att, signed, err := a.loadAttestations(cmd.Context(), args[0], &rf)
			if err != nil {
				return err
			}
			doc := att.BOM
			if prov {
				doc = att.Provenance
			}
			return a.emit(map[string]any{"release": rel.Digest, "signed": signed, "verified": true,
				"bom": json.RawMessage(att.BOM), "provenance": json.RawMessage(att.Provenance)}, func() {
				_, _ = a.out.Write(doc)
				fmt.Fprintln(a.out)
				how := "unsigned local build"
				if signed {
					how = "signature verified"
				}
				fmt.Fprintf(a.errw, "%s attestations match release %s (%s)\n", a.green("verified"), rel.Digest, how)
			})
		},
	}
	c.Flags().BoolVar(&prov, "provenance", false, "print the provenance instead of the BOM")
	rf.add(c, false, true)
	return c
}

func (a *app) loadAttestations(ctx context.Context, ref string, rf *regFlags) (*release.Release, *release.Attestations, bool, error) {
	if st, err := os.Stat(ref); err == nil && st.Mode().IsRegular() {
		data, err := os.ReadFile(ref)
		if err != nil {
			return nil, nil, false, err
		}
		rel, err := release.Open(data)
		if err != nil {
			return nil, nil, false, fmt.Errorf("open %s: %w", ref, err)
		}
		bp, pp := attestationFiles(ref)
		bom, err := os.ReadFile(bp)
		if err != nil {
			return nil, nil, false, fmt.Errorf("read BOM: %w", err)
		}
		prov, err := os.ReadFile(pp)
		if err != nil {
			return nil, nil, false, fmt.Errorf("read provenance: %w", err)
		}
		if err := release.VerifyAttestations(rel, bom, prov); err != nil {
			return nil, nil, false, fmt.Errorf("%s: %w", ref, err)
		}
		return rel, &release.Attestations{BOM: bom, Provenance: prov}, false, nil
	}
	v, err := rf.verifier()
	if err != nil {
		return nil, nil, false, fmt.Errorf("%q is not a file, so it is treated as a registry ref: %w", ref, err)
	}
	repo, tag := bundle.ParseRef(ref)
	if tag == "" {
		return nil, nil, false, errors.New("registry ref needs a tag, e.g. ghcr.io/acme/halos:v1.4.0")
	}
	t, err := dialRegistry(repo, rf.plainHTTP)
	if err != nil {
		return nil, nil, false, err
	}
	g, ok := t.(oras.ReadOnlyGraphTarget)
	if !ok {
		return nil, nil, false, fmt.Errorf("registry %s cannot list referrers", repo)
	}
	rel, atts, err := bundle.PullAttestations(ctx, g, tag, v)
	if err != nil {
		return nil, nil, false, err
	}
	return rel, atts[len(atts)-1], true, nil
}
