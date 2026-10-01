// Package devcontainer exports the Halos Dev Container Feature source
// (features/halos) with option defaults baked in for one org/ring.
//
// The feature applies a per-org egress firewall only when firewall=true, which
// needs the container to run with NET_ADMIN and NET_RAW. The firewall starts at
// container start (feature entrypoint), not at image build.
package devcontainer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/dshakes/halos/features"
	"github.com/dshakes/halos/internal/delivery/mdm"
	"github.com/dshakes/halos/internal/release"
)

// Options override the feature's option defaults. Empty fields keep the default.
type Options struct {
	Registry    string
	Org         string // defaults to rel.Manifest.Org when rel is given
	Ring        string // defaults to rel.Manifest.Ring when rel is given
	PubKeyPEM   string // release ed25519 public key, PKIX PEM, embedded inline
	HalodSHA256 string // hex sha256 of halod, or "amd64=<hex>,arm64=<hex>"
}

var shaOpt = regexp.MustCompile(`^([0-9a-fA-F]{64}|amd64=[0-9a-fA-F]{64},arm64=[0-9a-fA-F]{64})$`)

// Export returns relative path -> content for a feature source dir
// (devcontainer-feature.json, install.sh, init-firewall.sh). rel may be nil;
// if given it must pass v (a real signature verifier), and a nil v is an error.
// PubKeyPEM and HalodSHA256 are required: the feature refuses to install without them.
func Export(rel *release.Release, o Options, v mdm.Verifier) (map[string][]byte, error) {
	if rel != nil {
		if v == nil {
			return nil, fmt.Errorf("devcontainer: a release Verifier is required")
		}
		if err := v(rel); err != nil {
			return nil, fmt.Errorf("devcontainer: refusing unverified release: %w", err)
		}
		if o.Ring == "" {
			o.Ring = rel.Manifest.Ring
		}
	}
	if o.Org == "" && rel != nil {
		o.Org = rel.Manifest.Org
	}
	if o.Org != "" {
		if err := mdm.ValidateName(o.Org); err != nil {
			return nil, err
		}
	}
	if o.Ring != "" {
		if err := mdm.ValidateName(o.Ring); err != nil {
			return nil, err
		}
	}
	if !strings.HasPrefix(o.PubKeyPEM, "-----BEGIN PUBLIC KEY-----") {
		return nil, fmt.Errorf("devcontainer: PubKeyPEM must be an inline PUBLIC KEY PEM")
	}
	if !shaOpt.MatchString(o.HalodSHA256) {
		return nil, fmt.Errorf("devcontainer: HalodSHA256 is required (64 hex, or amd64=<hex>,arm64=<hex>)")
	}
	raw, err := features.FS.ReadFile("halos/devcontainer-feature.json")
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("devcontainer: parse feature json: %w", err)
	}
	opts, _ := doc["options"].(map[string]any)
	for k, v := range map[string]string{"registry": o.Registry, "org": o.Org, "ring": o.Ring, "pubkeyPem": strings.ReplaceAll(strings.TrimSpace(o.PubKeyPEM), "\n", `\n`), "halodSha256": o.HalodSHA256} {
		if v == "" {
			continue
		}
		opt, ok := opts[k].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("devcontainer: feature has no option %q", k)
		}
		opt["default"] = v
	}
	fj, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{"devcontainer-feature.json": append(fj, '\n')}
	for _, n := range []string{"install.sh", "init-firewall.sh"} {
		b, err := features.FS.ReadFile("halos/" + n)
		if err != nil {
			return nil, err
		}
		out[n] = b
	}
	return out, nil
}
