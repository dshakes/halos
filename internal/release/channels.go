package release

import (
	"fmt"
	"strings"

	"github.com/halos-dev/halos/internal/policy"
)

// VariantVersion is the version label of the variant release published with
// ring release ver: "<ver>-x-<experiment>.<variant>" (or the hashed channel
// suffix, see policy.ChannelName). Deterministic, so a rollback of the ring to
// ver can re-point every channel at the variant releases published with it.
func VariantVersion(ver, ring, exp, variant string) string {
	return ver + "-" + strings.TrimPrefix(policy.ChannelName(ring, exp, variant), ring+".")
}

// BuildRing builds ring's release plus one release per variant of every
// running client-axis experiment enrolling ring. The ring release manifest
// lists those experiments (salt, weights, channel per variant) so halod can
// assign a device to a variant with the gateway's hash and pull the channel.
// Each variant release is built from the variant's profile (extends resolved)
// with Experiment/Variant set, so its harness config carries the attribution.
func BuildRing(org *policy.Org, ring string, opts Options) (rel *Release, variants []*Release, err error) {
	var r *policy.Ring
	for _, x := range org.Rings {
		if x.Name == ring {
			r = x
		}
	}
	if r == nil {
		return nil, nil, fmt.Errorf("release: unknown ring %q", ring)
	}
	var exps []Experiment
	for _, e := range org.ClientExperiments(ring) {
		salt := e.Salt
		if salt == "" {
			salt = e.Name
		}
		me := Experiment{Name: e.Name, Salt: salt}
		for _, v := range e.Variants {
			vo := opts
			vo.Experiment, vo.Variant, vo.Experiments = e.Name, v.Name, nil
			vo.Version = VariantVersion(opts.Version, ring, e.Name, v.Name)
			vr, err := Build(org, v.Profile, ring, vo)
			if err != nil {
				return nil, nil, fmt.Errorf("release: experiment %s variant %s: %w", e.Name, v.Name, err)
			}
			variants = append(variants, vr)
			me.Variants = append(me.Variants, ExperimentVariant{Name: v.Name, Weight: v.Weight, Channel: policy.ChannelName(ring, e.Name, v.Name)})
		}
		exps = append(exps, me)
	}
	opts.Experiments = exps
	if rel, err = Build(org, r.Profile, ring, opts); err != nil {
		return nil, nil, err
	}
	return rel, variants, nil
}

// Channels returns the variant channels m routes ring's devices to. A release
// built for another ring (promoted across rings) routes nowhere: its
// experiments enrolled the ring it was built for.
func (m Manifest) Channels(ring string) []string {
	if m.Ring != ring {
		return nil
	}
	var out []string
	for _, e := range m.Experiments {
		for _, v := range e.Variants {
			out = append(out, v.Channel)
		}
	}
	return out
}

// Policy returns the policy experiment halod evaluates for a manifest
// entry: running, enrolling ring, with the manifest's salt and weights, so
// policy.Experiment.ResolveVariant (the gateway's function) does the hashing.
func (e Experiment) Policy(ring string) *policy.Experiment {
	pe := &policy.Experiment{Meta: policy.Meta{Name: e.Name}, Axis: policy.AxisClient, Status: "running", Rings: []string{ring}, Salt: e.Salt}
	for _, v := range e.Variants {
		pe.Variants = append(pe.Variants, policy.Variant{Name: v.Name, Weight: v.Weight})
	}
	return pe
}
