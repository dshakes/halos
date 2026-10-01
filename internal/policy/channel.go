package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// MaxChannelLen bounds a delivery channel name. Channels become OCI tags
// ("ring-<channel>.pointer", tag limit 128) and halod state keys, so a name
// that would exceed this is shortened by hashing (see ChannelName).
const MaxChannelLen = 100

// ChannelName is the delivery channel that serves variant of client-axis
// experiment exp to devices in ring: "<ring>.x-<exp>.<variant>". When that
// exceeds MaxChannelLen the experiment/variant part is replaced by the first
// 20 hex chars of sha256(exp NUL variant). Names are ValidName, so the result
// only uses [a-z0-9._-] and fits the OCI tag grammar.
//
// The ring release names its channels in its signed manifest; halod recomputes
// the name and refuses a mismatch. Validate rejects policies where a channel
// name collides with a ring or another channel.
func ChannelName(ring, exp, variant string) string {
	if n := ring + ".x-" + exp + "." + variant; len(n) <= MaxChannelLen {
		return n
	}
	h := sha256.Sum256([]byte(exp + "\x00" + variant))
	return ring + ".x-" + hex.EncodeToString(h[:])[:20]
}

// ClientExperiments returns the running client-axis experiments that enroll
// ring, in policy order. Validate allows at most one per ring.
func (o *Org) ClientExperiments(ring string) []*Experiment {
	var out []*Experiment
	for _, e := range o.Experiments {
		if e.Axis == AxisClient && e.Status == "running" && slices.Contains(e.Rings, ring) {
			out = append(out, e)
		}
	}
	return out
}
