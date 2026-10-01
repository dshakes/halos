// Package assign is the single source of cohort assignment. The fleet agent,
// the Kong plugin and halo-shadow all call it, so a user lands in the same ring
// and variant everywhere without any shared state.
package assign

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// Buckets is the assignment resolution: 10000 = 0.01% granularity.
const Buckets = 10000

// Bucket deterministically maps (salt, subject) to [0, Buckets).
func Bucket(salt, subject string) int {
	h := sha256.Sum256([]byte(salt + "\x00" + subject))
	return int(binary.BigEndian.Uint64(h[:8]) % Buckets)
}

// Share converts a fraction of the population (0.0057 = 0.57%) to a bucket
// count, rounded to nearest so float error can't drop a bucket (0.0057 *
// Buckets is 56.99...). Every percent/sample-rate cut goes through here.
func Share(fraction float64) int {
	return int(math.Round(min(max(fraction, 0), 1) * Buckets))
}

// Pick returns the index of the weighted choice for subject, or -1 if weights are empty/zero.
func Pick(salt, subject string, weights []float64) int {
	var total float64
	for _, w := range weights {
		if w > 0 {
			total += w
		}
	}
	if total == 0 {
		return -1
	}
	pos := float64(Bucket(salt, subject)) / Buckets * total
	var acc float64
	last := -1
	for i, w := range weights {
		if w <= 0 {
			continue
		}
		acc += w
		last = i
		if pos < acc {
			return i
		}
	}
	return last // float rounding at the top edge
}
