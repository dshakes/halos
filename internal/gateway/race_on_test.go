//go:build race

package gateway

// raceEnabled: the race detector slows CPU-bound code several times over;
// timing assertions scale by it.
const raceEnabled = true
