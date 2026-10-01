package harness

// Matrix returns the capability set of every registered adapter, keyed by
// adapter name. Adapters register from init(), so callers must import
// internal/harness/all (or the adapters they need) first.
func Matrix() map[string][]Capability {
	out := make(map[string][]Capability, len(registry))
	for n, a := range registry {
		out[n] = append([]Capability{}, a.Capabilities()...)
	}
	return out
}
