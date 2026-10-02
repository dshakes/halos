package main

import "testing"

// Kong hands the plugin at most 1000 request headers, so a client can push an
// x-halo-* header past the list PrepareVerified sees. Every gateway-owned
// name, including the kill-switch alert header, is cleared regardless.
func TestAccessClearsOwnedHeadersEvenWhenHeaderListTruncated(t *testing.T) {
	k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn), hdrs: map[string][]string{}} // what Kong returned: nothing
	trustedCfg(testPolicy(t)).access(k)
	if k.exitStatus != 0 {
		t.Fatalf("exit %d %s", k.exitStatus, k.exitBody)
	}
	for _, n := range []string{"x-halo-ring", "x-halo-release", "x-halo-experiment", "x-halo-variant", "x-halo-killswitch", "x-acme-user", "x-acme-groups"} {
		if !contains(k.cleared, n) {
			t.Errorf("%s not cleared: %v", n, k.cleared)
		}
	}
}
