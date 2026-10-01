package main

import "testing"

func TestSecretResolvesEnvVault(t *testing.T) {
	t.Setenv("HALO_SHADOW_TOKEN", "from-env")
	for in, want := range map[string]string{
		"{vault://env/halo-shadow-token}": "from-env",
		"{vault://env/HALO_SHADOW_TOKEN}": "from-env",
		"{vault://env/missing-var}":       "",
		"literal":                         "literal",
		"{vault://aws/x}":                 "{vault://aws/x}", // other vaults: Kong's job, passed through
	} {
		if got := secret(in); got != want {
			t.Errorf("secret(%q)=%q want %q", in, got, want)
		}
	}
}
