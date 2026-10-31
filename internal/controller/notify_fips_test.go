package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/hmackey"
)

// ADR-0038: a notify webhook secret Go's FIPS module would panic on refuses
// to start in FIPS mode, naming the flag; outside FIPS it only warns.
func TestNotifyWebhookSecretFIPS(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	hook, short, long := write("hook", "https://hooks.test/y"), write("short", "k"), write("long", strings.Repeat("k", 32))
	for _, tc := range []struct {
		name   string
		fips   bool
		secret string
		ok     bool
	}{
		{"fips short refused", true, short, false},
		{"fips long ok", true, long, true},
		{"no fips short warns only", false, short, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer hmackey.SetFIPSForTesting(tc.fips)()
			_, err := NotifiersFromFiles("", hook, tc.secret)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !strings.Contains(err.Error(), "--notify-webhook-secret-file") {
				t.Fatalf("error does not name the flag: %v", err)
			}
			// the builder halo-server and `halo controller run` use (NotifyConfig, NotifyFlags)
			_, err = NotifyConfig{WebhookURLFile: hook, WebhookSecretFile: tc.secret, WebhookEvents: "experiment.killed"}.Build()
			if (err == nil) != tc.ok {
				t.Fatalf("NotifyConfig.Build: err %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
