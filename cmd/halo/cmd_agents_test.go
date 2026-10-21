package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/a2a"
)

const testCard = `{"name":"Billing Agent","description":"d","version":"1.0.0","skills":[{"id":"lookup-invoice","name":"Lookup"}],
"supportedInterfaces":[{"url":"https://billing.example/a2a/v1","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`

// TestAgentsVerify: halo agents verify refuses a private destination unless
// allowed, prints the digest to pin, and fails on a digest or skill mismatch;
// with --policy-dir the agents.remote entry supplies the pins.
func TestAgentsVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			http.Redirect(w, r, "https://example.com/card", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(testCard))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	old := cardFetcher
	cardFetcher = func(timeout time.Duration, allowPrivate bool) a2a.Fetcher {
		return a2a.Fetcher{Timeout: timeout, AllowPrivate: allowPrivate, RootCAs: pool}
	}
	t.Cleanup(func() { cardFetcher = old })
	card := srv.URL + "/.well-known/agent-card.json"

	if code, out, _ := halo(t, "agents", "verify", card); code != exitError || !strings.Contains(out, "not public") {
		t.Fatalf("loopback without --allow-private: %d %s", code, out)
	}
	if code, out, _ := halo(t, "agents", "verify", "--allow-private", srv.URL+"/elsewhere"); code != exitError || !strings.Contains(out, "off-host") {
		t.Fatalf("off-host redirect: %d %s", code, out)
	}
	code, out, _ := halo(t, "--output", "json", "agents", "verify", "--allow-private", card)
	var rep agentVerifyReport
	if err := json.Unmarshal([]byte(out), &rep); code != 0 || err != nil || !strings.HasPrefix(rep.Result.Digest, "sha256:") || rep.Result.Card.Name != "Billing Agent" {
		t.Fatalf("verify: %d %s", code, out)
	}
	if code, out, _ := halo(t, "agents", "verify", "--allow-private", "--digest", "sha256:"+strings.Repeat("0", 64), card); code != exitError || !strings.Contains(out, "digest does not match") {
		t.Fatalf("digest mismatch: %d %s", code, out)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	keyFile := filepath.Join(t.TempDir(), "card.pub")
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	if code, out, _ := halo(t, "agents", "verify", "--allow-private", "--pubkey", keyFile, card); code != exitError || !strings.Contains(out, "not signed") {
		t.Fatalf("unsigned card with a pinned key: %d %s", code, out)
	}

	dir := copyDir(t, example)
	root := filepath.Join(dir, "halos.yaml")
	b, _ := os.ReadFile(root)
	entry := "agents:\n  actors: [{name: planner}]\n  remote:\n    - name: billing\n      cardURL: " + card + "\n      digest: " + rep.Result.Digest +
		"\n      skills: [lookup-invoice, refund]\n      rings: [ring3-ga]\n"
	if err := os.WriteFile(root, append(b, entry...), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := halo(t, "agents", "verify", "--allow-private", "--policy-dir", dir, card); code != exitError || !strings.Contains(out, "agents.remote[billing]") || !strings.Contains(out, "[refund]") {
		t.Fatalf("policy pins: %d %s", code, out)
	}
	if code, _, errb := halo(t, "agents", "verify", "--allow-private", "--policy-dir", dir, srv.URL+"/other"); code == 0 || !strings.Contains(errb, "no agents.remote entry") {
		t.Fatalf("url not in policy: %d %s", code, errb)
	}
}
