package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
)

// workloadEnv: testEnv trusting a halo-server workload key, with a 100%
// traffic experiment on every ring.
func workloadEnv(t *testing.T, experiments bool) (*env, *seen, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		c.Identity.workloadKeys = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		o.Workloads = &policy.Workloads{Audience: "halos", Experiments: experiments}
		o.Experiments = []*policy.Experiment{{
			Meta: policy.Meta{Name: "all-in"}, Type: policy.ExperimentCanary, Axis: policy.AxisTraffic,
			Status: "running", Rings: []string{"ring0", "ga"},
			Variants: []policy.Variant{{Name: "control", Weight: 0, Control: true},
				{Name: "treat", Weight: 100, Routes: map[string]policy.ModelRoute{"sonnet": {Upstream: "up", Model: "treat-model"}}}},
		}}
	})
	return e, s, priv
}

func mintWorkload(t *testing.T, priv ed25519.PrivateKey, iat time.Time, ttl time.Duration) string {
	t.Helper()
	tok, err := identity.SignWorkloadToken(priv, identity.WorkloadClaims{Issuer: identity.WorkloadIssuer, Subject: "workload:gh:acme/app",
		Audience: identity.WorkloadAudience, Groups: []string{"ai-platform"}, Kind: policy.SubjectWorkload, Rule: "main",
		IssuedAt: iat.Unix(), NotBefore: iat.Unix(), Expiry: iat.Add(ttl).Unix(), ID: "j1"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// A halo-server workload credential is a verified identity: ring from its
// groups, client x-halo-* still stripped, provider credentials never forwarded,
// and no experiment unless policy opts workloads in.
func TestWorkloadCredentialAcceptedStrippedAndNotExperimented(t *testing.T) {
	e, s, priv := workloadEnv(t, false)
	tok := mintWorkload(t, priv, time.Now(), 15*time.Minute)
	resp := e.post(t, "/v1/messages", tok, msgBody, map[string]string{
		"x-halo-ring": "ga", "x-halo-experiment": "all-in", "x-halo-variant": "treat", "X-Halo-Kind": "human",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, h, body, _ := s.get()
	if h.Get("x-halo-ring") != "ring0" {
		t.Errorf("x-halo-ring=%q want ring0 (from the credential's groups)", h.Get("x-halo-ring"))
	}
	if h.Get("x-halo-experiment") != "" || h.Get("x-halo-variant") != "" || h.Get("x-halo-kind") != "" || !strings.Contains(body, `"real-model"`) {
		t.Errorf("workload enrolled or spoofed headers leaked: %v %s", h, body)
	}
	if h.Get("Authorization") != "" {
		t.Error("workload credential forwarded upstream")
	}

	// Positive control: a human in the same ring is enrolled.
	e.post(t, "/v1/messages", e.token(t, "alice@acme.com", "ai-platform"), msgBody, nil)
	if _, h, _, _ := s.get(); h.Get("x-halo-experiment") != "all-in" {
		t.Fatalf("human not enrolled: %v", h)
	}
}

func TestWorkloadExperimentsOptIn(t *testing.T) {
	e, s, priv := workloadEnv(t, true)
	e.post(t, "/v1/messages", mintWorkload(t, priv, time.Now(), 15*time.Minute), msgBody, nil)
	if _, h, _, _ := s.get(); h.Get("x-halo-experiment") != "all-in" {
		t.Fatalf("workloads.experiments: true but not enrolled: %v", h)
	}
}

func TestWorkloadCredentialRejected(t *testing.T) {
	e, s, priv := workloadEnv(t, false)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	for name, tok := range map[string]string{
		"expired":       mintWorkload(t, priv, time.Now().Add(-20*time.Minute), 15*time.Minute),
		"untrusted key": mintWorkload(t, otherPriv, time.Now(), 15*time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			if resp := e.post(t, "/v1/messages", tok, msgBody, nil); resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status %d want 401", resp.StatusCode)
			}
		})
	}
	if hits, _, _, _ := s.get(); hits != 0 {
		t.Fatalf("rejected credentials reached upstream (%d)", hits)
	}
}

func TestWorkloadPubkeyFileConfig(t *testing.T) {
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	good, bad := filepath.Join(dir, "w.pub"), filepath.Join(dir, "bad.pub")
	_ = os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	_ = os.WriteFile(bad, []byte("not a key"), 0o600)
	env := func(string) string { return "" }
	cfg, err := loadConfig([]string{"--policy", "p.json", "--workload-pubkey-file", good}, env, nil)
	if err != nil || !strings.Contains(cfg.identityOptions().WorkloadKeys, "PUBLIC KEY") {
		t.Fatalf("good key: %v", err)
	}
	for _, f := range []string{bad, filepath.Join(dir, "missing.pub")} {
		if _, err := loadConfig([]string{"--policy", "p.json", "--workload-pubkey-file", f}, env, nil); err == nil {
			t.Errorf("%s accepted", f)
		}
	}
}
