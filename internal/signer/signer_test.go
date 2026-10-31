package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// TestMain doubles as the fake external signer: exec:// tests run this test
// binary with HALO_FAKE_SIGNER_KEY set.
func TestMain(m *testing.M) {
	if os.Getenv("HALO_FAKE_SIGNER_KEY") != "" {
		os.Exit(fakeExecSigner())
	}
	os.Exit(m.Run())
}

func fakeExecSigner() int {
	mode := os.Getenv("HALO_FAKE_SIGNER_MODE")
	var req execRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		os.Stderr.WriteString("bad request: " + err.Error())
		return 3
	}
	pemb, err := os.ReadFile(os.Getenv("HALO_FAKE_SIGNER_KEY"))
	if err != nil {
		return 4
	}
	s, err := bundle.ParseSigner(pemb)
	if err != nil {
		return 5
	}
	out := map[string]any{"protocol": ExecProtocol}
	switch {
	case mode == "exit1":
		os.Stderr.WriteString("hsm unavailable")
		return 1
	case mode == "garbage":
		os.Stdout.WriteString("not json")
		return 0
	case mode == "trailing":
		os.Stdout.WriteString(`{"protocol":"halos.signer.v1","algorithm":"ed25519","publicKey":"x"} {}`)
		return 0
	case mode == "big":
		os.Stdout.WriteString(strings.Repeat(" ", maxExecOutput+10))
		return 0
	case mode == "sleep":
		time.Sleep(5 * time.Second)
		return 0
	case mode == "wrongproto":
		out["protocol"] = "other.v9"
	case mode == "error":
		out["error"] = "key locked"
	case mode == "badalg" && req.Op == "public":
		out["algorithm"] = "rsa-pss-sha256"
		out["publicKey"] = "x"
	case mode == "mislabel" && req.Op == "public": // claims ecdsa for an ed25519 key
		pub, _ := bundle.MarshalPublicKeyPEM(s.Verifier().(bundle.PublicKeyVerifier))
		out["algorithm"], out["publicKey"] = bundle.AlgECDSAP256, string(pub)
	case req.Op == "public":
		pub, _ := bundle.MarshalPublicKeyPEM(s.Verifier().(bundle.PublicKeyVerifier))
		out["algorithm"], out["publicKey"] = s.Type(), string(pub)
	case req.Op == "sign":
		if h := sha256.Sum256(req.Message); string(h[:]) != string(req.SHA256) || req.Algorithm != s.Type() {
			out["error"] = "request digest or algorithm mismatch"
			break
		}
		signWith := s
		if mode == "wrongkey" {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			signWith = bundle.ECDSASigner{Key: other}
		}
		sig, err := signWith.Sign(context.Background(), string(req.Message))
		if err != nil {
			out["error"] = err.Error()
			break
		}
		if mode == "truncate" {
			sig = sig[:len(sig)-1]
		}
		out["signature"] = sig
	default:
		out["error"] = "unknown op " + req.Op
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	return 0
}

func writeKey(t *testing.T, k crypto.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func execURI(t *testing.T, keyPath, mode string, extra string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HALO_FAKE_SIGNER_KEY", keyPath)
	t.Setenv("HALO_FAKE_SIGNER_MODE", mode)
	return "exec://" + exe + "?key=test-key" + extra
}

// ---- fake KMS ----

type fakeKMS struct {
	t        *testing.T
	key      crypto.Signer
	spec     string
	usage    string
	signWith crypto.Signer // nil = key
	sigAlg   string        // override the answered SigningAlgorithm
	failSign string        // non-empty: Sign answers HTTP 400 with this __type

	mu   sync.Mutex
	reqs []map[string]any
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/kms/aws4_request") {
		http.Error(w, `{"__type":"UnrecognizedClientException","message":"bad sig"}`, http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
		http.Error(w, "content type", http.StatusBadRequest)
		return
	}
	b, _ := io.ReadAll(r.Body)
	var in map[string]any
	_ = json.Unmarshal(b, &in)
	f.mu.Lock()
	f.reqs = append(f.reqs, in)
	f.mu.Unlock()
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.GetPublicKey":
		der, err := x509.MarshalPKIXPublicKey(f.key.Public())
		if err != nil {
			f.t.Error(err)
		}
		usage := f.usage
		if usage == "" {
			usage = "SIGN_VERIFY"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"KeyId": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", "KeySpec": f.spec,
			"KeyUsage": usage, "PublicKey": der,
		})
	case "TrentService.Sign":
		if f.failSign != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"com.amazonaws.kms#` + f.failSign + `","message":"nope"}`))
			return
		}
		var req struct {
			KeyId, MessageType, SigningAlgorithm string
			Message                              []byte
		}
		_ = json.Unmarshal(b, &req)
		k := f.key
		if f.signWith != nil {
			k = f.signWith
		}
		var sig []byte
		var err error
		switch req.SigningAlgorithm {
		case "ECDSA_SHA_256":
			if req.MessageType != "DIGEST" || len(req.Message) != 32 {
				http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
				return
			}
			sig, err = k.Sign(rand.Reader, req.Message, crypto.SHA256)
		case "ED25519_SHA_512":
			if req.MessageType != "RAW" {
				http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
				return
			}
			sig, err = k.Sign(rand.Reader, req.Message, crypto.Hash(0))
		default:
			http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
			return
		}
		if err != nil {
			f.t.Error(err)
		}
		alg := req.SigningAlgorithm
		if f.sigAlg != "" {
			alg = f.sigAlg
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"KeyId": req.KeyId, "Signature": sig, "SigningAlgorithm": alg})
	default:
		http.Error(w, "unknown target", http.StatusBadRequest)
	}
}

func kmsOpts() Options {
	return Options{Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "")}
}

func newFakeKMS(t *testing.T, key crypto.Signer, spec string) (*fakeKMS, string) {
	t.Helper()
	f := &fakeKMS{t: t, key: key, spec: spec}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, "awskms://alias/halos-release?region=us-east-1&endpoint=" + srv.URL
}

// ---- conformance ----

type relRes struct{}

func (relRes) ResolveProfile(string) (*policy.Profile, error) {
	return &policy.Profile{Harnesses: map[string]policy.HarnessSpec{"signertest": {Version: "1.0.0"}}}, nil
}

type relAd struct{}

func (relAd) Name() string                       { return "signertest" }
func (relAd) Capabilities() []harness.Capability { return nil }
func (relAd) InstallCommand(string, harness.OS) string {
	return "true"
}
func (relAd) Render(*policy.Profile, harness.Context) ([]harness.File, []string, error) {
	return []harness.File{{Path: "/etc/x", Mode: 0o644, Data: []byte("x")}}, nil, nil
}

func init() { harness.Register(relAd{}) }

func TestConformance(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPath, ecPath := writeKey(t, edKey), writeKey(t, ecKey)
	backends := []struct {
		name    string
		uri     func(t *testing.T) string
		wantAlg string
	}{
		{"file ed25519 (bare path)", func(*testing.T) string { return edPath }, bundle.AlgEd25519},
		{"file ed25519", func(*testing.T) string { return "file://" + edPath }, bundle.AlgEd25519},
		{"file ecdsa", func(*testing.T) string { return "file://" + ecPath }, bundle.AlgECDSAP256},
		{"awskms p256", func(t *testing.T) string { _, u := newFakeKMS(t, ecKey, "ECC_NIST_P256"); return u }, bundle.AlgECDSAP256},
		{"awskms ed25519", func(t *testing.T) string { _, u := newFakeKMS(t, edKey, "ECC_NIST_EDWARDS25519"); return u }, bundle.AlgEd25519},
		{"exec ecdsa", func(t *testing.T) string { return execURI(t, ecPath, "", "") }, bundle.AlgECDSAP256},
		{"exec ed25519", func(t *testing.T) string { return execURI(t, edPath, "", "&timeout=20s") }, bundle.AlgEd25519},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			s, err := Open(ctx, b.uri(t), kmsOpts())
			if err != nil {
				t.Fatal(err)
			}
			v := s.Verifier()
			if s.Type() != b.wantAlg || v.Type() != b.wantAlg {
				t.Fatalf("alg %s/%s, want %s", s.Type(), v.Type(), b.wantAlg)
			}
			if bundle.KeyID(v) == "" {
				t.Fatal("no key id")
			}
			sig, err := s.Sign(ctx, "sha256:0123")
			if err != nil {
				t.Fatal(err)
			}
			pv := v.(bundle.PublicKeyVerifier)
			if err := bundle.VerifyAs(ctx, bundle.Keyring{pv}, b.wantAlg, "sha256:0123", sig); err != nil {
				t.Fatalf("own signature: %v", err)
			}
			if bundle.VerifyAs(ctx, bundle.Keyring{pv}, b.wantAlg, "sha256:0124", sig) == nil {
				t.Fatal("signature verified over another message")
			}
			// halod's view: the public key exported as PEM verifies a published ring
			pubPEM, err := bundle.MarshalPublicKeyPEM(pv)
			if err != nil {
				t.Fatal(err)
			}
			halodKey, err := bundle.ParseVerifier(pubPEM)
			if err != nil {
				t.Fatal(err)
			}
			rel, err := release.Build(relRes{}, "p", "r", release.Options{Version: "1", Org: "acme"})
			if err != nil {
				t.Fatal(err)
			}
			store := memory.New()
			if _, err := bundle.Publish(ctx, store, rel, s, "r"); err != nil {
				t.Fatal(err)
			}
			if _, _, err := bundle.PullRing(ctx, store, bundle.Keyring{halodKey}, bundle.RingOptions{Org: "acme", Ring: "r", Now: time.Now()}); err != nil {
				t.Fatalf("halod pull: %v", err)
			}
		})
	}
}

func TestFakeKMSRequests(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f, uri := newFakeKMS(t, ecKey, "ECC_NIST_P256")
	s, err := Open(context.Background(), uri, kmsOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(context.Background(), "sha256:ab"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 2 || f.reqs[0]["KeyId"] != "alias/halos-release" {
		t.Fatalf("requests %v", f.reqs)
	}
	// Sign is pinned to the ARN GetPublicKey resolved, not the alias
	if got := f.reqs[1]["KeyId"]; got != "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab" {
		t.Fatalf("Sign KeyId %v", got)
	}
}

func TestAWSKMSFailures(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tests := []struct {
		name    string
		key     crypto.Signer
		spec    string
		mutate  func(*fakeKMS)
		atOpen  bool
		wantErr string
	}{
		{"encrypt key", ecKey, "ECC_NIST_P256", func(f *fakeKMS) { f.usage = "ENCRYPT_DECRYPT" }, true, "SIGN_VERIFY"},
		{"rsa key spec", rsaKey, "RSA_2048", nil, true, "KeySpec"},
		{"spec contradicts key", ecKey, "ECC_NIST_EDWARDS25519", nil, true, "public key is ecdsa-p256-sha256"},
		{"signs with another key", ecKey, "ECC_NIST_P256", func(f *fakeKMS) { f.signWith = other }, false, "does not verify"},
		{"answers another algorithm", ecKey, "ECC_NIST_P256", func(f *fakeKMS) { f.sigAlg = "ECDSA_SHA_384" }, false, "ECDSA_SHA_384"},
		{"access denied", ecKey, "ECC_NIST_P256", func(f *fakeKMS) { f.failSign = "AccessDeniedException" }, false, "AccessDeniedException"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, uri := newFakeKMS(t, tt.key, tt.spec)
			if tt.mutate != nil {
				tt.mutate(f)
			}
			s, err := Open(context.Background(), uri, kmsOpts())
			if !tt.atOpen {
				if err != nil {
					t.Fatal(err)
				}
				_, err = s.Sign(context.Background(), "sha256:ab")
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want %q", err, tt.wantErr)
			}
		})
	}
	// bad credentials surface the KMS error at Open
	_, uri := newFakeKMS(t, ecKey, "ECC_NIST_P256")
	o := Options{Credentials: credentials.NewStaticCredentialsProvider("OTHER", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "")}
	if _, err := Open(context.Background(), uri, o); err == nil || !strings.Contains(err.Error(), "UnrecognizedClientException") {
		t.Fatalf("bad creds: %v", err)
	}
}

func TestParseKMSURI(t *testing.T) {
	arn := "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	tests := []struct {
		uri, region, endpoint, err string
	}{
		{uri: "awskms://" + arn, region: "eu-west-1"},
		{uri: "awskms://1234abcd-12ab-34cd-56ef-1234567890ab?region=us-east-2", region: "us-east-2"},
		{uri: "awskms://alias/release?region=us-east-1&fips=true", region: "us-east-1"},
		{uri: "awskms://mrk-0123456789abcdef0123456789abcdef?region=us-east-1", region: "us-east-1"},
		{uri: "awskms://" + arn + "?region=us-east-1", err: "contradicts"},
		{uri: "awskms://not a key", err: "not a KMS key"},
		{uri: "awskms://", err: "not a KMS key"},
		{uri: "awskms://alias/x?region=Mars", err: "invalid AWS region"},
		{uri: "awskms://alias/x?bogus=1", err: "unknown awskms query"},
		{uri: "awskms://alias/x?region=us-east-1&region=us-east-2", err: "given 2 times"},
		{uri: "awskms://alias/x?fips=yes", err: "fips"},
		{uri: "awskms://alias/x?fips=true&endpoint=https://kms.us-east-1.amazonaws.com", err: "not both"},
	}
	for _, tt := range tests {
		k, err := parseKMSURI(tt.uri)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%s: got %v want %q", tt.uri, err, tt.err)
			}
			continue
		}
		if err != nil || k.region != tt.region {
			t.Errorf("%s: %+v %v", tt.uri, k, err)
		}
	}
	for raw, ok := range map[string]bool{
		"https://kms.us-east-1.amazonaws.com/":             true,
		"https://vpce-1.kms.us-east-1.vpce.amazonaws.com":  true,
		"http://127.0.0.1:8080":                            true,
		"http://localhost:1":                               true,
		"http://kms.us-east-1.amazonaws.com":               false,
		"https://kms.evil.example":                         false,
		"https://kms.us-east-1.amazonaws.com.evil.example": false,
		"ftp://127.0.0.1":                                  false,
	} {
		if err := checkKMSEndpoint(raw); (err == nil) != ok {
			t.Errorf("endpoint %s: %v, want ok=%v", raw, err, ok)
		}
	}
	// a non-AWS endpoint is refused before any request is signed
	if _, err := Open(context.Background(), "awskms://alias/x?region=us-east-1&endpoint=https://kms.evil.example", kmsOpts()); err == nil {
		t.Fatal("non-AWS endpoint accepted")
	}
}

func TestExecFailures(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecPath, edPath := writeKey(t, ecKey), writeKey(t, edKey)
	tests := []struct {
		mode, key, extra string
		atOpen           bool
		wantErr          string
	}{
		{"exit1", ecPath, "", true, "hsm unavailable"},
		{"garbage", ecPath, "", true, "decode response"},
		{"trailing", ecPath, "", true, "trailing data"},
		{"big", ecPath, "", true, "over"},
		{"wrongproto", ecPath, "", true, "protocol"},
		{"error", ecPath, "", true, "key locked"},
		{"badalg", ecPath, "", true, "rsa-pss-sha256"},
		{"mislabel", edPath, "", true, "public key is ed25519"},
		{"sleep", ecPath, "&timeout=300ms", true, "timed out"},
		{"wrongkey", ecPath, "", false, "does not verify"},
		{"truncate", ecPath, "", false, "does not verify"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			s, err := Open(context.Background(), execURI(t, tt.key, tt.mode, tt.extra), Options{})
			if !tt.atOpen {
				if err != nil {
					t.Fatal(err)
				}
				_, err = s.Sign(context.Background(), "sha256:ab")
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want %q", err, tt.wantErr)
			}
		})
	}
	// a canceled context stops the signer
	s, err := Open(context.Background(), execURI(t, ecPath, "", ""), Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Sign(ctx, "sha256:ab"); err == nil {
		t.Fatal("canceled sign succeeded")
	}
}

// A shell-script signer: the protocol needs nothing but stdin/stdout.
func TestExecScriptSigner(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "signer.sh")
	body := "#!/bin/sh\ncat >/dev/null\necho '{\"protocol\":\"halos.signer.v1\",\"error\":\"pkcs11: token not present\"}'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), "exec://"+script, Options{}); err == nil || !strings.Contains(err.Error(), "token not present") {
		t.Fatalf("script error: %v", err)
	}
}

func TestParseExecURI(t *testing.T) {
	tests := []struct {
		uri, err string
		args     []string
	}{
		{uri: "exec:///usr/bin/s?arg=--slot&arg=0&key=k", args: []string{"--slot", "0"}},
		{uri: "exec://host/usr/bin/s", err: "exec:///absolute"},
		{uri: "exec://relative", err: "exec:///absolute"},
		{uri: "exec:///usr/../bin/s", err: "clean"},
		{uri: "exec:///usr/bin/s?x=1", err: "unknown exec"},
		{uri: "exec:///usr/bin/s?timeout=forever", err: "timeout"},
		{uri: "exec:///usr/bin/s?timeout=11m", err: "timeout"},
		{uri: "exec:///usr/bin/s?key=a&key=b", err: "more than once"},
	}
	for _, tt := range tests {
		e, err := parseExecURI(tt.uri)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%s: got %v want %q", tt.uri, err, tt.err)
			}
			continue
		}
		if err != nil || strings.Join(e.args, " ") != strings.Join(tt.args, " ") {
			t.Errorf("%s: %+v %v", tt.uri, e, err)
		}
	}
}

func TestOpenFileErrors(t *testing.T) {
	for uri, want := range map[string]string{
		"":                       "empty",
		"gcpkms://projects/x":    "unsupported key URI scheme",
		"file://":                "no path",
		"file:///does/not/exist": "read key file",
	} {
		if _, err := Open(context.Background(), uri, Options{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v want %q", uri, err, want)
		}
	}
	if Scheme("awskms://x") != "awskms" || Scheme("exec:///x") != "exec" || Scheme("/k.pem") != "file" {
		t.Fatal("Scheme")
	}
}
