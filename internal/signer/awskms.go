package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/dshakes/halos/internal/bundle"
)

// AWS KMS over its JSON API (awsJson1_1, SigV4 service "kms"), with only the
// two operations Halos needs: GetPublicKey and Sign. It reuses the AWS SDK
// core already in go.mod (credentials chain, SigV4) instead of adding
// service/kms. The private key never leaves KMS.

const (
	kmsService     = "kms"
	maxKMSResponse = 1 << 20
)

var (
	kmsRegionRE = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	// arn:<partition>:kms:<region>:<account>:key/<id> | alias/<name>
	kmsARNRE = regexp.MustCompile(`^arn:aws[a-z-]*:kms:([a-z0-9-]+):[0-9]{12}:(key|alias)/[A-Za-z0-9/_+=,.@:-]+$`)
	kmsKeyRE = regexp.MustCompile(`^([0-9a-fA-F-]{36}|mrk-[0-9a-f]{32}|alias/[A-Za-z0-9/_-]+)$`)
)

// kmsSpec maps a KMS key spec to the native algorithm and the KMS signing
// parameters that produce exactly that algorithm's signature.
type kmsSpec struct {
	alg, signingAlgorithm, messageType string
	prehash                            bool // send SHA-256(msg), not msg
}

var kmsSpecs = map[string]kmsSpec{
	// ECDSA over SHA-256(msg): KMS gets the digest (MessageType DIGEST) and
	// returns DER, which is bundle.AlgECDSAP256 byte for byte.
	"ECC_NIST_P256": {alg: bundle.AlgECDSAP256, signingAlgorithm: "ECDSA_SHA_256", messageType: "DIGEST", prehash: true},
	// Pure Ed25519 (RFC 8032) needs the raw message (MessageType RAW), which
	// is short here (a digest string or a domain-separated statement).
	"ECC_NIST_EDWARDS25519": {alg: bundle.AlgEd25519, signingAlgorithm: "ED25519_SHA_512", messageType: "RAW"},
}

type kmsClient struct {
	endpoint string
	region   string
	hc       *http.Client
	creds    aws.CredentialsProvider
	sigv4    *v4.Signer
	now      func() time.Time
}

// kmsURI is a parsed awskms:// URI.
type kmsURI struct {
	keyID, region, endpoint string
	fips                    bool
}

func parseKMSURI(uri string) (kmsURI, error) {
	var k kmsURI
	rest := strings.TrimPrefix(uri, "awskms://")
	key, rawQuery, _ := strings.Cut(rest, "?")
	k.keyID = key
	if !kmsARNRE.MatchString(key) && !kmsKeyRE.MatchString(key) {
		return k, fmt.Errorf("signer: awskms key %q is not a KMS key id, key ARN, alias/<name> or alias ARN", key)
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return k, fmt.Errorf("signer: awskms query: %w", err)
	}
	for name, vals := range q {
		if len(vals) != 1 {
			return k, fmt.Errorf("signer: awskms query parameter %q given %d times", name, len(vals))
		}
		switch v := vals[0]; name {
		case "region":
			k.region = v
		case "endpoint":
			k.endpoint = v
		case "fips":
			if v != "true" && v != "false" {
				return k, fmt.Errorf("signer: awskms fips=%q, want true or false", v)
			}
			k.fips = v == "true"
		default:
			return k, fmt.Errorf("signer: unknown awskms query parameter %q (want region, endpoint, fips)", name)
		}
	}
	if m := kmsARNRE.FindStringSubmatch(key); m != nil {
		if k.region != "" && k.region != m[1] {
			return k, fmt.Errorf("signer: awskms region=%s contradicts the key ARN's region %s", k.region, m[1])
		}
		k.region = m[1]
	}
	if k.region != "" && !kmsRegionRE.MatchString(k.region) {
		return k, fmt.Errorf("signer: invalid AWS region %q", k.region)
	}
	if k.endpoint != "" && k.fips {
		return k, errors.New("signer: awskms takes endpoint or fips=true, not both (point endpoint at the FIPS endpoint)")
	}
	return k, nil
}

// checkKMSEndpoint allows https to AWS endpoint domains (incl. VPC endpoint
// names) and http(s) to loopback only: SigV4-signed requests must not go to a
// third party.
func checkKMSEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("signer: awskms endpoint: %w", err)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		if u.Scheme == "http" || u.Scheme == "https" {
			return nil
		}
	}
	if u.Scheme != "https" {
		return fmt.Errorf("signer: awskms endpoint %q must be https", raw)
	}
	for _, sfx := range []string{".amazonaws.com", ".amazonaws.com.cn", ".api.aws"} {
		if strings.HasSuffix(host, sfx) {
			return nil
		}
	}
	return fmt.Errorf("signer: awskms endpoint host %q is not an AWS domain or loopback", host)
}

func openAWSKMS(ctx context.Context, uri string, o Options) (bundle.KeySigner, error) {
	k, err := parseKMSURI(uri)
	if err != nil {
		return nil, err
	}
	c := &kmsClient{region: k.region, hc: o.HTTPClient, creds: o.Credentials, sigv4: v4.NewSigner(), now: o.Now}
	if c.region == "" {
		c.region = o.Region
	}
	if c.creds == nil || c.region == "" {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("signer: awskms: load AWS config: %w", err)
		}
		if c.creds == nil {
			if cfg.Credentials == nil {
				return nil, errors.New("signer: awskms: no AWS credentials")
			}
			c.creds = cfg.Credentials
		}
		if c.region == "" {
			c.region = cfg.Region
		}
	}
	if !kmsRegionRE.MatchString(c.region) {
		return nil, fmt.Errorf("signer: awskms: no valid region (got %q): add ?region= to the URI, use a key ARN or set AWS_REGION", c.region)
	}
	switch {
	case k.endpoint != "":
		if err := checkKMSEndpoint(k.endpoint); err != nil {
			return nil, err
		}
		c.endpoint = k.endpoint
	case k.fips:
		c.endpoint = "https://kms-fips." + c.region + "." + awsDomain(c.region) + "/"
	default:
		c.endpoint = "https://kms." + c.region + "." + awsDomain(c.region) + "/"
	}
	if c.hc == nil {
		c.hc = &http.Client{Timeout: DefaultTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if c.now == nil {
		c.now = time.Now
	}

	octx, cancel := withTimeout(ctx, DefaultTimeout)
	defer cancel()
	var pk struct {
		KeyId             string   `json:"KeyId"`
		KeySpec           string   `json:"KeySpec"`
		KeyUsage          string   `json:"KeyUsage"`
		PublicKey         []byte   `json:"PublicKey"` // base64 DER SubjectPublicKeyInfo
		SigningAlgorithms []string `json:"SigningAlgorithms"`
	}
	if err := c.call(octx, "GetPublicKey", map[string]string{"KeyId": k.keyID}, &pk); err != nil {
		return nil, fmt.Errorf("signer: awskms GetPublicKey %s: %w", k.keyID, err)
	}
	if pk.KeyUsage != "SIGN_VERIFY" {
		return nil, fmt.Errorf("signer: awskms key %s has KeyUsage %q, want SIGN_VERIFY", k.keyID, pk.KeyUsage)
	}
	spec, ok := kmsSpecs[pk.KeySpec]
	if !ok {
		return nil, fmt.Errorf("signer: awskms key %s has KeySpec %q; Halos signs with ECC_NIST_P256 (ECDSA P-256) or ECC_NIST_EDWARDS25519 (Ed25519)", k.keyID, pk.KeySpec)
	}
	if len(pk.SigningAlgorithms) > 0 && !slices.Contains(pk.SigningAlgorithms, spec.signingAlgorithm) {
		return nil, fmt.Errorf("signer: awskms key %s does not offer %s (offers %v)", k.keyID, spec.signingAlgorithm, pk.SigningAlgorithms)
	}
	pub, err := bundle.ParseVerifierDER(pk.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("signer: awskms key %s public key: %w", k.keyID, err)
	}
	// Sign with the resolved key ARN, not an alias: re-pointing the alias
	// later cannot switch the key behind a running signer.
	keyID := k.keyID
	if kmsARNRE.MatchString(pk.KeyId) && strings.Contains(pk.KeyId, ":key/") {
		keyID = pk.KeyId
	}
	desc := "awskms " + keyID
	return newRemote(spec.alg, pub, desc, func(ctx context.Context, msg string) ([]byte, error) {
		m := []byte(msg)
		if spec.prehash {
			h := sha256.Sum256(m)
			m = h[:]
		}
		in := map[string]any{"KeyId": keyID, "Message": m, "MessageType": spec.messageType, "SigningAlgorithm": spec.signingAlgorithm}
		var out struct {
			KeyId            string `json:"KeyId"`
			Signature        []byte `json:"Signature"`
			SigningAlgorithm string `json:"SigningAlgorithm"`
		}
		ctx, cancel := withTimeout(ctx, DefaultTimeout)
		defer cancel()
		if err := c.call(ctx, "Sign", in, &out); err != nil {
			return nil, fmt.Errorf("Sign: %w", err)
		}
		if out.SigningAlgorithm != "" && out.SigningAlgorithm != spec.signingAlgorithm {
			return nil, fmt.Errorf("Sign answered with %s, asked for %s", out.SigningAlgorithm, spec.signingAlgorithm)
		}
		if len(out.Signature) == 0 {
			return nil, errors.New("Sign returned no signature")
		}
		return out.Signature, nil
	})
}

func awsDomain(region string) string {
	if strings.HasPrefix(region, "cn-") {
		return "amazonaws.com.cn"
	}
	return "amazonaws.com"
}

// call POSTs one SigV4-signed awsJson1_1 request and decodes the answer.
func (c *kmsClient) call(ctx context.Context, op string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	creds, err := c.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("AWS credentials: %w", err)
	}
	sum := sha256.Sum256(body)
	if err := c.sigv4.SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), kmsService, c.region, c.now().UTC()); err != nil {
		return fmt.Errorf("sigv4: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only response
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxKMSResponse+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(rb) > maxKMSResponse {
		return fmt.Errorf("response over %d bytes", maxKMSResponse)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Type    string `json:"__type"`
			Message string `json:"message"`
			Msg     string `json:"Message"`
		}
		_ = json.Unmarshal(rb, &e) // best effort: the status alone is still reported
		t := e.Type
		if i := strings.LastIndex(t, "#"); i >= 0 {
			t = t[i+1:]
		}
		return fmt.Errorf("HTTP %d %s: %s", resp.StatusCode, t, e.Message+e.Msg)
	}
	if err := json.Unmarshal(rb, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
