// Package upstreamauth signs requests to provider upstreams that need a
// gateway-held credential instead of the caller's, so halo-proxy can talk to
// Amazon Bedrock directly (no orchestrator, no SigV4 sidecar).
package upstreamauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

// ErrCredentials marks a request that could not be signed because no upstream
// credential was available. Callers answer it with 502, never forward unsigned.
var ErrCredentials = errors.New("upstreamauth: no AWS credentials for Bedrock")

const bedrockService = "bedrock"

var regionRE = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

// Region returns the SigV4 region for a Bedrock upstream: the configured one,
// else the label after bedrock-runtime[-fips] in host
// (bedrock-runtime.us-east-1.amazonaws.com, vpce-x.bedrock-runtime.eu-west-1.vpce.amazonaws.com).
func Region(configured, host string) (string, error) {
	if configured != "" {
		if !regionRE.MatchString(configured) {
			return "", fmt.Errorf("upstreamauth: invalid AWS region %q", configured)
		}
		return configured, nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	labels := strings.Split(strings.ToLower(host), ".")
	for i := 0; i+1 < len(labels); i++ {
		if strings.HasPrefix(labels[i], "bedrock-runtime") && regionRE.MatchString(labels[i+1]) {
			return labels[i+1], nil
		}
	}
	return "", fmt.Errorf("upstreamauth: cannot derive AWS region from host %q; set region on the upstream", host)
}

// awsSuffixes are the public AWS endpoint domains (commercial/GovCloud/ISO,
// China, and dual-stack api.aws) that may receive gateway-signed requests.
var awsSuffixes = []string{".amazonaws.com", ".amazonaws.com.cn", ".api.aws"}

// SignableHost reports whether SigV4-signing for host (port ignored) is
// allowed: an AWS endpoint domain or an entry of the operator's allow list
// (exact hostnames, e.g. a private VPC endpoint DNS name). Anything else would
// hand gateway-signed requests to a non-AWS party.
func SignableHost(host string, allow []string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, sfx := range awsSuffixes {
		if strings.HasSuffix(host, sfx) {
			return true
		}
	}
	for _, a := range allow {
		if strings.EqualFold(strings.TrimSuffix(a, "."), host) {
			return true
		}
	}
	return false
}

// StripClientAmz removes every x-amz* / x-amzn* header. Call it on the client's
// headers before halo-proxy stamps its own, so only gateway-set x-amz headers
// can end up in the signature.
func StripClientAmz(h http.Header) {
	for k := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-amz") {
			h.Del(k)
		}
	}
}

// Bedrock signs requests with AWS SigV4 for service "bedrock". Safe for
// concurrent use.
type Bedrock struct {
	// Credentials, when nil, is the AWS SDK default chain (env, shared
	// config/SSO, web identity/IRSA, ECS/EC2 IMDS), resolved on first use and
	// cached/refreshed by aws.CredentialsCache.
	Credentials aws.CredentialsProvider

	signer *v4.Signer
	now    func() time.Time

	mu     sync.Mutex
	loaded aws.CredentialsProvider
}

func (b *Bedrock) provider(ctx context.Context) (aws.CredentialsProvider, error) {
	if b.Credentials != nil {
		return b.Credentials, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.loaded == nil { // only success is cached: a fixed ~/.aws/config heals without restart
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: load AWS config: %w", ErrCredentials, err)
		}
		if cfg.Credentials == nil {
			return nil, ErrCredentials
		}
		b.loaded = cfg.Credentials
	}
	return b.loaded, nil
}

// clientAuth is dropped before signing: the caller's token (or a stale
// client-side signature) must never reach Bedrock.
var clientAuth = []string{"Authorization", "X-Api-Key", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-Sha256"}

// Sign replaces req's auth with a SigV4 signature over its final method, URL
// (escaped path as sent), host, body hash, Content-Type and x-amz* headers.
// Other headers are left unsigned so hops that touch them can't break the
// signature. req.Body is read fully and replaced (callers bound its size).
func (b *Bedrock) Sign(req *http.Request, region string) error {
	return b.sign(req, region, bedrockService)
}

func (b *Bedrock) sign(req *http.Request, region, service string) error {
	ctx := req.Context()
	StripClientCredentials(req.Header)
	for _, h := range clientAuth {
		req.Header.Del(h)
	}
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return fmt.Errorf("upstreamauth: read body to sign: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.ContentLength = int64(len(body))
	}
	sum := sha256.Sum256(body)

	prov, err := b.provider(ctx)
	if err != nil {
		return err
	}
	creds, err := prov.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCredentials, err)
	}
	if !creds.HasKeys() {
		return ErrCredentials
	}

	// Sign a header-minimal twin, then copy the auth headers across.
	twin := &http.Request{Method: req.Method, URL: req.URL, Host: req.Host, ContentLength: req.ContentLength, Header: http.Header{}}
	for k, v := range req.Header {
		if lk := strings.ToLower(k); lk == "content-type" || strings.HasPrefix(lk, "x-amz") {
			twin.Header[k] = v
		}
	}
	signer, now := b.signer, b.now
	if signer == nil {
		signer = v4.NewSigner()
	}
	if now == nil {
		now = time.Now
	}
	if err := signer.SignHTTP(ctx, creds, twin, hex.EncodeToString(sum[:]), service, region, now().UTC()); err != nil {
		return fmt.Errorf("upstreamauth: sigv4 sign: %w", err)
	}
	for _, h := range []string{"Authorization", "X-Amz-Date", "X-Amz-Security-Token"} {
		if v := twin.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	return nil
}

type regionKey struct{}

// WithBedrock marks ctx so Transport signs the request for region.
func WithBedrock(ctx context.Context, region string) context.Context {
	return context.WithValue(ctx, regionKey{}, region)
}

// Transport signs requests whose context was marked by WithBedrock and
// passes everything else through. Responses (incl. the
// application/vnd.amazon.eventstream stream) are returned untouched.
func (b *Bedrock) Transport(base http.RoundTripper) http.RoundTripper {
	return rt{base: base, b: b}
}

type rt struct {
	base http.RoundTripper
	b    *Bedrock
}

func (t rt) RoundTrip(req *http.Request) (*http.Response, error) {
	region, ok := req.Context().Value(regionKey{}).(string)
	if !ok {
		return t.base.RoundTrip(req)
	}
	out := req.Clone(req.Context()) // RoundTrippers must not mutate the caller's request
	if err := t.b.Sign(out, region); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return t.base.RoundTrip(out)
}
