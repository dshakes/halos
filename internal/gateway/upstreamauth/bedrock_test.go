package upstreamauth

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/smithy-go/logging"
)

// AWS SigV4 test-suite credentials and clock (get-vanilla).
var (
	suiteCreds = credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "")
	suiteTime  = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
)

func TestSigV4PublishedVector(t *testing.T) {
	var logged strings.Builder
	b := &Bedrock{
		Credentials: suiteCreds,
		now:         func() time.Time { return suiteTime },
		signer: v4.NewSigner(func(o *v4.SignerOptions) {
			o.LogSigning = true
			o.Logger = logging.LoggerFunc(func(_ logging.Classification, f string, v ...any) { fmt.Fprintf(&logged, f, v...) })
		}),
	}
	req := httptest.NewRequest("GET", "https://example.amazonaws.com/", nil)
	req.Header.Set("Authorization", "Bearer client-token") // must be replaced
	if err := b.sign(req, "us-east-1", "service"); err != nil {
		t.Fatal(err)
	}
	// aws-sig-v4-test-suite/get-vanilla/get-vanilla.creq and .authz
	wantCreq := "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if !strings.Contains(logged.String(), wantCreq) {
		t.Errorf("canonical request mismatch; signer logged:\n%s", logged.String())
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization\n got %s\nwant %s", got, want)
	}
}

func TestBedrockCanonicalRequestForRewrittenPath(t *testing.T) {
	var logged strings.Builder
	b := &Bedrock{
		Credentials: suiteCreds,
		now:         func() time.Time { return suiteTime },
		signer: v4.NewSigner(func(o *v4.SignerOptions) {
			o.LogSigning = true
			o.Logger = logging.LoggerFunc(func(_ logging.Classification, f string, v ...any) { fmt.Fprintf(&logged, f, v...) })
		}),
	}
	body := `{"messages":[]}`
	req := httptest.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fus.x/invoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.0.0.1") // unsigned
	if err := b.Sign(req, "us-east-1"); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	// Bedrock (non-S3) double-escapes the already-escaped path, as the SDK's bedrockruntime client does.
	wantCreq := "POST\n/model/arn%253Aaws%253Abedrock%253Aus-east-1%253A1%253Ainference-profile%252Fus.x/invoke\n\n" +
		"content-length:15\ncontent-type:application/json\nhost:bedrock-runtime.us-east-1.amazonaws.com\nx-amz-date:20150830T123600Z\n\n" +
		"content-length;content-type;host;x-amz-date\n" + hex.EncodeToString(sum[:])
	if !strings.Contains(logged.String(), wantCreq) {
		t.Fatalf("canonical request mismatch; signer logged:\n%s", logged.String())
	}
	if !strings.Contains(req.Header.Get("Authorization"), "Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request") {
		t.Fatalf("scope: %s", req.Header.Get("Authorization"))
	}
	if got, _ := io.ReadAll(req.Body); string(got) != body {
		t.Fatalf("body not restored: %q", got)
	}
}

func TestRegion(t *testing.T) {
	for _, tt := range []struct{ cfg, host, want string }{
		{"", "bedrock-runtime.us-east-1.amazonaws.com", "us-east-1"},
		{"", "bedrock-runtime.eu-central-1.amazonaws.com:443", "eu-central-1"},
		{"", "bedrock-runtime-fips.us-gov-west-1.amazonaws.com", "us-gov-west-1"},
		{"", "bedrock-runtime.cn-north-1.amazonaws.com.cn", "cn-north-1"},
		{"", "vpce-0abc-xyz.bedrock-runtime.ap-southeast-2.vpce.amazonaws.com", "ap-southeast-2"},
		{"eu-west-3", "bedrock-runtime.us-east-1.amazonaws.com", "eu-west-3"},
		{"us-west-2", "127.0.0.1:8080", "us-west-2"},
		{"", "127.0.0.1:8080", ""},
		{"", "bedrock.us-east-1.amazonaws.com", ""}, // control plane, not runtime
		{"US-EAST-1", "x", ""},
	} {
		got, err := Region(tt.cfg, tt.host)
		if got != tt.want || (err != nil) != (tt.want == "") {
			t.Errorf("Region(%q,%q) = %q,%v want %q", tt.cfg, tt.host, got, err, tt.want)
		}
	}
}

// fakeBedrock re-verifies SigV4 server-side from what actually arrived on the
// wire, then streams an eventstream response in two flushed chunks.
func fakeBedrock(t *testing.T, creds aws.CredentialsProvider, release <-chan struct{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := verifySigV4(r, creds); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = io.WriteString(w, "chunk-1\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "chunk-2\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// verifySigV4 recomputes the signature over the received request's signed
// headers, escaped path and body.
func verifySigV4(r *http.Request, creds aws.CredentialsProvider) error {
	auth := r.Header.Get("Authorization")
	_, sh, ok := strings.Cut(auth, "SignedHeaders=")
	if !ok || !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") {
		return fmt.Errorf("no sigv4 authorization: %q", auth)
	}
	sh, _, _ = strings.Cut(sh, ",")
	scope := strings.Split(strings.Fields(auth)[1], "/") // Credential=AK/date/region/service/aws4_request,
	ts, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return fmt.Errorf("x-amz-date: %w", err)
	}
	body, _ := io.ReadAll(r.Body)
	sum := sha256.Sum256(body)
	re := &http.Request{Method: r.Method, URL: r.URL, Host: r.Host, ContentLength: r.ContentLength, Header: http.Header{}}
	for _, h := range strings.Split(sh, ";") {
		if h != "host" && h != "content-length" && h != "x-amz-date" {
			re.Header[http.CanonicalHeaderKey(h)] = r.Header.Values(h)
		}
	}
	c, err := creds.Retrieve(r.Context())
	if err != nil {
		return err
	}
	if err := v4.NewSigner().SignHTTP(r.Context(), c, re, hex.EncodeToString(sum[:]), scope[3], scope[2], ts); err != nil {
		return err
	}
	if got := re.Header.Get("Authorization"); got != auth {
		return fmt.Errorf("signature mismatch:\n got %s\nwant %s", auth, got)
	}
	return nil
}

func TestTransportSignsForFakeBedrock(t *testing.T) {
	release := make(chan struct{})
	creds := credentials.NewStaticCredentialsProvider("AKID", "SECRET", "SESSION")
	srv := fakeBedrock(t, creds, release)
	client := &http.Client{Transport: (&Bedrock{Credentials: creds}).Transport(http.DefaultTransport)}

	for _, op := range []string{"invoke-with-response-stream", "converse-stream"} {
		t.Run(op, func(t *testing.T) {
			ctx := WithBedrock(context.Background(), "us-east-1")
			req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fus.x/"+op, strings.NewReader(`{"messages":[]}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer idp-token")
			req.Header.Set("X-Api-Key", "client-key")
			req.Header.Set("X-Amz-Security-Token", "client-forged")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d: %s", resp.StatusCode, b)
			}
			line, _ := bufio.NewReader(resp.Body).ReadString('\n')
			if line != "chunk-1\n" {
				t.Fatalf("first chunk %q", line)
			}
		})
	}
	close(release)
}

func TestTransportPassThroughAndMissingCreds(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { gotAuth = r.Header.Get("Authorization") }))
	t.Cleanup(srv.Close)
	b := &Bedrock{Credentials: credentials.NewStaticCredentialsProvider("", "", "")}
	client := &http.Client{Transport: b.Transport(http.DefaultTransport)}

	// Unmarked request: not signed, not touched.
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer x")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer x" {
		t.Fatalf("unmarked request auth %q", gotAuth)
	}

	// Marked request with no credentials: error, never forwarded unsigned.
	gotAuth = "unset"
	req, _ = http.NewRequestWithContext(WithBedrock(context.Background(), "us-east-1"), "POST", srv.URL, strings.NewReader("{}"))
	_, err = client.Do(req)
	if !errors.Is(err, ErrCredentials) {
		t.Fatalf("err %v want ErrCredentials", err)
	}
	if gotAuth != "unset" {
		t.Fatal("unsigned request reached upstream")
	}
}

func TestDefaultChainFromEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRETENV")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	req := httptest.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/m/invoke", strings.NewReader("{}"))
	if err := (&Bedrock{}).Sign(req, "us-east-1"); err != nil {
		t.Fatal(err)
	}
	if a := req.Header.Get("Authorization"); !strings.Contains(a, "Credential=AKIDENV/") {
		t.Fatalf("Authorization %q", a)
	}
}

func TestSignableHost(t *testing.T) {
	tests := []struct {
		host  string
		allow []string
		want  bool
	}{
		{"bedrock-runtime.us-east-1.amazonaws.com", nil, true},
		{"Bedrock-Runtime.us-east-1.amazonaws.com:443", nil, true},
		{"vpce-1.bedrock-runtime.eu-west-1.vpce.amazonaws.com", nil, true},
		{"bedrock-runtime.cn-north-1.amazonaws.com.cn", nil, true},
		{"bedrock-runtime.us-east-1.api.aws", nil, true},
		{"bedrock-runtime.us-east-1.evil.com", nil, false},
		{"amazonaws.com.evil.com", nil, false},
		{"evilamazonaws.com", nil, false},
		{"127.0.0.1:8080", nil, false},
		{"bedrock.corp.internal", []string{"bedrock.corp.internal"}, true},
		{"other.corp.internal", []string{"bedrock.corp.internal"}, false},
	}
	for _, tt := range tests {
		if got := SignableHost(tt.host, tt.allow); got != tt.want {
			t.Errorf("SignableHost(%q, %v) = %v, want %v", tt.host, tt.allow, got, tt.want)
		}
	}
}

func TestStripClientAmz(t *testing.T) {
	h := http.Header{}
	for _, k := range []string{"X-Amz-Meta-A", "x-amzn-trace-id", "X-Amz-Security-Token", "Content-Type"} {
		h.Set(k, "v")
	}
	StripClientAmz(h)
	if len(h) != 1 || h.Get("Content-Type") == "" {
		t.Fatalf("headers left: %v", h)
	}
}
