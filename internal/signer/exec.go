package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/bundle"
)

// The external-signer protocol, halos.signer.v1 (guides/key-management in
// the docs). Halos runs the command (no shell) once per operation, writes one
// JSON request to its stdin and closes it, and reads one JSON response from
// stdout. Exit status 0 with a response without "error" is success. stderr is
// for diagnostics only: Halos logs it at debug level, truncated, and never
// puts it in an error message. The command gets a minimal environment: PATH,
// HOME, every HALOS_SIGNER_* variable, and the variables the URI names with
// env= (an HSM PIN or token goes there, never in the URI: arguments show in
// ps). On timeout or cancellation its whole process group is killed.
//
//	-> {"protocol":"halos.signer.v1","op":"public","keyId":"<key param>"}
//	<- {"protocol":"halos.signer.v1","algorithm":"ecdsa-p256-sha256"|"ed25519","publicKey":"<PKIX PEM>"}
//
//	-> {"protocol":"halos.signer.v1","op":"sign","keyId":"...","algorithm":"...",
//	    "message":"<base64 bytes to sign>","sha256":"<base64 SHA-256 of message>"}
//	<- {"protocol":"halos.signer.v1","signature":"<base64>"}
//
//	<- {"protocol":"halos.signer.v1","error":"<reason>"}   (any op)
//
// ed25519 signs message itself (pure Ed25519); ecdsa-p256-sha256 signs the
// sha256 digest and answers ASN.1 DER (not raw r||s).
const (
	ExecProtocol    = "halos.signer.v1"
	ExecEnvPrefix   = "HALOS_SIGNER_" // passed through to the signer
	maxExecOutput   = 64 << 10
	maxExecStderr   = 4 << 10
	maxExecStderrLg = 512 // bytes of stderr logged at debug level
	execWaitDelay   = 2 * time.Second
	maxExecTimeout  = 10 * time.Minute
)

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

type execRequest struct {
	Protocol  string `json:"protocol"`
	Op        string `json:"op"`
	KeyID     string `json:"keyId,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Message   []byte `json:"message,omitempty"`
	SHA256    []byte `json:"sha256,omitempty"`
}

type execResponse struct {
	Protocol  string `json:"protocol"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
	Signature []byte `json:"signature"`
	Error     string `json:"error"`
}

type execSigner struct {
	path    string
	args    []string
	env     []string // extra variable names passed through (env=)
	keyID   string
	timeout time.Duration
	log     *slog.Logger
}

func parseExecURI(uri string) (execSigner, error) {
	var e execSigner
	u, err := url.Parse(uri)
	if err != nil {
		return e, fmt.Errorf("signer: exec URI: %w", err)
	}
	if u.Host != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return e, fmt.Errorf("signer: exec URI must be exec:///absolute/path[?arg=...] (got host %q)", u.Host)
	}
	if !filepath.IsAbs(u.Path) || filepath.Clean(u.Path) != u.Path || strings.ContainsRune(u.Path, 0) {
		return e, fmt.Errorf("signer: exec signer path %q must be absolute and clean", u.Path)
	}
	e.path, e.timeout = u.Path, DefaultTimeout
	for name, vals := range u.Query() {
		switch name {
		case "arg":
			e.args = vals
		case "env":
			for _, v := range vals {
				if !envNameRE.MatchString(v) {
					return e, fmt.Errorf("signer: exec env=%q is not an environment variable name", v)
				}
			}
			e.env = vals
		case "key":
			if len(vals) != 1 {
				return e, errors.New("signer: exec key= given more than once")
			}
			e.keyID = vals[0]
		case "timeout":
			if len(vals) != 1 {
				return e, errors.New("signer: exec timeout= given more than once")
			}
			d, err := time.ParseDuration(vals[0])
			if err != nil || d <= 0 || d > maxExecTimeout {
				return e, fmt.Errorf("signer: exec timeout=%q, want a duration in (0, %s]", vals[0], maxExecTimeout)
			}
			e.timeout = d
		default:
			return e, fmt.Errorf("signer: unknown exec query parameter %q (want arg, env, key, timeout)", name)
		}
	}
	// url.Query keeps repeated args in order, which is what the command sees.
	return e, nil
}

func openExec(ctx context.Context, uri string, log *slog.Logger) (bundle.KeySigner, error) {
	e, err := parseExecURI(uri)
	if err != nil {
		return nil, err
	}
	if err := checkSignerBinary(e.path); err != nil {
		return nil, err
	}
	e.log = log
	if e.log == nil {
		e.log = slog.Default()
	}
	desc := "exec signer " + e.path
	resp, err := e.run(ctx, execRequest{Protocol: ExecProtocol, Op: "public", KeyID: e.keyID})
	if err != nil {
		return nil, fmt.Errorf("signer: %s public: %w", desc, err)
	}
	if !slices.Contains(bundle.Algorithms, resp.Algorithm) {
		return nil, fmt.Errorf("signer: %s answered algorithm %q; want one of %v", desc, resp.Algorithm, bundle.Algorithms)
	}
	pub, err := bundle.ParseVerifier([]byte(resp.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("signer: %s public key: %w", desc, err)
	}
	alg := resp.Algorithm
	return newRemote(alg, pub, desc, func(ctx context.Context, msg string) ([]byte, error) {
		h := sha256.Sum256([]byte(msg))
		r, err := e.run(ctx, execRequest{Protocol: ExecProtocol, Op: "sign", KeyID: e.keyID, Algorithm: alg, Message: []byte(msg), SHA256: h[:]})
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}
		if len(r.Signature) == 0 {
			return nil, errors.New("sign: no signature in the response")
		}
		return r.Signature, nil
	})
}

// checkSignerBinary refuses a signer program anyone but root or the current
// user could replace: the path and, for a symlink, its target must not be
// group- or world-writable and must be owned by root or the current user.
func checkSignerBinary(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("signer: exec signer: %w", err)
	}
	if err := checkSignerFile(path, fi); err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("signer: exec signer: %w", err)
	}
	tfi, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("signer: exec signer: %w", err)
	}
	return checkSignerFile(target, tfi)
}

// signerEnv is the environment the signer runs with.
func (e execSigner) signerEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "PATH" || name == "HOME" || strings.HasPrefix(name, ExecEnvPrefix) || slices.Contains(e.env, name) {
			out = append(out, kv)
		}
	}
	return out
}

// limitedBuffer keeps the first n bytes and counts the rest.
type limitedBuffer struct {
	buf   bytes.Buffer
	n     int
	extra int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.n - b.buf.Len(); room > 0 {
		if len(p) <= room {
			b.buf.Write(p)
		} else {
			b.buf.Write(p[:room])
			b.extra += len(p) - room
		}
	} else {
		b.extra += len(p)
	}
	return len(p), nil
}

// run executes the signer once with req on stdin.
func (e execSigner) run(ctx context.Context, req execRequest) (execResponse, error) {
	var resp execResponse
	in, err := json.Marshal(req)
	if err != nil {
		return resp, fmt.Errorf("encode request: %w", err)
	}
	ctx, cancel := withTimeout(ctx, e.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.path, e.args...)
	cmd.Env = e.signerEnv()
	cmd.Stdin = bytes.NewReader(in)
	stdout := &limitedBuffer{n: maxExecOutput}
	stderr := &limitedBuffer{n: maxExecStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = execWaitDelay // a grandchild holding the pipes cannot hang Halos
	killProcessGroup(cmd)
	err = cmd.Run()
	if diag := strings.TrimSpace(stderr.buf.String()); diag != "" {
		if len(diag) > maxExecStderrLg {
			diag = diag[:maxExecStderrLg] + "...(truncated)"
		}
		e.log.Debug("exec signer stderr", "signer", e.path, "op", req.Op, "stderr", diag)
	}
	if ctx.Err() != nil {
		return resp, fmt.Errorf("timed out or canceled: %w", ctx.Err())
	}
	if err != nil {
		return resp, fmt.Errorf("%w (stderr logged at debug level)", err)
	}
	if stdout.extra > 0 {
		return resp, fmt.Errorf("response over %d bytes", maxExecOutput)
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.buf.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		return resp, fmt.Errorf("decode response: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return resp, errors.New("trailing data after the JSON response")
	}
	if resp.Protocol != ExecProtocol {
		return resp, fmt.Errorf("response protocol %q, want %q", resp.Protocol, ExecProtocol)
	}
	if resp.Error != "" {
		return resp, fmt.Errorf("signer error: %s", resp.Error)
	}
	return resp, nil
}
