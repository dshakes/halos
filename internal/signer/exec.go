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
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
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
// puts it in an error message. The command gets a minimal environment: PATH
// (absolute entries only), HOME, every HALOS_SIGNER_* variable, and the
// variables the URI names with env= (an HSM PIN or token goes there, never
// in the URI: arguments show in ps). It runs in / (Unix). Its whole process
// group is killed when it exits, times out or is cancelled. Before every run
// the binary, its symlink target and every ancestor directory are checked
// (owner, writability) and, with sha256=, its digest.
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

var (
	envNameRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

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
	sha256  string // hex; "" = not pinned
	args    []string
	env     []string // extra variable names passed through (env=)
	keyID   string
	timeout time.Duration
	log     *slog.Logger
}

// execURIForms is the error hint naming both accepted forms.
const execURIForms = "exec:///absolute/path on Unix, exec:///C:/path/to/signer.exe on Windows"

// windowsDriveRE matches the URL path of a Windows drive path: "/C:/..." or
// "/C:\..." (the leading slash is the file-URI convention).
var windowsDriveRE = regexp.MustCompile(`^/[A-Za-z]:[/\\]`)

func parseExecURI(uri string) (execSigner, error) { return parseExecURIFor(uri, runtime.GOOS) }

// parseExecURIFor parses an exec URI for the operating system goos (a
// parameter so both forms are tested everywhere). Unix: exec:///abs/path.
// Windows, file-URI style: exec:///C:/path/to/signer.exe (forward slashes,
// or backslashes written %5C). A host component (exec://C:..., where a
// Windows path was pasted after exec://) and UNC paths (exec:////server/share,
// a share others can write to) are refused with the correct form.
func parseExecURIFor(uri, goos string) (execSigner, error) {
	var e execSigner
	rest, ok := strings.CutPrefix(uri, "exec://")
	if !ok || !strings.HasPrefix(rest, "/") {
		return e, fmt.Errorf("signer: exec URI must be %s (three slashes, no host)", execURIForms)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return e, fmt.Errorf("signer: exec URI (%s): %w", execURIForms, err)
	}
	if u.Host != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return e, fmt.Errorf("signer: exec URI must be %s (got host %q)", execURIForms, u.Host)
	}
	if strings.ContainsRune(u.Path, 0) {
		return e, fmt.Errorf("signer: exec signer path %q must be absolute and clean", u.Path)
	}
	if strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, `/\`) {
		return e, errors.New("signer: exec signer on a UNC network path is refused (a share others can write to could swap it): copy it to a local disk and use " + execURIForms)
	}
	if e.path, err = execPathFor(u.Path, goos); err != nil {
		return e, err
	}
	e.timeout = DefaultTimeout
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
		case "sha256":
			if len(vals) != 1 || !sha256HexRE.MatchString(vals[0]) {
				return e, errors.New("signer: exec sha256= must be given once, as 64 lowercase hex digits")
			}
			e.sha256 = vals[0]
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
			return e, fmt.Errorf("signer: unknown exec query parameter %q (want arg, env, key, sha256, timeout)", name)
		}
	}
	// url.Query keeps repeated args in order, which is what the command sees.
	return e, nil
}

// execPathFor turns an exec URI's (unescaped) URL path into a native path
// for goos, refusing a path that is not absolute and clean there.
func execPathFor(p, goos string) (string, error) {
	if windowsDriveRE.MatchString(p) {
		if goos != "windows" {
			return "", fmt.Errorf("signer: exec signer path %q is a Windows drive path; on %s use exec:///absolute/path", p, goos)
		}
		w := strings.ReplaceAll(p[1:], "/", `\`) // C:\path\to\signer.exe
		for _, seg := range strings.Split(w[3:], `\`) {
			if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, `:*?"<>|`) {
				return "", fmt.Errorf("signer: exec signer path %q must be absolute and clean (%s)", w, execURIForms)
			}
		}
		return w, nil
	}
	if goos == "windows" {
		return "", fmt.Errorf("signer: exec signer path %q has no drive letter; on Windows use exec:///C:/path/to/signer.exe", p)
	}
	if !path.IsAbs(p) || path.Clean(p) != p || strings.Contains(p, `\`) {
		return "", fmt.Errorf("signer: exec signer path %q must be absolute and clean (%s)", p, execURIForms)
	}
	return p, nil
}

// ExecURI builds the exec:// URI for the signer at the native path p with
// query q (arg, env, key, sha256, timeout; nil for none): exec:///abs/path
// on Unix, exec:///C:/path/to/signer.exe for a Windows drive path. Use it
// rather than concatenating "exec://"+p, which is wrong on Windows.
func ExecURI(p string, q url.Values) string {
	if len(p) >= 3 && windowsDriveRE.MatchString("/"+p[:3]) { // C:\ or C:/
		p = "/" + strings.ReplaceAll(p, `\`, "/")
	}
	u := url.URL{Scheme: "exec", Path: p}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func openExec(ctx context.Context, uri string, log *slog.Logger) (bundle.KeySigner, error) {
	e, err := parseExecURI(uri)
	if err != nil {
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
// user could replace: the path, its symlink target and every ancestor
// directory of the target must be owned by root or the current user, and
// none may be group- or world-writable (a directory may be if it is sticky,
// like /tmp). With want set, the target's SHA-256 must match. It runs before
// every exec, not only at Open, so a binary swapped later is refused.
func checkSignerBinary(path, want string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("signer: exec signer: %w", err)
	}
	if err := checkSignerFile(path, fi); err != nil {
		return err
	}
	target := path
	if fi.Mode()&os.ModeSymlink != 0 {
		if target, err = filepath.EvalSymlinks(path); err != nil {
			return fmt.Errorf("signer: exec signer: %w", err)
		}
		tfi, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("signer: exec signer: %w", err)
		}
		if err := checkSignerFile(target, tfi); err != nil {
			return err
		}
	} else if target, err = filepath.EvalSymlinks(path); err != nil {
		return fmt.Errorf("signer: exec signer: %w", err)
	}
	for dir := filepath.Dir(target); ; dir = filepath.Dir(dir) {
		dfi, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("signer: exec signer directory: %w", err)
		}
		if err := checkSignerDir(dir, dfi); err != nil {
			return err
		}
		if parent := filepath.Dir(dir); parent == dir {
			break
		}
	}
	if want == "" {
		return nil
	}
	f, err := os.Open(target) //nolint:gosec // the operator-configured signer path, checked above
	if err != nil {
		return fmt.Errorf("signer: exec signer: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("signer: exec signer: hash: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("signer: exec signer %s has sha256 %s, the URI pins %s: refusing to run it", target, got, want)
	}
	return nil
}

// signerEnv is the environment the signer runs with.
func (e execSigner) signerEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		name, val, _ := strings.Cut(kv, "=")
		switch {
		case isPathVar(name): // "PATH"; "Path" on Windows
			out = append(out, name+"="+absolutePath(val))
		case baseEnvVar(name) || strings.HasPrefix(name, ExecEnvPrefix) || slices.Contains(e.env, name):
			out = append(out, kv)
		}
	}
	return out
}

// absolutePath drops empty, "." and relative PATH entries: the signer must
// not run a helper found in its working directory.
func absolutePath(path string) string {
	var keep []string
	for _, d := range filepath.SplitList(path) {
		if filepath.IsAbs(d) {
			keep = append(keep, d)
		}
	}
	return strings.Join(keep, string(os.PathListSeparator))
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
	if err := checkSignerBinary(e.path, e.sha256); err != nil {
		return resp, err
	}
	ctx, cancel := withTimeout(ctx, e.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.path, e.args...)
	cmd.Env = e.signerEnv()
	cmd.Dir = signerWorkDir(e.path)
	cmd.Stdin = bytes.NewReader(in)
	stdout := &limitedBuffer{n: maxExecOutput}
	stderr := &limitedBuffer{n: maxExecStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = execWaitDelay // a grandchild holding the pipes cannot hang Halos
	killProcessGroup(cmd)
	err = cmd.Run()
	reapProcessGroup(cmd) // a helper the signer backgrounded must not outlive it
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
