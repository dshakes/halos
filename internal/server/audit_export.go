package server

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/storage"
)

// AuditConfig is halo-server's --audit-config file (ADR-0016): rotation of
// the hash-chained audit log and its export to SIEM sinks.
type AuditConfig struct {
	Rotation AuditRotation `json:"rotation"`
	Export   AuditExport   `json:"export"`
}

// AuditExport forwards every audit entry, at least once and in order, to each
// sink. Each sink has its own cursor, so one sink being down holds back only
// itself.
type AuditExport struct {
	Sinks               []AuditSink `json:"sinks,omitempty"`
	BatchSize           int         `json:"batchSize,omitempty"`           // entries per delivery; default 100, max 1000
	PollIntervalSeconds int         `json:"pollIntervalSeconds,omitempty"` // idle re-check; appends wake sinks at once; default 5
	MaxBackoffSeconds   int         `json:"maxBackoffSeconds,omitempty"`   // retry backoff cap; default 300
}

// AuditSink is one export destination. Credentials are SecretRefs (an
// environment variable or a file), never literals in the config.
type AuditSink struct {
	Name   string `json:"name"`             // [a-z0-9-], unique: names the cursor file and the metrics label
	Type   string `json:"type"`             // webhook | splunk-hec | syslog
	Format string `json:"format,omitempty"` // native (default: the stored entry, byte for byte) | ocsf

	URL        string               `json:"url,omitempty"`        // webhook, splunk-hec: https only
	Headers    map[string]SecretRef `json:"headers,omitempty"`    // webhook: e.g. DD-API-KEY
	HMACSecret *SecretRef           `json:"hmacSecret,omitempty"` // webhook: X-Halo-Signature over timestamp.body
	Token      *SecretRef           `json:"token,omitempty"`      // splunk-hec (required)
	Index      string               `json:"index,omitempty"`      // splunk-hec
	SourceType string               `json:"sourceType,omitempty"` // splunk-hec; default halo:audit

	Address  string `json:"address,omitempty"`  // syslog: host:port, RFC 5425 (TLS, octet counting)
	Facility int    `json:"facility,omitempty"` // syslog: 0 = 13 (log audit)

	CAFile         string `json:"caFile,omitempty"`   // trust this CA bundle instead of the system roots
	CertFile       string `json:"certFile,omitempty"` // client certificate (mTLS), with KeyFile
	KeyFile        string `json:"keyFile,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"` // per delivery; default 10
}

// SecretRef names where a secret lives: exactly one of Env or File. The value
// is read once at startup and never logged or echoed in an error.
type SecretRef struct {
	Env  string `json:"env,omitempty"`
	File string `json:"file,omitempty"`
}

const (
	sinkWebhook = "webhook"
	sinkHEC     = "splunk-hec"
	sinkSyslog  = "syslog"
	fmtNative   = "native"
	fmtOCSF     = "ocsf"
)

var (
	sinkNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	headerNameRE = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

// ParseAuditConfig decodes and validates an --audit-config file. Unknown
// fields are errors, so a typo cannot silently disable a sink.
func ParseAuditConfig(r io.Reader) (AuditConfig, error) {
	var c AuditConfig
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("audit config: %w", err)
	}
	return c, c.Validate()
}

// Validate checks the config without reading any secret.
func (c AuditConfig) Validate() error {
	if c.Rotation.MaxBytes < 0 || c.Rotation.MaxAgeSeconds < 0 {
		return errors.New("audit config: rotation bounds must be >= 0")
	}
	if c.Rotation.MaxBytes > 0 && c.Rotation.MaxBytes < 4096 {
		return errors.New("audit config: rotation.maxBytes must be at least 4096")
	}
	x := c.Export
	if x.BatchSize < 0 || x.BatchSize > 1000 || x.PollIntervalSeconds < 0 || x.MaxBackoffSeconds < 0 {
		return errors.New("audit config: export.batchSize must be 0..1000, intervals >= 0")
	}
	seen := map[string]bool{}
	for i, s := range x.Sinks {
		if err := s.validate(); err != nil {
			return fmt.Errorf("audit config: sinks[%d] (%q): %w", i, s.Name, err)
		}
		if seen[s.Name] {
			return fmt.Errorf("audit config: duplicate sink name %q", s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

func (s AuditSink) validate() error {
	if !sinkNameRE.MatchString(s.Name) {
		return errors.New("name must match [a-z0-9][a-z0-9-]{0,62}")
	}
	if s.Format != "" && s.Format != fmtNative && s.Format != fmtOCSF {
		return errors.New("format must be native or ocsf")
	}
	if (s.CertFile == "") != (s.KeyFile == "") {
		return errors.New("certFile and keyFile must be set together")
	}
	if s.TimeoutSeconds < 0 {
		return errors.New("timeoutSeconds must be >= 0")
	}
	refs := map[string]*SecretRef{"hmacSecret": s.HMACSecret, "token": s.Token}
	for h, r := range s.Headers {
		refs["headers."+h] = &r
	}
	for n, r := range refs {
		if r != nil && (r.Env == "") == (r.File == "") {
			return fmt.Errorf("%s: set exactly one of env or file", n)
		}
	}
	switch s.Type {
	case sinkWebhook, sinkHEC:
		if s.Address != "" || s.Facility != 0 {
			return errors.New("address and facility are syslog-only")
		}
		u, err := url.Parse(s.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("url must be an https URL (audit never leaves in cleartext)") // never echo the URL: it may carry a token
		}
		if s.Type == sinkHEC {
			if s.Token == nil {
				return errors.New("splunk-hec needs token")
			}
			if len(s.Headers) > 0 || s.HMACSecret != nil {
				return errors.New("headers and hmacSecret are webhook-only")
			}
			return nil
		}
		if s.Token != nil || s.Index != "" || s.SourceType != "" {
			return errors.New("token, index and sourceType are splunk-hec-only")
		}
		for h := range s.Headers {
			ch := http.CanonicalHeaderKey(h)
			if !headerNameRE.MatchString(h) || ch == "Content-Type" || strings.HasPrefix(ch, "X-Halo-") {
				return fmt.Errorf("header %q is invalid or reserved", h)
			}
		}
	case sinkSyslog:
		if s.URL != "" || len(s.Headers) > 0 || s.HMACSecret != nil || s.Token != nil || s.Index != "" || s.SourceType != "" {
			return errors.New("syslog takes address (and TLS files, facility) only")
		}
		if h, p, err := net.SplitHostPort(s.Address); err != nil || h == "" || p == "" {
			return errors.New("address must be host:port")
		}
		if s.Facility < 0 || s.Facility > 23 {
			return errors.New("facility must be 0..23")
		}
	default:
		return errors.New("type must be webhook, splunk-hec or syslog")
	}
	return nil
}

func (r SecretRef) resolve(what string) (string, error) {
	var v string
	if r.Env != "" {
		e, ok := os.LookupEnv(r.Env)
		if !ok {
			return "", fmt.Errorf("%s: environment variable %s is not set", what, r.Env)
		}
		v = e
	} else {
		b, err := os.ReadFile(r.File)
		if err != nil {
			return "", fmt.Errorf("%s: %w", what, err) // a PathError names the file, never its content
		}
		v = string(b)
	}
	if v = strings.TrimSpace(v); v == "" {
		return "", fmt.Errorf("%s: secret is empty", what)
	}
	return v, nil
}

func (s AuditSink) tlsConfig() (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.CAFile != "" {
		pem, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("caFile: %w", err)
		}
		c.RootCAs = x509.NewCertPool()
		if !c.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("caFile %s: no PEM certificates", s.CAFile)
		}
	}
	if s.CertFile != "" {
		kp, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		c.Certificates = []tls.Certificate{kp}
	}
	return c, nil
}

// auditEvent is one entry to deliver, with the exact bytes stored on disk so
// a SIEM can recompute its hash.
type auditEvent struct {
	e   AuditEntry
	raw []byte
}

// payload renders ev in the sink's format.
func payload(format string, ev auditEvent) []byte {
	if format != fmtOCSF {
		return ev.raw
	}
	b, _ := json.Marshal(ocsfEvent(ev)) // plain structs: cannot fail
	return b
}

// auditSender delivers a batch, or fails it whole; it is used by one goroutine.
type auditSender interface {
	send(ctx context.Context, evs []auditEvent) error
	close()
}

// newAuditSender resolves sink's secrets and TLS material.
func newAuditSender(s AuditSink, host string) (auditSender, error) {
	tc, err := s.tlsConfig()
	if err != nil {
		return nil, err
	}
	timeout := 10 * time.Second
	if s.TimeoutSeconds > 0 {
		timeout = time.Duration(s.TimeoutSeconds) * time.Second
	}
	format := cmp.Or(s.Format, fmtNative)
	if s.Type == sinkSyslog {
		fac := s.Facility
		if fac == 0 {
			fac = 13 // log audit
		}
		return &syslogSink{addr: s.Address, tls: tc, timeout: timeout, pri: fac*8 + 6, host: syslogHost(host), format: format}, nil
	}
	h := &httpSink{kind: s.Type, url: s.URL, format: format, host: host, index: s.Index, sourceType: cmp.Or(s.SourceType, "halo:audit"), hdr: http.Header{},
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	for name, ref := range s.Headers {
		v, err := ref.resolve("headers." + name)
		if err != nil {
			return nil, err
		}
		h.hdr.Set(name, v)
	}
	if s.HMACSecret != nil {
		v, err := s.HMACSecret.resolve("hmacSecret")
		if err != nil {
			return nil, err
		}
		h.secret = []byte(v)
	}
	if s.Token != nil {
		v, err := s.Token.resolve("token")
		if err != nil {
			return nil, err
		}
		h.hdr.Set("Authorization", "Splunk "+v)
	}
	return h, nil
}

// httpSink is the generic webhook (body: JSON array of events) and Splunk HEC
// (body: concatenated HEC event objects).
type httpSink struct {
	kind, url, format       string
	host, index, sourceType string
	hdr                     http.Header
	secret                  []byte
	client                  *http.Client
	now                     func() time.Time // tests
}

func (h *httpSink) body(evs []auditEvent) []byte {
	var b bytes.Buffer
	if h.kind == sinkWebhook {
		b.WriteByte('[')
		for i, ev := range evs {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(payload(h.format, ev))
		}
		b.WriteByte(']')
		return b.Bytes()
	}
	for _, ev := range evs {
		meta, _ := json.Marshal(struct { // plain struct: cannot fail
			Time       float64 `json:"time"`
			Host       string  `json:"host,omitempty"`
			Source     string  `json:"source"`
			SourceType string  `json:"sourcetype"`
			Index      string  `json:"index,omitempty"`
		}{float64(ev.e.Time.UnixMilli()) / 1000, h.host, "halo-server", h.sourceType, h.index})
		b.Write(meta[:len(meta)-1])
		b.WriteString(`,"event":`)
		b.Write(payload(h.format, ev))
		b.WriteString("}\n")
	}
	return b.Bytes()
}

func (h *httpSink) send(ctx context.Context, evs []auditEvent) error {
	body := h.body(evs)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: invalid URL", h.kind) // err would echo the URL
	}
	req.Header = h.hdr.Clone()
	req.Header.Set("Content-Type", "application/json")
	if len(h.secret) > 0 {
		now := time.Now
		if h.now != nil {
			now = h.now
		}
		ts := now().Unix()
		req.Header.Set(controller.TimestampHeader, strconv.FormatInt(ts, 10))
		req.Header.Set(controller.SignatureHeader, controller.Sign(h.secret, ts, body))
	}
	resp, err := h.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL
		}
		return fmt.Errorf("%s: %w", h.kind, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) // drain for keep-alive
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d", h.kind, resp.StatusCode)
	}
	return nil
}

func (h *httpSink) close() { h.client.CloseIdleConnections() }

// syslogSink writes RFC 5424 messages over TLS with RFC 5425 octet-counting
// framing. The protocol has no acknowledgement: a batch counts as delivered
// once the TLS write returns (see ADR-0016).
type syslogSink struct {
	addr, host, format string
	tls                *tls.Config
	timeout            time.Duration
	pri                int
	conn               net.Conn
}

// syslogHost makes a hostname RFC 5424-safe: printable ASCII, no spaces, <=255.
func syslogHost(h string) string {
	h = strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' {
			return -1
		}
		return r
	}, h)
	if h == "" {
		return "-"
	}
	return h[:min(len(h), 255)]
}

func (s *syslogSink) send(ctx context.Context, evs []auditEvent) error {
	var b bytes.Buffer
	for _, ev := range evs {
		msg := fmt.Sprintf("<%d>1 %s %s halo-server - audit - %s", s.pri, ev.e.Time.UTC().Format("2006-01-02T15:04:05.999999Z07:00"), s.host, payload(s.format, ev))
		fmt.Fprintf(&b, "%d %s", len(msg), msg)
	}
	if s.conn == nil {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: s.timeout}, Config: s.tls}
		c, err := d.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			return fmt.Errorf("syslog: dial: %w", err)
		}
		s.conn = c
	}
	deadline := time.Now().Add(s.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = s.conn.SetWriteDeadline(deadline) // a failed set surfaces as a failed write
	if _, err := s.conn.Write(b.Bytes()); err != nil {
		s.close() // reconnect next time; the batch is resent
		return fmt.Errorf("syslog: write: %w", err)
	}
	return nil
}

func (s *syslogSink) close() {
	if s.conn != nil {
		_ = s.conn.Close() // nothing to do on error
		s.conn = nil
	}
}

// ---- forwarder ----

// auditCursor is the last delivered entry. Seq is the logical offset; Hash
// lets a resumed forwarder prove the next entry continues what it sent.
type auditCursor struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

type auditForwarder struct {
	name       string
	log        *auditLog
	sink       auditSender
	cursorPath string
	docs       rollout.Docs // HA: the cursor document, fenced by this sink's lease; nil = cursorPath
	batch      int
	poll       time.Duration
	maxBackoff time.Duration
	logger     *slog.Logger
	cur        auditCursor // owned by run

	sent, failed, acked atomic.Uint64
	lastOK              atomic.Int64 // unix seconds
}

func newAuditForwarders(c AuditExport, dir string, l *auditLog, logger *slog.Logger) ([]*auditForwarder, error) {
	if len(c.Sinks) == 0 {
		return nil, nil
	}
	shared := l.shared != nil // HA: cursors are documents, loaded per lease term (RunAuditExport)
	if dir == "" && !shared {
		return nil, errors.New("audit export needs a data dir: cursors must survive a restart")
	}
	cdir := filepath.Join(dir, "audit-forward")
	if !shared {
		if err := os.MkdirAll(cdir, 0o750); err != nil {
			return nil, fmt.Errorf("audit export: %w", err)
		}
	}
	host, _ := os.Hostname() // "" is fine: HEC omits it, syslog sends "-"
	out := make([]*auditForwarder, 0, len(c.Sinks))
	for _, s := range c.Sinks {
		snd, err := newAuditSender(s, host)
		if err != nil {
			return nil, fmt.Errorf("audit export sink %q: %w", s.Name, err)
		}
		f := &auditForwarder{name: s.Name, log: l, sink: snd, cursorPath: filepath.Join(cdir, s.Name+".json"), logger: logger,
			batch: 100, poll: 5 * time.Second, maxBackoff: 5 * time.Minute}
		if c.BatchSize > 0 {
			f.batch = c.BatchSize
		}
		if c.PollIntervalSeconds > 0 {
			f.poll = time.Duration(c.PollIntervalSeconds) * time.Second
		}
		if c.MaxBackoffSeconds > 0 {
			f.maxBackoff = time.Duration(c.MaxBackoffSeconds) * time.Second
		}
		if shared {
			f.cursorPath = ""
		} else if b, err := os.ReadFile(f.cursorPath); err == nil {
			if err := json.Unmarshal(b, &f.cur); err != nil {
				return nil, fmt.Errorf("audit export sink %q: cursor %s: %w", s.Name, f.cursorPath, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("audit export sink %q: %w", s.Name, err)
		}
		f.acked.Store(f.cur.Seq)
		out = append(out, f)
	}
	return out, nil
}

// next reads up to batch entries after the cursor. It stops at the first
// entry that does not continue the chain (seq, prev or hash): what came
// before it is returned with the error, and nothing after it is ever sent.
func (f *auditForwarder) next() ([]auditEvent, error) {
	snap, err := f.log.snapshot()
	if err != nil {
		return nil, err
	}
	defer snap.close()
	cur := f.cur
	if head := f.log.headSeq(); cur.Seq > head {
		return nil, fmt.Errorf("cursor at seq %d is ahead of the log head %d: the data dir was restored or replaced; export halted (see the SIEM export guide)", cur.Seq, head)
	}
	var evs []auditEvent
	var broken error
	err = snap.from(cur.Seq, func(raw []byte, e AuditEntry) bool {
		if e.Seq == cur.Seq && cur.Seq != 0 && e.Hash != cur.Hash {
			broken = fmt.Errorf("entry at delivered seq %d differs from the one delivered: the log was rewritten; export halted (see the SIEM export guide)", cur.Seq)
			return false
		}
		if e.Seq <= cur.Seq {
			return true
		}
		// A new cursor anchors on the oldest entry still on disk; once anchored,
		// or from genesis, every entry must link to the one before.
		linked := e.Seq == cur.Seq+1 && e.Prev == cur.Hash
		if (cur.Seq != 0 || e.Seq == 1) && !linked {
			broken = fmt.Errorf("audit chain broken at seq %d (after delivered seq %d): export halted until the log verifies", e.Seq, cur.Seq)
			return false
		}
		if e.Hash != e.sum() {
			broken = fmt.Errorf("audit chain broken at seq %d (hash mismatch): export halted until the log verifies", e.Seq)
			return false
		}
		evs = append(evs, auditEvent{e: e, raw: bytes.Clone(raw)})
		cur = auditCursor{Seq: e.Seq, Hash: e.Hash}
		return len(evs) < f.batch
	})
	return evs, errors.Join(err, broken)
}

// step delivers one batch and advances the cursor; n is how many it sent.
// The cursor is persisted only after the sink accepted the batch, so a crash
// in between resends that batch: at-least-once, duplicates bounded by a batch.
func (f *auditForwarder) step(ctx context.Context) (int, error) {
	evs, err := f.next()
	if len(evs) == 0 {
		return 0, err
	}
	if f.cur.Seq == 0 && evs[0].e.Seq != 1 {
		f.logger.Warn("audit export starts after genesis: earlier segments are gone", "sink", f.name, "seq", evs[0].e.Seq)
	}
	if err := f.sink.send(ctx, evs); err != nil {
		return 0, fmt.Errorf("deliver seq %d..%d: %w", evs[0].e.Seq, evs[len(evs)-1].e.Seq, err)
	}
	last := evs[len(evs)-1].e
	next := auditCursor{Seq: last.Seq, Hash: last.Hash}
	b, _ := json.Marshal(next) // plain struct: cannot fail
	if err := f.saveCursor(ctx, b); err != nil {
		return 0, fmt.Errorf("persist cursor after seq %d (batch will be resent): %w", last.Seq, err)
	}
	f.cur = next
	f.acked.Store(next.Seq)
	f.sent.Add(uint64(len(evs)))
	f.lastOK.Store(time.Now().Unix())
	return len(evs), nil
}

// kindAuditCursor is the document kind of HA export cursors (one per sink).
const kindAuditCursor = "audit-cursor"

func (f *auditForwarder) saveCursor(ctx context.Context, b []byte) error {
	if f.docs == nil {
		return fsutil.WriteAtomic(f.cursorPath, b, 0o600)
	}
	// Not ctx alone: the sink has the batch, so the cursor should land even
	// at shutdown; the fence still refuses it if this replica lost the lease.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storage.OpTimeout)
	defer cancel()
	return f.docs.PutDoc(sctx, kindAuditCursor, f.name, b)
}

// loadCursor reads the shared cursor at the start of a lease term: another
// replica may have advanced it since this one last led.
func (f *auditForwarder) loadCursor(ctx context.Context) error {
	b, ok, err := f.docs.GetDoc(ctx, kindAuditCursor, f.name)
	if err != nil {
		return err
	}
	f.cur = auditCursor{}
	if ok {
		if err := json.Unmarshal(b, &f.cur); err != nil {
			return fmt.Errorf("cursor document: %w", err)
		}
	}
	f.acked.Store(f.cur.Seq)
	return nil
}

// run delivers until ctx ends. Failures back off exponentially (1s doubling,
// capped at maxBackoff, jittered) and never skip an entry.
func (f *auditForwarder) run(ctx context.Context) {
	var backoff time.Duration
	for {
		wake := f.log.changed() // before reading: an append during step is not missed
		n, err := f.step(ctx)
		if ctx.Err() != nil {
			return
		}
		wait := f.poll
		switch {
		case err != nil:
			f.failed.Add(1)
			backoff = min(max(2*backoff, time.Second), f.maxBackoff)
			wait = backoff/2 + rand.N(backoff/2+1) //nolint:gosec // jitter, not security
			wake = nil                             // back off even if entries keep arriving
			f.logger.Error("audit export failed; retrying", "sink", f.name, "delivered_seq", f.cur.Seq, "retry_in", wait, "err", err)
		case n == f.batch:
			backoff = 0
			continue // more is waiting
		default:
			backoff = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-wake:
			t.Stop()
		}
	}
}

// RunAuditExport forwards the audit log to every configured sink until ctx
// ends. Call it once; it returns at once when no sink is configured.
//
// With a shared Backend (ADR-0021) each sink forwards from exactly one replica
// at a time, under lease "audit-export-<sink>": its cursor is a document
// written through that lease's fence, so N replicas never deliver the same
// entries N times and a deposed forwarder cannot move the cursor back.
// Delivery stays at-least-once: a batch sent just before a failover is resent.
func (s *Server) RunAuditExport(ctx context.Context) {
	var wg sync.WaitGroup
	for _, f := range s.forwarders {
		wg.Go(func() {
			defer f.sink.close()
			b := s.cfg.Backend
			if b == nil {
				f.run(ctx)
				return
			}
			b.Leased(ctx, "audit-export-"+f.name, func(lctx context.Context, docs rollout.Docs) {
				f.docs = docs
				if err := f.loadCursor(lctx); err != nil {
					f.failed.Add(1)
					f.logger.Error("audit export: read cursor; retrying next lease round", "sink", f.name, "err", err)
					return
				}
				f.run(lctx)
			})
		})
	}
	wg.Wait()
}

// WriteMetrics writes halo-server's Prometheus text-format metrics.
func (s *Server) WriteMetrics(w io.Writer) {
	fmt.Fprintf(w, "# TYPE halo_server_audit_rotate_errors_total counter\nhalo_server_audit_rotate_errors_total %d\n", s.auditLog.rotateErrs.Load())
	fmt.Fprintf(w, "# HELP halo_server_audit_append_errors_total Audit appends that failed: the action was refused (strict) or went unrecorded (best-effort refusals and logins).\n# TYPE halo_server_audit_append_errors_total counter\nhalo_server_audit_append_errors_total %d\n", s.auditFails.Load())
	fmt.Fprintf(w, "# HELP halo_server_policy_refused_total Policy loads refused for security validation errors (the last good policy keeps serving).\n# TYPE halo_server_policy_refused_total counter\nhalo_server_policy_refused_total %d\n", s.pol.refused.Load())
	fmt.Fprintf(w, "# HELP halo_server_policy_tightened_total Refused policy loads whose workload rule removals were applied over the last good policy.\n# TYPE halo_server_policy_tightened_total counter\nhalo_server_policy_tightened_total %d\n", s.pol.tightened.Load())
	fmt.Fprintf(w, "# HELP halo_server_workload_rules_skipped Workload rules in the policy in effect that pin no tenant, so token exchange never matches them.\n# TYPE halo_server_workload_rules_skipped gauge\nhalo_server_workload_rules_skipped %d\n", s.pol.skipped.Load())
	if len(s.forwarders) == 0 {
		return
	}
	head := s.auditLog.headSeq()
	for _, m := range []struct {
		name, typ string
		v         func(*auditForwarder) uint64
	}{
		{"halo_server_audit_forward_sent_total", "counter", func(f *auditForwarder) uint64 { return f.sent.Load() }},
		{"halo_server_audit_forward_failed_total", "counter", func(f *auditForwarder) uint64 { return f.failed.Load() }},
		{"halo_server_audit_forward_lag_entries", "gauge", func(f *auditForwarder) uint64 { return head - min(head, f.acked.Load()) }},
		{"halo_server_audit_forward_last_success_timestamp_seconds", "gauge", func(f *auditForwarder) uint64 { return uint64(max(0, f.lastOK.Load())) }}, //nolint:gosec // clamped non-negative
	} {
		fmt.Fprintf(w, "# TYPE %s %s\n", m.name, m.typ)
		for _, f := range s.forwarders {
			fmt.Fprintf(w, "%s{sink=%q} %d\n", m.name, f.name, m.v(f))
		}
	}
}

// ---- OCSF ----

// ocsfAPIActivity is the OCSF 1.3 API Activity class (6003) shape. The field
// mapping is documented in ADR-0016; raw_data is the stored entry, so the
// hash chain stays verifiable from the SIEM.
type ocsfAPIActivity struct {
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name"`
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name"`
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name"`
	TypeUID      int    `json:"type_uid"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity"`
	StatusID     int    `json:"status_id"`
	Status       string `json:"status"`
	Time         int64  `json:"time"`
	Actor        struct {
		User struct {
			UID  string `json:"uid"`
			Name string `json:"name"`
		} `json:"user"`
	} `json:"actor"`
	API struct {
		Operation string `json:"operation"`
		Request   *struct {
			UID string `json:"uid"`
		} `json:"request,omitempty"`
	} `json:"api"`
	SrcEndpoint *struct {
		IP string `json:"ip"`
	} `json:"src_endpoint,omitempty"`
	Resources []ocsfResource `json:"resources,omitempty"`
	Metadata  struct {
		Version string `json:"version"`
		Product struct {
			Name       string `json:"name"`
			VendorName string `json:"vendor_name"`
		} `json:"product"`
		LogName  string `json:"log_name"`
		Sequence uint64 `json:"sequence"`
		UID      string `json:"uid"`
	} `json:"metadata"`
	Unmapped struct {
		Prev    string            `json:"prev"`
		Hash    string            `json:"hash"`
		Details map[string]string `json:"details,omitempty"`
	} `json:"unmapped"`
	RawData string `json:"raw_data"`
}

type ocsfResource struct {
	Name string `json:"name"`
}

func ocsfEvent(ev auditEvent) ocsfAPIActivity {
	e := ev.e
	var o ocsfAPIActivity
	o.ActivityID, o.ActivityName = 99, e.Action // Other: Halos actions are not CRUD verbs; activity_name carries the action
	o.CategoryUID, o.CategoryName = 6, "Application Activity"
	o.ClassUID, o.ClassName = 6003, "API Activity"
	o.TypeUID = o.ClassUID*100 + o.ActivityID
	o.SeverityID, o.Severity = 1, "Informational"
	o.StatusID, o.Status = 1, "Success" // only performed actions are audited
	o.Time = e.Time.UnixMilli()
	o.Actor.User.UID, o.Actor.User.Name = e.Actor, e.Actor
	o.API.Operation = e.Action
	if e.RequestID != "" {
		o.API.Request = &struct {
			UID string `json:"uid"`
		}{e.RequestID}
	}
	if e.IP != "" {
		o.SrcEndpoint = &struct {
			IP string `json:"ip"`
		}{e.IP}
	}
	if e.Target != "" {
		o.Resources = []ocsfResource{{Name: e.Target}}
	}
	o.Metadata.Version = "1.3.0"
	o.Metadata.Product.Name, o.Metadata.Product.VendorName = "Halos", "Halos"
	o.Metadata.LogName, o.Metadata.Sequence, o.Metadata.UID = "audit", e.Seq, e.Hash
	o.Unmapped.Prev, o.Unmapped.Hash, o.Unmapped.Details = e.Prev, e.Hash, e.Details
	o.RawData = string(ev.raw)
	return o
}
