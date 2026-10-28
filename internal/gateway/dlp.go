package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dshakes/halos/internal/policy"
)

// DLP (ADR-0033): secret detection and prompt-injection scoring on model-call
// bodies. Detectors are RE2 (Go regexp: linear time) behind a literal
// prefilter, so a body without a candidate costs one substring search per
// detector. A secret is never logged, audited or kept: findings carry the
// detector id, an 8-hex SHA-256 prefix and the JSON path.

// DLP finding kinds.
const (
	DLPSecret    = "secret"
	DLPInjection = "injection"
	// DLPTruncated is DLPReport.Blocked (never a finding kind) when the secret
	// action is block and the body could not be scanned in full.
	DLPTruncated = "truncated"
)

// Codes on a DLP block (OpenAI Responses error code; Rejection.Code).
const (
	CodeSecretDetected    = "secret_detected"
	CodeInjectionDetected = "prompt_injection_detected"
	CodeScanIncomplete    = "dlp_scan_incomplete"
)

// dlpScanBudget bounds the time one request scan may take; past it the rest
// of the body is not scanned (counted as truncated) and, under monitor or
// redact, the request passes with the findings so far; under a block secret
// action it is refused (DLPTruncated).
const dlpScanBudget = 250 * time.Millisecond

// DLPFinding is one secret or injection signal. It never holds the secret.
type DLPFinding struct {
	Kind     string   `json:"kind"`               // DLPSecret | DLPInjection
	Detector string   `json:"detector"`           // detector id; "injection" for injection
	Hash     string   `json:"hash,omitempty"`     // first 8 hex of SHA-256(secret)
	Location string   `json:"location"`           // JSON path in the request, or "response"
	Score    int      `json:"score,omitempty"`    // injection score
	Signals  []string `json:"signals,omitempty"`  // injection signals that scored
	ToolData bool     `json:"toolData,omitempty"` // found in a tool result or document
}

// DLPReport is a request scan's outcome.
type DLPReport struct {
	SecretAction, InjectionAction string // effective actions (policy.DLP*)
	Findings                      []DLPFinding
	// Redacted is the body with every secret replaced, nil when unchanged
	// (no redaction). It is the pre-model-rewrite body: what the shadow mirror sends.
	Redacted  []byte
	Truncated bool   // the body was larger than the scan cap or the scan ran out of time
	OverCap   bool   // Truncated because the body was larger than the scan cap
	Blocked   string // DLPSecret | DLPInjection | DLPTruncated when the request is refused
	Took      time.Duration
}

// Count returns the findings of kind.
func (r *DLPReport) Count(kind string) int {
	if r == nil {
		return 0
	}
	n := 0
	for _, f := range r.Findings {
		if f.Kind == kind {
			n++
		}
	}
	return n
}

type detector struct {
	id string
	// anchors are literals the secret starts at or contains. The regex runs
	// only on a window of back bytes before and fwd bytes after each anchor
	// occurrence, so its cost follows the candidates, not the text. nil = the
	// whole text (org patterns).
	anchors   []string
	fold      bool // anchors are lower case and searched case-insensitively (ASCII)
	back, fwd int
	require   string // a literal that must occur somewhere in the text; "" = none
	re        *regexp.Regexp
	group     int               // capture group that is the secret; 0 = whole match
	check     func(string) bool // extra validation of the secret; nil = none
	// gate, when set, is a cheap test at anchor offset i that must pass
	// before the regex runs on that window.
	gate func(s string, i int) bool
}

// builtinDetectors are high-precision: a token format with a fixed prefix or
// structure, or (generic-secret) a key name next to a high-entropy value.
var builtinDetectors = []*detector{
	{id: "aws-access-key-id", anchors: []string{"AKIA", "ASIA", "ABIA", "ACCA"}, back: 1, fwd: 21, re: regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`),
		check: func(s string) bool { return !strings.HasSuffix(s, "EXAMPLE") }}, // AWS's documentation key
	{id: "github-token", anchors: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, back: 1, fwd: 260, re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b`)},
	{id: "gitlab-token", anchors: []string{"glpat-", "glptt-", "gldt-", "glrt-"}, back: 1, fwd: 71, re: regexp.MustCompile(`\b(?:glpat|glptt|gldt|glrt)-[A-Za-z0-9_-]{20,64}\b`)},
	{id: "slack-token", anchors: []string{"xox"}, back: 1, fwd: 256, re: regexp.MustCompile(`\bxox[abposr]-[0-9]{6,}-[0-9A-Za-z-]{10,}`)},
	{id: "slack-webhook", anchors: []string{"https://hooks.slack.com/"}, fwd: 256, re: regexp.MustCompile(`https://hooks\.slack\.com/(?:services|workflows)/T[A-Z0-9]{6,}/[A-Z0-9]{6,}/[A-Za-z0-9]{16,}`)},
	{id: "stripe-key", anchors: []string{"_live_"}, back: 3, fwd: 256, re: regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b`)},
	{id: "anthropic-api-key", anchors: []string{"sk-ant-"}, back: 1, fwd: 512, re: regexp.MustCompile(`\bsk-ant-(?:api|admin|oat)[0-9]{2}-[A-Za-z0-9_-]{32,}`)},
	{id: "openai-api-key", anchors: []string{"T3BlbkFJ"}, back: 256, fwd: 264, re: regexp.MustCompile(`\bsk-(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}`)},
	// A JWT: base64url JSON header and payload ({" encodes to eyJ) and a signature.
	{id: "jwt", anchors: []string{"eyJ"}, back: 1, fwd: 8192, re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}`)},
	// PEM private keys with a real body (documentation stubs like "..." do not match).
	{id: "private-key", anchors: []string{"-----BEGIN "}, fwd: 16 << 10, re: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:\\[nr]|[\s])*[A-Za-z0-9+/=\s\\:-]{64,}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
	// A GCP service-account key file: its private_key_id. Its private_key is the PEM detector's.
	{id: "gcp-service-account", require: "service_account", anchors: []string{`"private_key_id`}, fwd: 96, re: regexp.MustCompile(`"private_key_id\\?"\s*:\s*\\?"([a-f0-9]{40})\\?"`), group: 1},
	// generic-secret: a secret-ish key name assigned a high-entropy value.
	{id: "generic-secret", anchors: []string{"secret", "token", "passw", "pwd", "key", "credential", "auth"}, fold: true, back: 16, fwd: 300,
		re: regexp.MustCompile(`(?i)(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_.-]{0,20}\\?["']?\s*(?:[:=]|:=|=>)\s*\\?["'\x60]?([A-Za-z0-9+/_~.=-]{24,256})`), group: 1,
		check: highEntropy, gate: assignedLongValue},
}

// assignedLongValue reports whether the key name at s[i:] is followed, within
// a few bytes, by an assignment and a run of at least 24 value characters:
// generic-secret's regex only runs where it can match.
func assignedLongValue(s string, i int) bool {
	end := min(len(s), i+48)
	j := strings.IndexAny(s[i:end], ":=")
	if j < 0 {
		return false
	}
	k := i + j + 1
	for k < len(s) && k < i+j+8 && strings.IndexByte(" \t=>\"'`\\", s[k]) >= 0 {
		k++
	}
	n := 0
	for k+n < len(s) && n < 24 && isValueByte(s[k+n]) {
		n++
	}
	return n >= 24
}

func isValueByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("+/_~.=-", c) >= 0
}

var builtinAnchors = func() *anchorIndex {
	x := newAnchorIndex(len(builtinDetectors))
	for i, d := range builtinDetectors {
		x.add(i, d.fold, d.anchors...)
	}
	return x
}()

// asciiLower lower-cases ASCII letters only, so byte offsets stay valid in s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// anchorIndex finds every anchor occurrence for a set of detectors (or
// injection signals) in one pass over the text: a table keyed by an anchor's
// first two bytes, then a prefix compare. Anchors are at least 2 bytes.
type anchorIndex struct {
	tab  [2]*[1 << 16]bool // [0] exact, [1] ASCII case-folded
	refs [2]map[uint16][]anchorRef
	n    int
}

type anchorRef struct {
	a   string
	idx int // detector or signal index
}

func newAnchorIndex(n int) *anchorIndex {
	x := &anchorIndex{n: n}
	for i := range x.tab {
		x.tab[i], x.refs[i] = new([1 << 16]bool), map[uint16][]anchorRef{}
	}
	return x
}

func (x *anchorIndex) add(idx int, fold bool, anchors ...string) {
	f := 0
	if fold {
		f = 1
	}
	for _, a := range anchors {
		k := uint16(a[0])<<8 | uint16(a[1])
		x.tab[f][k] = true
		x.refs[f][k] = append(x.refs[f][k], anchorRef{a, idx})
	}
}

// hits returns, per index, the sorted offsets where one of its anchors starts.
func (x *anchorIndex) hits(s, lower string) [][]int {
	out := make([][]int, x.n)
	for i := 0; i+1 < len(s); i++ {
		for f, hay := range [2]string{s, lower} {
			k := uint16(hay[i])<<8 | uint16(hay[i+1])
			if !x.tab[f][k] {
				continue
			}
			for _, r := range x.refs[f][k] {
				if strings.HasPrefix(hay[i:], r.a) && (len(out[r.idx]) == 0 || out[r.idx][len(out[r.idx])-1] != i) {
					out[r.idx] = append(out[r.idx], i)
				}
			}
		}
	}
	return out
}

// dlpRegexBytes bounds the bytes one request scan (or one response) feeds to
// regexes; past it the scan stops and is truncated. With merged windows a
// scan feeds each detector about the text once, so real bodies stay far below.
const dlpRegexBytes = 64 << 20

// nearChunk is the most text near feeds a regex in one call, so the scan
// budget is checked at least that often.
const nearChunk = 32 << 10

// scanBudget bounds one scan's regex work by a deadline (zero: none) and a
// byte count. A nil budget is unlimited.
type scanBudget struct {
	deadline time.Time
	bytes    int
	out      bool // ran out: the scan is incomplete
}

func newScanBudget(deadline time.Time) *scanBudget {
	return &scanBudget{deadline: deadline, bytes: dlpRegexBytes}
}

// spend charges n regex bytes; false once the budget has run out.
func (b *scanBudget) spend(n int) bool {
	if b == nil {
		return true
	}
	if !b.out {
		b.bytes -= n
		b.out = b.bytes < 0 || (!b.deadline.IsZero() && !time.Now().Before(b.deadline))
	}
	return !b.out
}

// exhausted reports whether b ran out.
func (b *scanBudget) exhausted() bool { return b != nil && b.out }

// near runs re on the windows [i-back, i+fwd) around the anchor offsets in at
// that pass gate (or on all of s when whole), merged where they overlap and
// fed in chunks of nearChunk (overlapping by back+fwd), so each byte of s is
// scanned about once however many anchors repeat in it. Matches come from the
// index engine; submatch offsets are computed only for a match, when sub is
// set. fn gets each match's offsets in s and returns false to stop. near
// returns false when b ran out before the windows were covered.
func near(re *regexp.Regexp, s string, at []int, whole bool, back, fwd int, gate func(string, int) bool, sub bool, b *scanBudget, fn func(m []int) bool) bool {
	next := 0 // matches are reported left to right, never overlapping
	// scan covers [lo, hi): false to stop (fn said so, or b ran out).
	scan := func(lo, hi, overlap int) bool {
		for p := lo; p < hi; p += nearChunk {
			end := min(hi, p+nearChunk+overlap)
			if whole {
				end = hi
			}
			if !b.spend(end - p) {
				return false
			}
			for _, m := range re.FindAllStringIndex(s[p:end], -1) {
				a, z := m[0]+p, m[1]+p
				if a < next || (end < hi && a >= p+nearChunk) { // already reported, or the next chunk's
					continue
				}
				out := []int{a, z}
				if sub { // submatches of this match only, with one byte of context for \b
					cut := min(len(s), z+1)
					if sm := re.FindStringSubmatchIndex(s[a:cut]); sm != nil && sm[0] == 0 {
						for k := range sm {
							if sm[k] >= 0 {
								sm[k] += a
							}
						}
						out = sm
					}
				}
				next = z
				if !fn(out) {
					return false
				}
			}
			if whole {
				break
			}
		}
		return true
	}
	if whole {
		return scan(0, len(s), 0) || !b.exhausted()
	}
	lo, hi := -1, -1
	for _, i := range at {
		if gate != nil && !gate(s, i) {
			continue
		}
		wlo, whi := max(0, i-back), min(len(s), i+fwd)
		if lo >= 0 && wlo <= hi {
			hi = max(hi, whi)
			continue
		}
		if lo >= 0 && !scan(lo, hi, back+fwd) {
			return !b.exhausted()
		}
		lo, hi = wlo, whi
	}
	if lo >= 0 && !scan(lo, hi, back+fwd) {
		return !b.exhausted()
	}
	return true
}

// highEntropy accepts values that look generated: letters and digits mixed,
// at least 3.5 bits of Shannon entropy per character and no placeholder
// shape. Identifiers (camelCase, dotted paths) and hex digests rarely pass.
func highEntropy(s string) bool {
	if strings.ContainsAny(s, ".") && !strings.ContainsAny(s, "+/=_-") { // pkg.Func, a.b.c
		return false
	}
	var lower, upper, digit bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	if !digit || !lower || !upper {
		return false
	}
	words := 0 // path- or sentence-like: two or more lowercase words between separators
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(seg) >= 4 && strings.ToLower(seg) == seg && strings.IndexFunc(seg, unicode.IsDigit) < 0 {
			words++
		}
	}
	if words >= 2 {
		return false
	}
	l := strings.ToLower(s)
	for _, p := range []string{"example", "xxxx", "your", "placeholder", "changeme", "redacted", "dummy", "sample", "test", "fake"} {
		if strings.Contains(l, p) {
			return false
		}
	}
	return entropy(s) >= 3.5
}

func entropy(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h, n := 0.0, float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// DetectorIDs lists the built-in detector ids, sorted.
func DetectorIDs() []string {
	out := make([]string, 0, len(builtinDetectors))
	for _, d := range builtinDetectors {
		out = append(out, d.id)
	}
	sort.Strings(out)
	return out
}

// dlpEngine is the compiled detector set for one policy DLP block.
type dlpEngine struct {
	off []bool      // per builtinDetectors: disabled by policy
	org []*detector // org patterns
}

var dlpEngines struct {
	mu sync.Mutex
	m  map[*policy.DLP]*dlpEngine // one entry per live snapshot; a reload is a new pointer
}

// engineFor compiles d once per policy snapshot. Org patterns that do not
// compile are skipped (halo validate refuses them).
func engineFor(d *policy.DLP) *dlpEngine {
	dlpEngines.mu.Lock()
	defer dlpEngines.mu.Unlock()
	if e, ok := dlpEngines.m[d]; ok {
		return e
	}
	e := &dlpEngine{off: make([]bool, len(builtinDetectors))}
	for i, b := range builtinDetectors {
		e.off[i] = slices.Contains(d.Secrets.Disable, b.id)
	}
	for _, p := range d.Secrets.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil || re.MatchString("") {
			continue
		}
		g := 0
		if re.NumSubexp() > 0 {
			g = 1
		}
		e.org = append(e.org, &detector{id: p.ID, re: re, group: g})
	}
	if dlpEngines.m == nil || len(dlpEngines.m) >= 8 { // ponytail: old snapshots are dropped wholesale; a handful live at once
		dlpEngines.m = map[*policy.DLP]*dlpEngine{}
	}
	dlpEngines.m[d] = e
	return e
}

type secretMatch struct {
	det        string
	start, end int // byte offsets of the secret in the text
	hash       string
}

// secrets returns the non-overlapping secrets in s, in order. When b runs out
// it returns those found so far and b.exhausted() reports the scan incomplete.
func (e *dlpEngine) secrets(s string, b *scanBudget) []secretMatch {
	var out []secretMatch
	hits := builtinAnchors.hits(s, asciiLower(s))
	for di, d := range builtinDetectors {
		if e.off[di] || len(hits[di]) == 0 || (d.require != "" && !strings.Contains(s, d.require)) {
			continue
		}
		if !near(d.re, s, hits[di], false, d.back, d.fwd, d.gate, d.group > 0, b, func(m []int) bool { return e.add(&out, d, s, m) }) {
			break
		}
	}
	for _, d := range e.org {
		if b.exhausted() || !near(d.re, s, nil, true, 0, 0, nil, d.group > 0, b, func(m []int) bool { return e.add(&out, d, s, m) }) {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	// Earliest first; on overlap keep the first (then longest) and drop the rest.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].start != out[j].start {
			return out[i].start < out[j].start
		}
		return out[i].end > out[j].end
	})
	kept := out[:0]
	for _, m := range out {
		if len(kept) > 0 && m.start < kept[len(kept)-1].end {
			continue
		}
		m.hash = SecretHash(s[m.start:m.end])
		kept = append(kept, m)
	}
	return kept
}

// add records match m of d. Every match is kept, never capped: a secret past
// a cap would go unredacted (and unblocked) without the scan being marked
// truncated. The scan budget bounds the work instead.
func (e *dlpEngine) add(out *[]secretMatch, d *detector, s string, m []int) bool {
	a, b := m[0], m[1]
	if d.group > 0 && len(m) > 2*d.group+1 && m[2*d.group] >= 0 {
		a, b = m[2*d.group], m[2*d.group+1]
	}
	if a < b && (d.check == nil || d.check(s[a:b])) {
		*out = append(*out, secretMatch{det: d.id, start: a, end: b})
	}
	return true
}

// SecretHash is the 8-hex SHA-256 prefix a finding and a redaction marker
// carry: enough to correlate one secret across events, never to recover it.
func SecretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:4])
}

// RedactionMarker replaces a secret in a redacted body.
func RedactionMarker(detector, hash string) string {
	return "[REDACTED:" + detector + ":" + hash + "]"
}

// ---- prompt injection ----

type injSignal struct {
	name      string
	weight    int
	anchors   []string // lower-case literals the regex is run near (see near)
	back, fwd int
	re        *regexp.Regexp
	// match, when set, replaces near(re): a linear matcher for a signal whose
	// regex is too costly to run on every window (counted repetitions).
	match func(s string, b *scanBudget) bool
}

// htmlCommentKeywords are the imperatives html-comment-imperative looks for.
var htmlCommentKeywords = regexp.MustCompile(`(?i)\b(?:ignore (?:previous|prior|all)|you must|assistant|ai agent|do not (?:tell|mention|reveal)|curl |wget |send (?:the|all|your)|exfiltrate)\b`)

// htmlCommentImperative reports an HTML comment (`<!--` ... `-->`, no `>`
// inside, as `[^>]` in the regex it replaces) holding an imperative with at
// most 1000 characters on either side. Each `-->` is visited once and its
// comment is bounded by the previous `>`, so the work is linear in s: the
// equivalent regex, `<!--[^>]{0,1000}?\b(...)\b[^>]{0,1000}?-->`, costs about
// 2000 NFA states per byte of every window.
func htmlCommentImperative(s string, b *scanBudget) bool {
	for off := 0; ; {
		j := strings.Index(s[off:], "-->")
		if j < 0 {
			return false
		}
		j += off
		lo := max(off, j-2004)
		if k := strings.LastIndexByte(s[lo:j], '>'); k >= 0 {
			lo += k + 1
		}
		if i := strings.Index(s[lo:j], "<!--"); i >= 0 {
			body := s[lo+i+4 : j]
			if !b.spend(len(body)) {
				return false
			}
			for _, m := range htmlCommentKeywords.FindAllStringIndex(body, -1) {
				if m[0] <= 1000 && len(body)-m[1] <= 1000 {
					return true
				}
			}
		}
		off = j + 3
	}
}

// injectionSignals are conservative heuristics: each counts once per text,
// and the default threshold needs two independent ones.
var injectionSignals = []injSignal{
	{"instruction-override", 3, []string{"ignore", "disregard", "forget", "override"}, 1, 120,
		regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|preceding|original|system)\s+(?:instructions?|prompts?|rules|directives|guidelines|messages)\b`), nil},
	{"role-reassignment", 2, []string{"you are now", "new instructions", "new system instructions", "from now on", "system prompt"}, 16, 64,
		regexp.MustCompile(`(?i)\b(?:you are now (?:a|an|in|the|DAN)\b|new (?:system )?instructions?\s*:|from now on,? you (?:must|will|are)\b|(?:reveal|print|output|repeat) (?:your|the) system prompt)`), nil},
	{"fake-turn", 2, []string{"<system>", "</system>", "<instructions>", "</instructions>", "<tool_result>", "</tool_result>", "<function_results>", "</function_results>", "[inst]", "[/inst]", "<|im_", "human:", "assistant:", "system:"}, 64, 24,
		regexp.MustCompile(`(?m)(?:^|\n)[ \t]*(?:</?(?:system|instructions|tool_result|function_results|antml:[a-z_]+)>|\[/?INST\]|<\|im_(?:start|end)\|>|(?:Human|Assistant|SYSTEM):\s)`), nil},
	{name: "html-comment-imperative", weight: 2, anchors: []string{"<!--"}, match: htmlCommentImperative},
	{"exfil-url", 2, []string{"!["}, 0, 800,
		regexp.MustCompile(`(?i)!\[[^\]]{0,200}\]\(https?://[^)\s]{1,500}[?&][a-z0-9_]{1,40}=[^)\s&]{24,}`), nil},
}

var signalAnchors = func() *anchorIndex {
	x := newAnchorIndex(len(injectionSignals) + 1)
	for i, sg := range injectionSignals {
		x.add(i, true, sg.anchors...)
	}
	x.add(len(injectionSignals), true, bypassHints...)
	return x
}()

// bypassHints prefilter policy.BypassToken (a case-insensitive regex over the whole text).
var bypassHints = []string{"bypass", "danger", "yolo", "allow-all"}

// bypassNear runs policy.BypassToken on the windows around the hint offsets,
// merged where they overlap and charged to b.
func bypassNear(s string, at []int, b *scanBudget) bool {
	check := func(lo, hi int) bool {
		for p := lo; p < hi; p += nearChunk {
			end := min(hi, p+nearChunk+96)
			if !b.spend(end-p) || policy.BypassToken(s[p:end]) != "" {
				return true // found, or out of budget: stop
			}
		}
		return false
	}
	lo, hi := -1, -1
	for _, i := range at {
		wlo, whi := max(0, i-32), min(len(s), i+64)
		if lo >= 0 && wlo <= hi {
			hi = max(hi, whi)
			continue
		}
		if lo >= 0 && check(lo, hi) {
			return !b.exhausted()
		}
		lo, hi = wlo, whi
	}
	return lo >= 0 && check(lo, hi) && !b.exhausted()
}

// injectionScore scores one tool-result text. A URL carrying a detected
// secret and a permission-bypass token (policy.BypassToken) add signals of
// their own. Regex work is charged to b; b.exhausted() then reports the score
// incomplete.
func injectionScore(s string, secrets []secretMatch, b *scanBudget) (score int, signals []string) {
	hits := signalAnchors.hits(s, asciiLower(s))
	for i, sg := range injectionSignals {
		hit := false
		switch {
		case len(hits[i]) == 0:
		case sg.match != nil:
			hit = sg.match(s, b)
		default:
			near(sg.re, s, hits[i], false, sg.back, sg.fwd, nil, false, b, func([]int) bool { hit = true; return false })
		}
		if hit {
			score += sg.weight
			signals = append(signals, sg.name)
		}
	}
	if invisible := invisibleUnicode(s); invisible > 0 {
		score += invisible
		signals = append(signals, "invisible-unicode")
	}
	for _, m := range secrets {
		if urlAround(s, m.start) {
			score += 3
			signals = append(signals, "secret-in-url")
			break
		}
	}
	if bypassNear(s, hits[len(injectionSignals)], b) {
		score += 2
		signals = append(signals, "permission-bypass")
	}
	return score, signals
}

// invisibleUnicode scores hidden characters: 3 for Unicode tag characters
// (invisible ASCII smuggling), 2 for zero-width or bidi controls, else 0.
func invisibleUnicode(s string) int {
	if strings.IndexFunc(s, func(r rune) bool { return r >= 0x200B }) < 0 { // nothing at or above U+200B: nothing hidden
		return 0
	}
	n := 0
	for i, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			return 3
		case r == 0xFEFF && i == 0: // a BOM at the start is benign
		case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069, r == 0xFEFF:
			n = 2
		}
	}
	return n
}

// urlAround reports whether offset i sits inside an http(s) URL.
func urlAround(s string, i int) bool {
	lo := max(0, i-512)
	j := strings.LastIndex(s[lo:i], "http")
	if j < 0 {
		return false
	}
	seg := s[lo+j : i]
	return (strings.HasPrefix(seg, "http://") || strings.HasPrefix(seg, "https://")) && !strings.ContainsAny(seg, " \t\n\"'<>")
}

// ---- request scanning ----

// dlpUserData are the keys whose value is caller- or tool-defined JSON: tool
// inputs (Anthropic and Bedrock input), function arguments and responses
// (Gemini args, response; Bedrock toolResult json), tool schemas and
// metadata. Nothing under them is protocol: no value there is skipped, and no
// key there is shown in a location. A top-level "input" is the OpenAI
// Responses conversation, not a tool input.
var dlpUserData = map[string]bool{"input": true, "args": true, "response": true, "json": true, "arguments": true,
	"input_schema": true, "inputSchema": true, "parameters": true, "schema": true, "metadata": true}

// userDataAt is the index of the first frame of st that is inside user data
// (dlpUserData), len(st) when none is.
func userDataAt(st []jsonFrame) int {
	for i, f := range st {
		if f.obj && dlpUserData[f.key] && (i > 0 || f.key != "input") {
			return i + 1
		}
	}
	return len(st)
}

// dlpSkipKeys are protocol ids and enums, never scanned at a protocol
// position (outside user data).
var dlpSkipKeys = map[string]bool{
	"model": true, "id": true, "type": true, "role": true, "tool_use_id": true, "call_id": true,
	"previous_response_id": true, "media_type": true, "mimeType": true, "mime_type": true,
	"cache_control": true, "file_id": true,
}

// dlpOpaque are opaque or signed blobs, skipped only where the protocol puts
// them: key -> the container of the object holding it ("x[]" is an element of
// array x). Anthropic image and document source.data and redacted_thinking
// data (base64), thinking blocks' thinking and signature (signed: changing
// them breaks the next turn), Bedrock reasoningText.signature, Gemini
// inlineData.data and parts[].thoughtSignature, OpenAI Responses reasoning
// items' encrypted_content.
var dlpOpaque = map[string][]string{
	"data":              {"source", "inlineData", "content[]"},
	"thinking":          {"content[]"},
	"signature":         {"content[]", "reasoningText"},
	"thoughtSignature":  {"parts[]"},
	"encrypted_content": {"input[]", "output[]"},
}

// skipValue reports whether the string value at the top of st is a protocol
// id, enum or opaque blob that is not scanned.
func skipValue(st []jsonFrame) bool {
	n := len(st)
	if n == 0 || !st[n-1].obj || n-1 >= userDataAt(st) {
		return false
	}
	k := st[n-1].key
	if dlpSkipKeys[k] {
		return true
	}
	where, ok := dlpOpaque[k]
	if !ok || n < 2 {
		return false
	}
	c := st[n-2].key // the object holding k is the value of this key...
	if !st[n-2].obj {
		if n < 3 || !st[n-3].obj {
			return false
		}
		c = st[n-3].key + "[]" // ...or an element of this array
	}
	return slices.Contains(where, c)
}

type jsonFrame struct {
	obj     bool
	key     string // obj: current key
	idx     int    // array: current index
	wantKey bool
}

// dlpPathKeys are the wire protocols' own keys, the only ones a location shows.
var dlpPathKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range strings.Fields(`messages content text system input output instructions contents parts
		functionResponse functionCall response args name id toolResult toolUse toolUseId json source document image
		thinking signature data inlineData fileData mimeType media_type type role model tools input_schema description
		parameters inputSchema toolSpec tool_use_id call_id arguments summary encrypted_content reasoningContent
		reasoningText redactedContent guardContent systemInstruction title context citations metadata image_url
		file_data filename file_url url fileUri bytes format cache_control cachePoint tool_choice toolConfig
		inferenceConfig generationConfig prompt query result error status thoughtSignature video audio uri
		s3Location schema refusal annotations`) {
		m[k] = true
	}
	return m
}()

// pathOf renders the JSON path of the value at the top of st. Findings carry
// it to logs, the audit log and the block message, so a key that is not a
// protocol key, or any key inside user data (a tool input's own keys), is
// shown as "*": a key can hold a secret.
func pathOf(st []jsonFrame) string {
	var b strings.Builder
	user := userDataAt(st)
	for i, f := range st {
		if f.obj {
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			if i < user && dlpPathKeys[f.key] {
				b.WriteString(f.key)
			} else {
				b.WriteByte('*')
			}
		} else {
			b.WriteString("[" + strconv.Itoa(f.idx) + "]")
		}
		if b.Len() > 200 {
			return b.String()[:200] + "..."
		}
	}
	return b.String()
}

// toolData reports whether the value at st is tool output or a document
// entering the model (not text the user typed), per wire protocol.
func toolData(proto string, st []jsonFrame) bool {
	contents := 0
	for i, f := range st {
		if !f.obj {
			continue
		}
		switch {
		case f.key == "toolResult" || f.key == "functionResponse": // Bedrock Converse, Gemini
			return true
		case f.key == "content":
			contents++
		case proto == ProtoResponses && i == 2 && f.key == "output" && st[0].key == "input": // function_call_output et al.
			return true
		}
	}
	// Anthropic: a block's own "content" is a tool_result (or document) body.
	return (proto == ProtoAnthropic || proto == ProtoBedrock) && contents >= 2
}

// ScanRequest scans a model-call body under d for a caller in ring and unit
// chain units. It returns nil when DLP is off for the caller. The scan stops at
// d.ScanLimit() bytes or dlpScanBudget, whichever first.
func ScanRequest(d *policy.DLP, proto, ring string, units []string, body []byte) *DLPReport {
	if d == nil || len(body) == 0 {
		return nil
	}
	sa, ia := d.Actions(ring, units)
	if sa == policy.DLPOff && ia == policy.DLPOff {
		return nil
	}
	began := time.Now()
	budget := newScanBudget(began.Add(dlpScanBudget)) // checked inside every regex pass, not only between strings
	rep := &DLPReport{SecretAction: sa, InjectionAction: ia}
	e := engineFor(d)
	threshold := d.Injection.ScoreThreshold()
	scan := body
	if lim := d.ScanLimit(); int64(len(scan)) > lim {
		scan, rep.Truncated, rep.OverCap = scan[:lim], true, true
	}
	var out bytes.Buffer // redacted body, built only once a secret is redacted
	copied := 0          // body[:copied] is already in out
	redact := sa == policy.DLPRedact
	err := walkStrings(scan, func(st []jsonFrame, start, end int, s string, key bool) bool {
		at := st // the value's position; a key's is its object's
		if key {
			// Object keys are scanned for secrets too (a tool input or result can
			// put one in a key) and redacted like values; never scored for
			// injection, and the location never shows the key.
			at = st[:len(st)-1]
		} else if skipValue(st) {
			return true
		}
		tool := toolData(proto, at)
		var ms []secretMatch
		if sa != policy.DLPOff || (!key && tool && ia != policy.DLPOff) { // a secret in a URL is an injection signal too
			ms = e.secrets(s, budget)
		}
		var loc string
		if len(ms) > 0 || tool {
			loc = pathOf(at)
			if key {
				loc += ".<key>"
			}
		}
		for _, m := range ms {
			if sa == policy.DLPOff {
				break
			}
			rep.Findings = append(rep.Findings, DLPFinding{Kind: DLPSecret, Detector: m.det, Hash: m.hash, Location: loc, ToolData: tool})
		}
		if !key && tool && ia != policy.DLPOff {
			if score, sig := injectionScore(s, ms, budget); score >= threshold {
				rep.Findings = append(rep.Findings, DLPFinding{Kind: DLPInjection, Detector: DLPInjection, Location: loc, Score: score, Signals: sig, ToolData: true})
			}
		}
		if redact && len(ms) > 0 {
			out.Write(body[copied:start])
			writeJSONString(&out, redactString(s, ms))
			copied = end
		}
		if budget.exhausted() || time.Since(began) > dlpScanBudget {
			rep.Truncated = true
			return false
		}
		return true
	})
	if err != nil && !errors.Is(err, errTruncatedJSON) {
		rep.Truncated = true // not JSON: nothing scanned (the upstream rejects it too)
	}
	if out.Len() > 0 || copied > 0 {
		out.Write(body[copied:])
		rep.Redacted = out.Bytes()
	}
	switch {
	case sa == policy.DLPBlock && rep.Count(DLPSecret) > 0:
		rep.Blocked = DLPSecret
	case ia == policy.DLPBlock && rep.Count(DLPInjection) > 0:
		rep.Blocked = DLPInjection
	case sa == policy.DLPBlock && rep.Truncated:
		// Block means no secret reaches the model: an unscanned tail could hold one.
		rep.Blocked = DLPTruncated
	}
	rep.Took = time.Since(began)
	return rep
}

// redactString replaces each match in s with its marker.
func redactString(s string, ms []secretMatch) string {
	var b strings.Builder
	last := 0
	for _, m := range ms {
		b.WriteString(s[last:m.start])
		b.WriteString(RedactionMarker(m.det, m.hash))
		last = m.end
	}
	b.WriteString(s[last:])
	return b.String()
}

// writeJSONString writes s as a JSON string literal without HTML escaping.
func writeJSONString(w *bytes.Buffer, s string) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)       // a string always encodes
	w.Truncate(w.Len() - 1) // Encode's trailing newline
}

var errTruncatedJSON = errors.New("dlp: body cut at the scan limit")

// walkStrings calls fn for every string in the JSON document b, object keys
// included (key true: the top of st is the object, its key not yet set), with
// the container stack and the literal's byte range [start, end) in b. fn
// returns false to stop. A document cut short (the scan limit) ends with
// errTruncatedJSON after every complete string was visited.
func walkStrings(b []byte, fn func(st []jsonFrame, start, end int, s string, key bool) bool) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var st []jsonFrame
	after := func() {
		if n := len(st); n > 0 {
			if st[n-1].obj {
				st[n-1].wantKey = true
			} else {
				st[n-1].idx++
			}
		}
	}
	for {
		before := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return errTruncatedJSON
			}
			var se *json.SyntaxError
			if errors.As(err, &se) && int(se.Offset) >= len(b) {
				return errTruncatedJSON
			}
			return fmt.Errorf("dlp: %w", err)
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				st = append(st, jsonFrame{obj: true, wantKey: true})
			case '[':
				st = append(st, jsonFrame{})
			default:
				st = st[:len(st)-1]
				after()
			}
		case string:
			end := int(dec.InputOffset())
			start := int(before) + bytes.IndexByte(b[before:end], '"')
			if n := len(st); n > 0 && st[n-1].obj && st[n-1].wantKey {
				if !fn(st, start, end, t, true) {
					return nil
				}
				st[n-1].key, st[n-1].wantKey = t, false
				continue
			}
			if !fn(st, start, end, t, false) {
				return nil
			}
			after()
		default:
			after()
		}
	}
}

// Reject is the refusal for a blocked request, in the caller's wire format:
// 400 (a permanent client error, which the CLIs show and do not retry), or
// 413 for a body over the scan cap under a block secret action.
func (r *DLPReport) Reject(proto string) *Rejection {
	if r == nil || r.Blocked == "" {
		return nil
	}
	if r.Blocked == DLPTruncated {
		if r.OverCap {
			return &Rejection{Status: http.StatusRequestEntityTooLarge, Protocol: proto,
				Message: "halos: request blocked: it is larger than gateway.dlp.maxScanBytes, so it cannot be scanned for secrets, and this ring's DLP secret action is block. Shorten the conversation (for example /compact or a new session) and retry, or ask an admin to raise maxScanBytes."}
		}
		return &Rejection{Status: http.StatusBadRequest, Protocol: proto, Code: CodeScanIncomplete,
			Message: "halos: request blocked: it could not be scanned for secrets in full (not JSON, or the scan ran past its time budget), and this ring's DLP secret action is block. Shorten the request and retry."}
	}
	var f DLPFinding
	for _, x := range r.Findings {
		if x.Kind == r.Blocked {
			f = x
			break
		}
	}
	if r.Blocked == DLPSecret {
		return &Rejection{Status: http.StatusBadRequest, Protocol: proto, Code: CodeSecretDetected,
			Message: fmt.Sprintf("halos: request blocked: it contains a secret (%s, %s at %s). Remove the secret from the conversation or file and retry; rotate it if it was real.", f.Detector, RedactionMarker(f.Detector, f.Hash), f.Location)}
	}
	return &Rejection{Status: http.StatusBadRequest, Protocol: proto, Code: CodeInjectionDetected,
		Message: fmt.Sprintf("halos: request blocked: a tool result looks like a prompt injection (score %d: %s at %s). Review that tool output, remove it from the conversation and retry.", f.Score, strings.Join(f.Signals, ", "), f.Location)}
}

// ---- response scanning (monitor only) ----

// Response scanning bounds: text is scanned in windows of dlpRespWindow with
// dlpRespOverlap carried over (so a secret split across deltas or windows is
// seen whole), up to dlpRespMax bytes per response.
const (
	dlpRespWindow  = 16 << 10
	dlpRespOverlap = 4 << 10
	dlpRespMax     = 4 << 20
)

// DLPResponseScanner looks for secrets in a response's generated text as it
// streams. It never changes the response. Not safe for concurrent use: one
// UsageTap feeds it from one goroutine, and Findings is read once the body ended.
type DLPResponseScanner struct {
	e         *dlpEngine
	buf       []byte
	scanned   int // bytes of buf already scanned (the overlap carried over)
	total     int
	seen      map[string]bool
	findings  []DLPFinding
	budget    *scanBudget // regex bytes for the whole response; no deadline (it streams)
	Truncated bool
}

// NewDLPResponseScanner returns a scanner, or nil when DLP or response
// scanning is off for the caller.
func NewDLPResponseScanner(d *policy.DLP, ring string, units []string) *DLPResponseScanner {
	if !d.Responses() {
		return nil
	}
	if sa, _ := d.Actions(ring, units); sa == policy.DLPOff {
		return nil
	}
	return &DLPResponseScanner{e: engineFor(d), seen: map[string]bool{}, budget: newScanBudget(time.Time{})}
}

// Text adds generated text.
func (s *DLPResponseScanner) Text(t string) {
	if s.total >= dlpRespMax || s.budget.exhausted() {
		s.Truncated = true
		return
	}
	s.total += len(t)
	s.buf = append(s.buf, t...)
	if len(s.buf) >= dlpRespWindow {
		s.flush()
		keep := len(s.buf) - dlpRespOverlap
		for keep < len(s.buf) && !utf8.RuneStart(s.buf[keep]) {
			keep++
		}
		s.buf = s.buf[:copy(s.buf, s.buf[keep:])]
		s.scanned = len(s.buf)
	}
}

func (s *DLPResponseScanner) flush() {
	if len(s.buf) <= s.scanned && s.scanned > 0 {
		return
	}
	for _, m := range s.e.secrets(string(s.buf), s.budget) {
		if k := m.det + m.hash; !s.seen[k] {
			s.seen[k] = true
			s.findings = append(s.findings, DLPFinding{Kind: DLPSecret, Detector: m.det, Hash: m.hash, Location: "response"})
		}
	}
	if s.budget.exhausted() {
		s.Truncated = true
	}
}

// Findings scans what is left and returns every distinct secret seen.
func (s *DLPResponseScanner) Findings() []DLPFinding {
	s.flush()
	s.buf = nil
	return s.findings
}
