package supplychain

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Rule is one static check. The ruleset is deliberately small and
// conservative: each rule matches something an extension has no ordinary
// reason to contain, so a finding is worth a human look (ADR-0028).
type Rule struct {
	ID      string
	Summary string
}

// Rules is the documented ruleset, in report order.
var Rules = []Rule{
	{"hidden-unicode", "zero-width, bidirectional-override or Unicode tag characters, which hide text from a reviewer but not from a model"},
	{"html-comment-instruction", "an HTML comment (invisible when Markdown renders) that carries an instruction: ignore previous instructions, do not tell the user, run curl/bash, ..."},
	{"permission-bypass", "a permission-bypass mode or flag (bypassPermissions, danger-full-access, --dangerously-skip-permissions, --yolo, ...): AGENTS.md invariant 1"},
	{"remote-exec", "fetch-and-execute: curl/wget piped to a shell or interpreter, sh -c \"$(curl ...)\", bash <(curl ...), iex (irm ...)"},
	{"credential-path", "a credential location: ~/.ssh, ~/.aws, gcloud credentials, .netrc, .git-credentials, docker or kube config, or reading a .env file"},
	{"exfil-url", "a URL on a request-capture, tunnel or paste service (webhook.site, ngrok, interact.sh, pastebin, Discord webhooks, ...) or a public raw-IP URL"},
	{"base64-blob", "a base64 run of 1024 characters or more (inline data: images excepted)"},
	{"executable-binary", "a native executable or Java class file (ELF, Mach-O, PE, CAFEBABE)"},
}

// Finding is one rule match. Line is 1-based (0 = whole file).
type Finding struct {
	Rule   string `json:"rule"`
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail"`
}

func (f Finding) String() string {
	loc := f.Path
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return fmt.Sprintf("%s: %s: %s", f.Rule, loc, f.Detail)
}

// minBase64 is the base64-blob threshold in characters (~768 decoded bytes).
const minBase64 = 1024

var (
	bypassRe = regexp.MustCompile(`(?i)\b(bypassPermissions|danger-full-access|dangerously-skip-permissions|dangerously-bypass-approvals-and-sandbox)\b|(^|[\s"'=])--yolo\b`)
	execRes  = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(-?\s*)?((ba|z|k|da|fi)?sh|python[0-9.]*|node|perl|ruby)\b`),
		regexp.MustCompile(`(?i)\b(ba|z)?sh\s+(-c\s+)?["']?\$\(\s*(curl|wget)\b`),
		regexp.MustCompile(`(?i)\b(ba|z)?sh\s+<\(\s*(curl|wget)\b`),
		regexp.MustCompile(`(?i)\b(iex|invoke-expression)\b[^\n]*\b(irm|iwr|invoke-restmethod|invoke-webrequest|downloadstring)\b`),
		regexp.MustCompile(`(?i)\b(irm|iwr|invoke-restmethod|invoke-webrequest)\b[^\n|]*\|\s*(iex|invoke-expression)\b`),
	}
	credRe = regexp.MustCompile(`(?i)(~|\$home|\$\{home\}|%userprofile%)[/\\]\.(ssh|aws|netrc|kube[/\\]config|docker[/\\]config\.json|git-credentials|config[/\\]gcloud)\b|` +
		`\.ssh[/\\](id_[a-z0-9]+|authorized_keys)\b|\.aws[/\\]credentials\b|application_default_credentials\.json|\.git-credentials\b|` +
		`\b(cat|less|more|head|tail|source|grep|base64|cp|scp|type|get-content|readfile)\s+["']?[^\s|;"']*\.env(\s|$|["'` + "`" + `;|)])`)
	exfilRe = regexp.MustCompile(`(?i)https?://(?:[a-z0-9-]+\.)*(?:webhook\.site|requestbin\.(?:net|com)|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|` +
		`burpcollaborator\.net|oastify\.com|interact\.sh|oast\.(?:fun|live|me|online|pro|site)|pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|` +
		`hookbin\.com|beeceptor\.com|requestcatcher\.com|canarytokens\.com)\b|https?://(?:discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot)`)
	rawIPRe   = regexp.MustCompile(`(?i)https?://(\d{1,3}(?:\.\d{1,3}){3})\b`)
	commentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	cueRes    = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|other|system)\b[^.\n]{0,20}\b(instructions?|rules?|prompts?|guidelines?|directives?)\b`),
		regexp.MustCompile(`(?i)\b(do not|don't|never)\s+(tell|inform|mention|reveal|show|disclose)\b[^.\n]{0,20}\b(user|human|operator|reviewer)\b`),
		regexp.MustCompile(`(?i)\byou are now\b|\bsystem prompt\b|\b(new|updated|secret|hidden|real) instructions?\b`),
		regexp.MustCompile(`(?i)\b(run|execute|exec|call|invoke)\b[^.\n]{0,40}\b(curl|wget|bash|powershell|iex|eval)\b`),
	}
)

// Scan runs every rule over every file of t. Findings are sorted by path,
// line and rule.
func Scan(t Tree) []Finding {
	var out []Finding
	for p, b := range t {
		out = append(out, scanFile(p, b)...)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return out
}

func scanFile(p string, b []byte) []Finding {
	if kind := executable(b); kind != "" {
		return []Finding{{Rule: "executable-binary", Path: p, Detail: kind + " executable"}}
	}
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return nil // other binary content (images, archives) is not text a model reads
	}
	var out []Finding
	add := func(rule string, line int, detail string) {
		out = append(out, Finding{Rule: rule, Path: p, Line: line, Detail: detail})
	}
	text := string(b)
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		if d := hiddenRunes(line, n == 1); d != "" {
			add("hidden-unicode", n, d)
		}
		if m := bypassRe.FindString(line); m != "" {
			add("permission-bypass", n, fmt.Sprintf("%q", strings.TrimSpace(m)))
		}
		for _, re := range execRes {
			if m := re.FindString(line); m != "" {
				add("remote-exec", n, fmt.Sprintf("%q", clip(m)))
				break
			}
		}
		if m := credRe.FindString(line); m != "" {
			add("credential-path", n, fmt.Sprintf("%q", clip(strings.TrimSpace(m))))
		}
		if m := exfilRe.FindString(line); m != "" {
			add("exfil-url", n, fmt.Sprintf("%q", m))
		} else if m := rawIPRe.FindStringSubmatch(line); m != nil && publicIP(m[1]) {
			add("exfil-url", n, fmt.Sprintf("%q is a raw public IP address", m[0]))
		}
		if l := longBase64(line); l > 0 {
			add("base64-blob", n, fmt.Sprintf("%d-character base64 run", l))
		}
	}
	for _, m := range commentRe.FindAllStringSubmatchIndex(text, -1) {
		body := text[m[2]:m[3]]
		for _, re := range cueRes {
			if c := re.FindString(body); c != "" {
				add("html-comment-instruction", strings.Count(text[:m[0]], "\n")+1, fmt.Sprintf("hidden comment says %q", clip(c)))
				break
			}
		}
	}
	return out
}

// hiddenRunes describes the invisible control characters in line, if any. A
// byte-order mark is allowed at the very start of the file.
func hiddenRunes(line string, first bool) string {
	var found []string
	for i, r := range line {
		switch {
		case r == 0xFEFF && first && i == 0:
		case r >= 0x200B && r <= 0x200D, r == 0x2060, r >= 0x2061 && r <= 0x2064, r == 0xFEFF, r == 0x180E:
			found = append(found, fmt.Sprintf("U+%04X zero-width", r))
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			found = append(found, fmt.Sprintf("U+%04X bidi control", r))
		case r >= 0xE0000 && r <= 0xE007F:
			found = append(found, fmt.Sprintf("U+%05X tag character", r))
		case r >= 0xE0100 && r <= 0xE01EF:
			found = append(found, fmt.Sprintf("U+%05X variation selector", r))
		}
	}
	if len(found) == 0 {
		return ""
	}
	if len(found) > 3 {
		return fmt.Sprintf("%s and %d more", strings.Join(found[:3], ", "), len(found)-3)
	}
	return strings.Join(found, ", ")
}

// longBase64 returns the length of the longest base64 run in line of at
// least minBase64 characters, skipping data:image/...;base64, payloads.
func longBase64(line string) int {
	best, start := 0, -1
	flush := func(end int) {
		if start >= 0 && end-start >= minBase64 && end-start > best {
			if !strings.HasSuffix(strings.ToLower(line[max(0, start-40):start]), ";base64,") || !strings.Contains(strings.ToLower(line[max(0, start-40):start]), "data:image/") {
				best = end - start
			}
		}
		start = -1
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_' || c == '=' {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(line))
	return best
}

func publicIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast()
}

func executable(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		return "ELF"
	case bytes.HasPrefix(b, []byte{0xfe, 0xed, 0xfa, 0xce}), bytes.HasPrefix(b, []byte{0xfe, 0xed, 0xfa, 0xcf}),
		bytes.HasPrefix(b, []byte{0xce, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(b, []byte{0xcf, 0xfa, 0xed, 0xfe}):
		return "Mach-O"
	case bytes.HasPrefix(b, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "Mach-O universal or Java class"
	case len(b) > 0x40 && bytes.HasPrefix(b, []byte("MZ")):
		off := int(b[0x3c]) | int(b[0x3d])<<8 | int(b[0x3e])<<16 | int(b[0x3f])<<24
		if off > 0 && off+4 <= len(b) && bytes.Equal(b[off:off+4], []byte("PE\x00\x00")) {
			return "PE"
		}
	}
	return ""
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
