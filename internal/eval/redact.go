package eval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// Redaction of harvested shadow steps (ADR-0020). A shadow pair holds the
// developer's prompt, code and terminal output; nothing from it is written to
// a case file before this pass, and there is no switch to turn it off.

// RedactionRulesVersion names the built-in rule set recorded in every case's
// provenance. Bump it whenever a built-in rule changes.
const RedactionRulesVersion = "1"

// DefaultKeepFields are the top-level request fields a harvested case keeps:
// what the model needs to answer the step on each wire protocol. Everything
// else is dropped, because the rest (Claude Code's metadata.user_id, Codex's
// prompt_cache_key, user, safety_identifier, previous_response_id...) carries
// account and session identifiers, not the conversation.
var DefaultKeepFields = []string{
	// Anthropic Messages, Bedrock invoke
	"model", "system", "messages", "tools", "tool_choice", "max_tokens", "temperature", "top_p", "top_k", "stop_sequences", "thinking", "anthropic_version",
	// OpenAI Responses
	"instructions", "input", "max_output_tokens", "parallel_tool_calls", "reasoning", "text", "include",
	// Gemini
	"contents", "systemInstruction", "generationConfig", "toolConfig",
	// Bedrock Converse
	"inferenceConfig",
}

// opaqueKeys hold provider ids, signatures and encrypted reasoning that must
// replay byte for byte (a tool_use id pairs with its tool_result; a thinking
// signature is verified). The high-entropy heuristic skips them; every other
// rule, credential shapes included, still applies.
var opaqueKeys = map[string]bool{"id": true, "tool_use_id": true, "call_id": true, "type": true, "role": true, "name": true,
	"signature": true, "thoughtSignature": true, "encrypted_content": true}

var (
	pemBlockRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	jwtRe      = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	authRe     = regexp.MustCompile(`(?i)\b(bearer|basic|token)(\s+)[A-Za-z0-9._~+/=-]{12,}`)
	// assignRe: NAME=value / "name": "value" where the name says credential
	// (env dumps, config files, curl -H lines in terminal output).
	assignRe    = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:passw(?:or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_]*)("?\s*[:=]\s*"?)[^\s"',;]{6,}`)
	secretKeyRe = regexp.MustCompile(`(?i)(passw(?:or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization)`)
	emailRe     = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	tokenRe     = regexp.MustCompile(`[A-Za-z0-9+/=_-]{10,}`)
)

// Redactor rewrites a shadow step so it can be written to disk.
type Redactor struct {
	patterns []*regexp.Regexp
	keep     map[string]bool
	version  string
}

// NewRedactor builds the redactor: the built-in rules plus operator regexes
// (RE2; every match becomes [REDACTED:custom]) and extra top-level request
// fields to keep on top of DefaultKeepFields.
func NewRedactor(patterns, keepFields []string) (*Redactor, error) {
	r := &Redactor{keep: map[string]bool{}, version: RedactionRulesVersion}
	for _, p := range patterns {
		if p == "" {
			return nil, errors.New("redact: empty pattern")
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("redact: pattern %q: %w", p, err)
		}
		r.patterns = append(r.patterns, re)
	}
	for _, f := range DefaultKeepFields {
		r.keep[f] = true
	}
	var extra []string
	for _, f := range keepFields {
		if f = strings.TrimSpace(f); f != "" && !r.keep[f] {
			r.keep[f] = true
			extra = append(extra, f)
		}
	}
	if len(patterns) > 0 || len(extra) > 0 {
		slices.Sort(extra)
		h := sha256.Sum256([]byte(strings.Join(patterns, "\x00") + "\x01" + strings.Join(extra, "\x00")))
		r.version += "+" + hex.EncodeToString(h[:4])
	}
	return r, nil
}

// Version is the rule-set id recorded in provenance: the built-in version,
// plus a hash of the operator's patterns and extra fields when there are any.
func (r *Redactor) Version() string { return r.version }

// Text redacts one string. heuristic enables the high-entropy rule (off for
// opaque provider fields).
func (r *Redactor) Text(s string, heuristic bool) string {
	s = pemBlockRe.ReplaceAllString(s, "[REDACTED:private-key]")
	s = jwtRe.ReplaceAllString(s, "[REDACTED:jwt]")
	s = authRe.ReplaceAllString(s, "${1}${2}[REDACTED:credential]")
	s = assignRe.ReplaceAllString(s, "${1}${2}[REDACTED:credential]")
	s = tokenRe.ReplaceAllStringFunc(s, func(t string) string {
		switch {
		case policy.HasTokenShape(t):
			return "[REDACTED:credential]"
		case heuristic && policy.LooksSecret(t):
			return "[REDACTED:secret]"
		}
		return t
	})
	s = emailRe.ReplaceAllString(s, "[REDACTED:email]")
	for _, re := range r.patterns {
		s = re.ReplaceAllString(s, "[REDACTED:custom]")
	}
	return s
}

// walk redacts every string (keys included) in a decoded JSON value. A
// non-empty string under a credential-named key is replaced whole.
func (r *Redactor) walk(v any, key string) any {
	switch t := v.(type) {
	case string:
		if t != "" && !opaqueKeys[key] && secretKeyRe.MatchString(key) {
			return "[REDACTED:credential]"
		}
		return r.Text(t, !opaqueKeys[key])
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[r.Text(k, false)] = r.walk(x, k)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = r.walk(x, key)
		}
		return out
	}
	return v // numbers (json.Number), bools, null
}

func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exactly as sent
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

// Request keeps only the allowlisted top-level fields of a model request and
// redacts every string in them. Any failure is an error, never a pass-through.
func (r *Redactor) Request(body []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("redact: request is not a JSON object: %w", err)
	}
	out := map[string]any{}
	for k, raw := range top {
		if !r.keep[k] {
			continue
		}
		v, err := decodeJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("redact: request field %q: %w", k, err)
		}
		out[k] = r.walk(v, k)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("redact: encode request: %w", err)
	}
	if err := checkRedacted(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Action redacts the arguments of every call. JSON arguments are walked and
// re-encoded in canonical form (sorted keys, as argCanon produces); freeform
// input (custom tools) is redacted as text.
func (r *Redactor) Action(a Action) (Action, error) {
	out := Action{}
	for _, c := range a.Calls {
		in := c.Input
		if json.Valid([]byte(in)) {
			v, err := decodeJSON([]byte(in))
			if err != nil {
				return Action{}, fmt.Errorf("redact: %s arguments: %w", c.Name, err)
			}
			b, err := json.Marshal(r.walk(v, ""))
			if err != nil {
				return Action{}, fmt.Errorf("redact: %s arguments: %w", c.Name, err)
			}
			in = canon(b) // the form argCanon gives a replayed answer
		} else {
			in = r.Text(in, true)
		}
		out.Calls = append(out.Calls, Call{Name: r.Text(c.Name, false), Input: in})
	}
	return out, nil
}

// checkRedacted fails closed when a credential shape survived redaction
// (defence in depth: run on every byte that is about to be written).
func checkRedacted(b []byte) error {
	s := string(b)
	switch {
	case pemBlockRe.MatchString(s):
		return errors.New("redact: a private key survived redaction; nothing was written")
	case jwtRe.MatchString(s):
		return errors.New("redact: a JWT survived redaction; nothing was written")
	case policy.HasTokenShape(s):
		return errors.New("redact: a credential-shaped token survived redaction; nothing was written")
	}
	return nil
}
