package a2a

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonicalize returns the RFC 8785 JSON Canonicalization Scheme form of the
// single JSON value in b: object members sorted by UTF-16 code units, no
// insignificant whitespace, ECMAScript number and string serialization.
func Canonicalize(b []byte) ([]byte, error) {
	v, err := decodeJSON(b)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeJCS(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeJSON decodes exactly one JSON value, keeping numbers exact and
// refusing duplicate object keys (RFC 8785 requires I-JSON, RFC 7493).
func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("a2a: trailing data after the JSON value")
	}
	return v, nil
}

const maxDepth = 64

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("a2a: JSON nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("a2a: invalid JSON: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch d {
	case '{':
		m := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("a2a: invalid JSON: %w", err)
			}
			k, _ := kt.(string)
			if _, dup := m[k]; dup {
				return nil, fmt.Errorf("a2a: duplicate key %q", k)
			}
			if m[k], err = decodeValue(dec, depth+1); err != nil {
				return nil, err
			}
		}
		_, err = dec.Token()
		return m, err
	case '[':
		a := []any{}
		for dec.More() {
			v, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		_, err = dec.Token()
		return a, err
	}
	return nil, fmt.Errorf("a2a: unexpected %v", d)
}

func writeJCS(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case string:
		writeString(buf, v)
	case json.Number:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return fmt.Errorf("a2a: number %s is not an IEEE 754 double", v)
		}
		buf.WriteString(formatNumber(f))
	case []any:
		buf.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCS(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeJCS(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("a2a: unexpected JSON value %T", v)
	}
	return nil
}

func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString is ECMAScript JSON.stringify for a string.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// formatNumber is ECMAScript Number.prototype.toString for a finite double.
func formatNumber(f float64) string {
	if f == 0 {
		return "0" // also -0
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// Shortest round-tripping digits and decimal exponent: d.ddde±x.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	k, n := len(digits), x+1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		ev := strconv.Itoa(int(math.Abs(float64(n - 1))))
		if k == 1 {
			out = digits + "e" + es + ev
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + es + ev
		}
	}
	return sign + out
}
