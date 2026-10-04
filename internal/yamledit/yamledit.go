// Package yamledit finds a kind/name YAML document in a policy repo (any
// document of a multi-document file) and edits it by byte splice, leaving
// comments, formatting and every other document intact.
package yamledit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/policy"
)

// Doc is one YAML document of a given kind/name found in a policy repo.
// Data is the whole file; node positions (Line/Column) are file-absolute.
type Doc struct {
	Path    string // path as walked (dir joined with the file)
	Rel     string // slash-separated path relative to dir
	Data    []byte
	Mapping *yaml.Node
}

// Scalar returns the key and value nodes for key in mapping m, or nils.
func Scalar(m *yaml.Node, key string) (k, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// Get returns the node at path (mapping keys from the document root), or nil.
func (d *Doc) Get(path ...string) *yaml.Node {
	n := d.Mapping
	for _, k := range path {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		_, n = Scalar(n, k)
	}
	return n
}

// Parse returns the document declaring kind/name in data (which may hold
// several documents), or nil when none does.
func Parse(data []byte, kind policy.Kind, name string) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
		if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
			continue
		}
		m := doc.Content[0]
		_, k := Scalar(m, "kind")
		_, n := Scalar(m, "name")
		if k != nil && n != nil && k.Value == string(kind) && n.Value == name {
			return m, nil
		}
	}
}

// Find locates the document with the given kind and name under dir.
func Find(dir string, kind policy.Kind, name string) (*Doc, error) {
	var found *Doc
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != dir && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}
		if d.IsDir() || (!strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml")) {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // walks the operator-owned policy repo
		if err != nil {
			return err
		}
		m, err := Parse(data, kind, name)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		if m != nil {
			rel, _ := filepath.Rel(dir, p)
			found = &Doc{Path: p, Rel: filepath.ToSlash(rel), Data: data, Mapping: m}
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("%s %q not found under %s", kind, name, dir)
	}
	return found, nil
}

// offset converts a node's 1-based line and (character) column to a byte offset.
func (d *Doc) offset(n *yaml.Node) (int, bool) {
	o := 0
	for l := 1; l < n.Line; l++ {
		i := bytes.IndexByte(d.Data[o:], '\n')
		if i < 0 {
			return 0, false
		}
		o += i + 1
	}
	for c := 1; c < n.Column; c++ {
		if o >= len(d.Data) || d.Data[o] == '\n' {
			return 0, false
		}
		_, sz := utf8.DecodeRune(d.Data[o:])
		o += sz
	}
	return o, true
}

// scalarSpan returns the [start,end) byte span of scalar v's source text,
// verified to decode back to v.Value.
func (d *Doc) scalarSpan(v *yaml.Node) (int, int, bool) {
	b := d.Data
	start, ok := d.offset(v)
	if !ok || start >= len(b) {
		return 0, 0, false
	}
	end := -1
	switch {
	case v.Style&yaml.DoubleQuotedStyle != 0 && b[start] == '"':
		for i := start + 1; i < len(b); i++ {
			if b[i] == '\\' {
				i++
			} else if b[i] == '"' {
				end = i + 1
				break
			}
		}
	case v.Style&yaml.SingleQuotedStyle != 0 && b[start] == '\'':
		for i := start + 1; i < len(b); i++ {
			if b[i] == '\'' {
				if i+1 < len(b) && b[i+1] == '\'' {
					i++
					continue
				}
				end = i + 1
				break
			}
		}
	case v.Style == 0:
		end = start
		for end < len(b) && b[end] != '\n' && (b[end] != '#' || end <= start || (b[end-1] != ' ' && b[end-1] != '\t')) {
			end++
		}
		for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r') {
			end--
		}
		return start, end, string(b[start:end]) == v.Value
	}
	if end < 0 {
		return 0, 0, false
	}
	var s string
	if yaml.Unmarshal(b[start:end], &s) != nil || s != v.Value {
		return 0, 0, false
	}
	return start, end, true
}

// Quote renders v as an inline YAML scalar, keeping style (single/double
// quotes) when possible and quoting whenever a plain scalar would change meaning.
func Quote(v string, style yaml.Style) string {
	if style&yaml.SingleQuotedStyle != 0 && !strings.ContainsAny(v, "\n\r") {
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	}
	if style&yaml.DoubleQuotedStyle == 0 {
		if out, err := yaml.Marshal(v); err == nil && string(out) == v+"\n" && !strings.Contains(v, " #") {
			return v
		}
	}
	var b bytes.Buffer // JSON strings are valid YAML double-quoted scalars
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // a string cannot fail to encode
	return strings.TrimSuffix(b.String(), "\n")
}

// SetField sets a top-level scalar key by splicing bytes at the value's
// source span, so comments, blank lines, formatting and other documents are
// untouched. val is the raw string; it is quoted as needed (an existing
// quote style is kept).
func (d *Doc) SetField(key, val string) ([]byte, error) {
	if _, v := Scalar(d.Mapping, key); v != nil {
		if v.Kind != yaml.ScalarNode || v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
			return nil, fmt.Errorf("%s: %q is not an inline scalar", d.Path, key)
		}
		start, end, ok := d.scalarSpan(v)
		if !ok {
			return nil, fmt.Errorf("%s:%d: cannot locate value of %q for editing", d.Path, v.Line, key)
		}
		out := slices.Concat(d.Data[:start], []byte(Quote(val, v.Style)), d.Data[end:])
		return out, nil
	}
	nk, _ := Scalar(d.Mapping, "name")
	if nk == nil {
		return nil, fmt.Errorf("%s: document has no name", d.Path)
	}
	lines := strings.Split(string(d.Data), "\n")
	ins := pad(nk.Column-1) + key + ": " + Quote(val, 0)
	lines = slices.Insert(lines, nk.Line, ins) // after the name line
	return []byte(strings.Join(lines, "\n")), nil
}

// SetRaw replaces the plain inline scalar v (a node of d.Mapping, at any
// depth) with raw, spliced byte for byte like SetField, but unquoted: for
// numbers and booleans.
func (d *Doc) SetRaw(v *yaml.Node, raw string) ([]byte, error) {
	if v == nil || v.Kind != yaml.ScalarNode || v.Style != 0 {
		return nil, fmt.Errorf("%s: value is not a plain inline scalar", d.Path)
	}
	start, end, ok := d.scalarSpan(v)
	if !ok {
		return nil, fmt.Errorf("%s:%d: cannot locate the value for editing", d.Path, v.Line)
	}
	return slices.Concat(d.Data[:start], []byte(raw), d.Data[end:]), nil
}

// SetPath sets the inline scalar at path to raw, spliced in verbatim like
// SetRaw (raw must already be valid YAML: quote strings with Quote). Path
// elements are mapping keys, or "name=<v>" to pick the sequence item whose
// name is v. Only a missing top-level key is inserted (after name); deeper
// keys must exist.
func (d *Doc) SetPath(path []string, raw string) ([]byte, error) {
	var n yaml.Node
	if len(path) == 0 || strings.ContainsAny(raw, "\n\r") || yaml.Unmarshal([]byte(raw), &n) != nil || len(n.Content) != 1 || n.Content[0].Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("yamledit: %q is not an inline scalar for %v", raw, path)
	}
	v := d.Mapping
	for _, k := range path {
		switch {
		case v == nil:
		case v.Kind == yaml.SequenceNode && strings.HasPrefix(k, "name="):
			i := slices.IndexFunc(v.Content, func(it *yaml.Node) bool {
				_, nv := Scalar(it, "name")
				return it.Kind == yaml.MappingNode && nv != nil && nv.Value == k[len("name="):]
			})
			if i < 0 {
				v = nil
			} else {
				v = v.Content[i]
			}
		case v.Kind == yaml.MappingNode:
			_, v = Scalar(v, k)
		default:
			v = nil
		}
	}
	if v == nil {
		if len(path) != 1 {
			return nil, fmt.Errorf("%s: %s not found", d.Path, strings.Join(path, "."))
		}
		nk, _ := Scalar(d.Mapping, "name")
		if nk == nil {
			return nil, fmt.Errorf("%s: document has no name", d.Path)
		}
		lines := strings.Split(string(d.Data), "\n")
		lines = slices.Insert(lines, nk.Line, pad(nk.Column-1)+path[0]+": "+raw)
		return []byte(strings.Join(lines, "\n")), nil
	}
	if v.Kind != yaml.ScalarNode || v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return nil, fmt.Errorf("%s: %s is not an inline scalar", d.Path, strings.Join(path, "."))
	}
	start, end, ok := d.scalarSpan(v)
	if !ok && v.Style == 0 {
		// A plain scalar inside a flow collection ({a: 1, b: 2}) ends at a
		// flow indicator, which scalarSpan (block context) does not stop at.
		if s, sok := d.offset(v); sok {
			e := s + len(v.Value)
			ok = e <= len(d.Data) && string(d.Data[s:e]) == v.Value && (e == len(d.Data) || strings.IndexByte(",}] \t\r\n", d.Data[e]) >= 0)
			start, end = s, e
		}
	}
	if !ok {
		return nil, fmt.Errorf("%s:%d: cannot locate value of %s for editing", d.Path, v.Line, strings.Join(path, "."))
	}
	return slices.Concat(d.Data[:start], []byte(raw), d.Data[end:]), nil
}

// AppendSeq appends item to the sequence at path (mapping keys from the
// document root), creating missing keys, by splicing lines: everything
// outside the edited sequence keeps its bytes. A block sequence gets a new
// "- item" after its last item; a flow sequence ([a, b]) is rewritten as a
// block sequence.
func (d *Doc) AppendSeq(path []string, item any) ([]byte, error) {
	if len(path) == 0 {
		return nil, errors.New("yamledit: empty path")
	}
	lines := strings.Split(string(d.Data), "\n")
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%s: append to %s: %s", d.Path, strings.Join(path, "."), fmt.Sprintf(format, a...))
	}
	insert := func(at int, ins []string, err error) ([]byte, error) {
		if err != nil {
			return nil, fail("render: %v", err)
		}
		return []byte(strings.Join(slices.Insert(lines, at, ins...), "\n")), nil
	}
	m := d.Mapping
	for i, k := range path {
		kn, v := Scalar(m, k)
		if kn == nil { // add the rest of the path after the mapping's last entry
			if m.Style&yaml.FlowStyle != 0 || len(m.Content) == 0 {
				return nil, fail("cannot add %q to a flow or empty mapping", k)
			}
			kc := m.Content[0].Column - 1
			end := extent(lines, m.Content[len(m.Content)-2].Line-1, kc, true)
			ins, err := nested(path[i:], kc, item)
			return insert(end+1, ins, err)
		}
		if v.Kind == yaml.ScalarNode && v.Tag == "!!null" { // "key:" with no value
			if !clearNull(lines, kn) {
				return nil, fail("cannot edit empty value of %q", k)
			}
			ins, err := nested(path[i+1:], kn.Column-1+2, item)
			return insert(kn.Line, ins, err)
		}
		if i < len(path)-1 {
			if v.Kind != yaml.MappingNode {
				return nil, fail("%q is not a mapping", k)
			}
			m = v
			continue
		}
		if v.Kind != yaml.SequenceNode {
			return nil, fail("%q is not a list", k)
		}
		if v.Style&yaml.FlowStyle != 0 {
			return d.flowToBlock(kn, v, item)
		}
		dash := v.Column - 1
		if l := lines[v.Line-1]; dash >= len(l) || l[dash] != '-' {
			return nil, fail("cannot locate list")
		}
		end := extent(lines, v.Content[len(v.Content)-1].Line-1, dash, false)
		ins, err := itemLines(dash, item)
		return insert(end+1, ins, err)
	}
	return nil, fail("unreachable")
}

// flowToBlock replaces the flow sequence v (value of key kn) with a block
// sequence holding its items plus item.
func (d *Doc) flowToBlock(kn, v *yaml.Node, item any) ([]byte, error) {
	start, ok := d.offset(v)
	b := d.Data
	if !ok || start >= len(b) || b[start] != '[' {
		return nil, fmt.Errorf("%s:%d: cannot locate flow list %q", d.Path, v.Line, kn.Value)
	}
	end, depth, q := -1, 0, byte(0)
	for i := start; i < len(b) && end < 0; i++ {
		switch c := b[i]; {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[':
			depth++
		case c == ']':
			if depth--; depth == 0 {
				end = i + 1
			}
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("%s:%d: unterminated flow list %q", d.Path, v.Line, kn.Value)
	}
	var ins []string
	for _, it := range append(slices.Clone(v.Content), nil) {
		var x any = it
		if it == nil {
			x = item
		}
		l, err := itemLines(kn.Column-1+2, x)
		if err != nil {
			return nil, fmt.Errorf("%s: render %q: %w", d.Path, kn.Value, err)
		}
		ins = append(ins, l...)
	}
	head := bytes.TrimRight(b[:start], " \t")
	return slices.Concat(head, []byte("\n"+strings.Join(ins, "\n")), b[end:]), nil
}

// clearNull removes an explicit null token (~, null) after "key:" on kn's
// line, keeping any trailing comment.
func clearNull(lines []string, kn *yaml.Node) bool {
	l := lines[kn.Line-1]
	c := strings.Index(l[min(kn.Column-1, len(l)):], ":")
	if c < 0 {
		return false
	}
	c += kn.Column - 1
	rest, comment := l[c+1:], ""
	if h := strings.Index(rest, "#"); h >= 0 {
		rest, comment = rest[:h], " "+rest[h:]
	}
	switch strings.TrimSpace(rest) {
	case "", "~", "null", "Null", "NULL":
		lines[kn.Line-1] = l[:c+1] + comment
		return true
	}
	return false
}

// extent returns the last line index belonging to the node starting on line
// start: following lines indented deeper than col (blank lines tentatively).
// For a mapping entry, a block sequence may also sit at col itself.
func extent(lines []string, start, col int, mapping bool) int {
	end := start
	for j := start + 1; j < len(lines); j++ {
		t := strings.TrimLeft(lines[j], " ")
		if strings.TrimSpace(t) == "" {
			continue
		}
		ind := len(lines[j]) - len(t)
		if ind > col || mapping && ind == col && (t == "-" || strings.HasPrefix(t, "- ")) {
			end = j
			continue
		}
		break
	}
	return end
}

// nested renders "k1:\n  k2:\n    - item" at indent.
func nested(path []string, indent int, item any) ([]string, error) {
	var out []string
	for _, k := range path {
		out = append(out, pad(indent)+k+":")
		indent += 2
	}
	it, err := itemLines(indent, item)
	return append(out, it...), err
}

// itemLines renders item as a block sequence entry with its dash at indent.
func itemLines(indent int, item any) ([]string, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(item); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	src := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	out := make([]string, len(src))
	for i, l := range src {
		switch {
		case i == 0:
			out[i] = pad(indent) + "- " + l
		case l != "":
			out[i] = pad(indent+2) + l
		}
	}
	return out, nil
}

func pad(n int) string { return strings.Repeat(" ", max(n, 0)) }

// Save writes data over the document's file atomically, keeping its permissions.
func (d *Doc) Save(data []byte) error {
	return fsutil.WriteAtomic(d.Path, data, fsutil.ExistingPerm(d.Path, 0o644))
}
