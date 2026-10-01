package docgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type node = map[string]any

type row struct{ path, typ, def, enum, req, cons, desc string }

type walker struct {
	defs  node
	rows  []row
	notes []string
}

func str(n node, k string) string {
	if v, ok := n[k]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func (w *walker) resolve(n node, seen map[string]bool) (node, map[string]bool) {
	ref, _ := n["$ref"].(string)
	name := strings.TrimPrefix(ref, "#/$defs/")
	if ref == "" || seen[name] {
		return n, seen
	}
	d, _ := w.defs[name].(node)
	next := map[string]bool{name: true}
	for k := range seen {
		next[k] = true
	}
	return d, next
}

func typeOf(n node) string {
	t := ""
	switch v := n["type"].(type) {
	case string:
		t = v
	case []any:
		var p []string
		for _, x := range v {
			p = append(p, fmt.Sprint(x))
		}
		t = strings.Join(p, " or ")
	}
	if it, ok := n["items"].(node); ok && t == "array" {
		if it["$ref"] != nil {
			t += " of object"
		} else if s := typeOf(it); s != "" {
			t += " of " + s
		}
	}
	return t
}

func (w *walker) walk(path string, n node, required bool, seen map[string]bool) {
	n, seen = w.resolve(n, seen)
	if path != "" {
		r := row{path: path, typ: typeOf(n), desc: str(n, "description")}
		if required {
			r.req = "yes"
		}
		if d, ok := n["default"]; ok {
			r.def = fmt.Sprint(d)
		}
		if e, ok := n["enum"].([]any); ok {
			var p []string
			for _, x := range e {
				p = append(p, fmt.Sprint(x))
			}
			r.enum = strings.Join(p, ", ")
		} else if c, ok := n["const"]; ok {
			r.enum = fmt.Sprint("const ", c)
		}
		var cs []string
		for _, k := range []string{"format", "pattern", "minimum", "maximum", "minLength", "maxLength", "minItems"} {
			if v, ok := n[k]; ok {
				cs = append(cs, fmt.Sprintf("%s %v", k, v))
			}
		}
		r.cons = strings.Join(cs, "; ")
		w.rows = append(w.rows, r)
	}
	reqd := map[string]bool{}
	if rs, ok := n["required"].([]any); ok {
		for _, x := range rs {
			reqd[fmt.Sprint(x)] = true
		}
	}
	if props, ok := n["properties"].(node); ok {
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c, _ := props[k].(node)
			p := k
			if path != "" {
				p = path + "." + k
			}
			w.walk(p, c, reqd[k], seen)
		}
	}
	if ap, ok := n["additionalProperties"].(node); ok {
		w.walk(path+".*", ap, false, seen)
	}
	if it, ok := n["items"].(node); ok {
		w.walk(path+"[]", it, false, seen)
	}
	if one, ok := n["oneOf"].([]any); ok {
		var alts []string
		for _, o := range one {
			if rs, ok := o.(node)["required"].([]any); ok {
				var p []string
				for _, x := range rs {
					p = append(p, fmt.Sprint(x))
				}
				alts = append(alts, "`"+strings.Join(p, " + ")+"`")
			}
		}
		if len(alts) > 0 {
			where := "top level"
			if path != "" {
				where = "`" + path + "`"
			}
			w.notes = append(w.notes, fmt.Sprintf("%s: exactly one of %s", where, strings.Join(alts, " or ")))
		}
	}
}

func schemaPage(kind string, s node) string {
	w := &walker{}
	w.defs, _ = s["$defs"].(node)
	w.walk("", s, false, nil)
	title := str(s, "title")
	if title == "" {
		title = kind
	}
	var b strings.Builder
	b.WriteString(frontmatter(title, str(s, "description")))
	b.WriteString(escText(str(s, "description")) + "\n\n")
	fmt.Fprintf(&b, "Generated from `schemas/%s.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.\n\n", kind)
	b.WriteString("| Field | Type | Required | Default | Allowed values | Constraints | Description |\n|---|---|---|---|---|---|---|\n")
	for _, r := range w.rows {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s |\n", r.path, esc(r.typ), r.req, esc(r.def), esc(r.enum), esc(r.cons), esc(r.desc))
	}
	if len(w.notes) > 0 {
		b.WriteString("\n## Constraints\n\n")
		for _, n := range w.notes {
			b.WriteString("- " + n + "\n")
		}
	}
	return b.String()
}

// Policy renders one page per schemas/*.schema.json into dir plus index.md and
// returns the number of pages written.
func Policy(schemaDir, dir string) (int, error) {
	files, err := filepath.Glob(filepath.Join(schemaDir, "*.schema.json"))
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, fmt.Errorf("no *.schema.json in %s", schemaDir)
	}
	sort.Strings(files)
	if err := resetDir(dir); err != nil {
		return 0, err
	}
	var idx strings.Builder
	idx.WriteString(frontmatter("Policy reference", "Every policy file kind and field, generated from the JSON Schemas."))
	idx.WriteString("Generated from `schemas/*.schema.json`; do not edit. Regenerate with `make docs-gen`.\n\n| Kind | Description |\n|---|---|\n")
	for _, f := range files {
		kind := strings.TrimSuffix(filepath.Base(f), ".schema.json")
		raw, err := os.ReadFile(f)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", f, err)
		}
		var s node
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, fmt.Errorf("parse %s: %w", f, err)
		}
		p := filepath.Join(dir, kind+".md")
		if err := os.WriteFile(p, []byte(schemaPage(kind, s)), 0o644); err != nil {
			return 0, fmt.Errorf("write %s: %w", p, err)
		}
		fmt.Fprintf(&idx, "| [`%s`](/halos/reference/policy/%s/) | %s |\n", kind, kind, esc(str(s, "description")))
	}
	if err := os.WriteFile(filepath.Join(dir, "index.md"), []byte(idx.String()), 0o644); err != nil {
		return 0, err
	}
	return len(files) + 1, nil
}
