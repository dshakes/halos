package server

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
)

// schemaGen derives JSON Schema (the OpenAPI 3.1 dialect) from the Go types the
// handlers encode and decode, so a field added to a response struct shows up in
// the spec the next time it is generated, and a test fails until it does.
//
// Rules, chosen to match encoding/json:
//   - a field is required unless it has omitempty or omitzero;
//   - a pointer field without omitempty is nullable, a slice or map is not (the
//     handlers initialise them; the live conformance test catches a nil one);
//   - embedded structs without a json name are flattened;
//   - a named struct becomes a component, named after its Go type (pkg.Type for
//     types outside this package).
//
// Types with their own MarshalJSON/MarshalText need an entry in schemaOverrides;
// generation fails loudly rather than guessing.
type schemaGen struct {
	comps map[string]any
	names map[reflect.Type]string
	owner map[string]reflect.Type
	errs  []error
}

func newSchemaGen() *schemaGen {
	return &schemaGen{comps: map[string]any{}, names: map[reflect.Type]string{}, owner: map[string]reflect.Type{}}
}

var (
	timeType     = reflect.TypeOf(time.Time{})
	durationType = reflect.TypeOf(time.Duration(0))
	rawType      = reflect.TypeOf(json.RawMessage(nil))
	marshalerT   = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalT = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

// schemaOverrides are types whose JSON form is not what their Go shape says.
var schemaOverrides = map[reflect.Type]map[string]any{
	timeType:                          {"type": "string", "format": "date-time"},
	durationType:                      {"type": "integer", "format": "int64", "description": "Nanoseconds."},
	rawType:                           {},
	reflect.TypeOf(scimResourceDoc{}): {"$ref": "#/components/schemas/ScimResource"},
	reflect.TypeOf(scimListDoc{}):     {"$ref": "#/components/schemas/ScimList"},
}

func (g *schemaGen) fail(format string, a ...any) { g.errs = append(g.errs, fmt.Errorf(format, a...)) }

// schema returns the schema for t: a $ref for a named struct, inline otherwise.
func (g *schemaGen) schema(t reflect.Type) map[string]any {
	if o, ok := schemaOverrides[t]; ok {
		return cloneMap(o)
	}
	if t.Kind() == reflect.Pointer {
		return g.schema(t.Elem())
	}
	if (t.Implements(marshalerT) || reflect.PointerTo(t).Implements(marshalerT) ||
		t.Implements(textMarshalT) || reflect.PointerTo(t).Implements(textMarshalT)) && t.Kind() != reflect.Interface {
		g.fail("%s has a custom JSON encoding: add it to schemaOverrides", t)
		return map[string]any{}
	}
	switch t.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return map[string]any{"type": "integer"}
	case reflect.Int64, reflect.Uint64:
		return map[string]any{"type": "integer", "format": "int64"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Interface:
		return map[string]any{}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 && t.Kind() == reflect.Slice {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": g.schema(t.Elem())}
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			g.fail("%s: map keys must be strings", t)
		}
		return map[string]any{"type": "object", "additionalProperties": g.schema(t.Elem())}
	case reflect.Struct:
		if t.Name() == "" {
			return g.structSchema(t)
		}
		return map[string]any{"$ref": "#/components/schemas/" + g.component(t)}
	}
	g.fail("%s: no JSON Schema mapping", t)
	return map[string]any{}
}

// component registers named struct t and returns its component name.
func (g *schemaGen) component(t reflect.Type) string {
	if n, ok := g.names[t]; ok {
		return n
	}
	n := t.Name()
	if !strings.HasSuffix(t.PkgPath(), "/internal/server") {
		n = t.PkgPath()[strings.LastIndex(t.PkgPath(), "/")+1:] + "." + n
	}
	if o, taken := g.owner[n]; taken && o != t {
		g.fail("component name %s is used by %s and %s", n, o, t)
	}
	g.names[t], g.owner[n] = n, t
	g.comps[n] = map[string]any{} // reserve before recursing: types may refer to themselves
	g.comps[n] = g.structSchema(t)
	return n
}

func (g *schemaGen) structSchema(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	g.fields(t, props, &required)
	out := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		slices.Sort(required)
		out["required"] = slices.Compact(required)
	}
	return out
}

func (g *schemaGen) fields(t reflect.Type, props map[string]any, required *[]string) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag, hasTag := f.Tag.Lookup("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				g.fields(ft, props, required)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		_ = hasTag
		optional := strings.Contains(opts, "omitempty") || strings.Contains(opts, "omitzero")
		s := g.schema(f.Type)
		if strings.Contains(opts, "string") && f.Type.Kind() != reflect.String {
			s = map[string]any{"type": "string"}
		}
		if f.Type.Kind() == reflect.Pointer && !optional {
			s = nullable(s)
		}
		props[name] = s
		if !optional {
			*required = append(*required, name)
		}
	}
}

// nullable allows null next to s (OpenAPI 3.1: JSON Schema 2020-12 types).
func nullable(s map[string]any) map[string]any {
	if ty, ok := s["type"].(string); ok {
		s = cloneMap(s)
		s["type"] = []any{ty, "null"}
		return s
	}
	return map[string]any{"oneOf": []any{s, map[string]any{"type": "null"}}}
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
