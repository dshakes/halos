package toggle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/dshakes/halos/internal/harness/hutil"
)

// A fragment is the delta between a harness's rendered base file and the same
// file rendered with a toggle on: maps recurse, arrays carry only the elements
// the base lacks, anything else is the new value. Merge applies deltas with the
// matching semantics (maps merge, arrays append what is absent, scalars replace),
// so several toggles compose without a re-render on the device.
// ponytail: arrays are sets of whole elements; a toggle hook that lands in an
// existing Claude hook matcher group re-adds that group. Give toggle hooks a
// matcher of their own.

// Delta returns the JSON delta turning base into on for the file at p, or nil
// when they are equal. A nil base means the toggle adds the file.
func Delta(p string, base, on []byte) ([]byte, error) {
	if bytes.Equal(base, on) {
		return nil, nil
	}
	var b, o any
	if base != nil {
		var err error
		if b, err = decode(p, base); err != nil {
			return nil, fmt.Errorf("toggle: base %s: %w", p, err)
		}
	}
	o, err := decode(p, on)
	if err != nil {
		return nil, fmt.Errorf("toggle: toggled %s: %w", p, err)
	}
	d, changed := diff(b, o)
	if !changed {
		return nil, nil
	}
	return json.Marshal(d)
}

// Merge applies JSON deltas to the file at p (base nil = absent) and returns
// the re-encoded file.
func Merge(p string, base []byte, deltas ...[]byte) ([]byte, error) {
	var cur any = map[string]any{}
	if base != nil {
		var err error
		if cur, err = decode(p, base); err != nil {
			return nil, fmt.Errorf("toggle: base %s: %w", p, err)
		}
	}
	for _, raw := range deltas {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var d any
		if err := dec.Decode(&d); err != nil {
			return nil, fmt.Errorf("toggle: fragment for %s: %w", p, err)
		}
		cur = apply(cur, d)
	}
	return encode(p, cur)
}

func decode(p string, data []byte) (any, error) {
	var v map[string]any
	switch strings.ToLower(path.Ext(strings.ReplaceAll(p, `\`, "/"))) {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
	case ".toml":
		if err := toml.Unmarshal(data, &v); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%s is not a structured settings file; toggles can only change .json and .toml", p)
	}
	return v, nil
}

func encode(p string, v any) ([]byte, error) {
	if strings.EqualFold(path.Ext(strings.ReplaceAll(p, `\`, "/")), ".toml") {
		b, err := toml.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("toggle: encode %s: %w", p, err)
		}
		return b, nil
	}
	m, _ := v.(map[string]any)
	return hutil.JSON(m)
}

func diff(base, on any) (any, bool) {
	switch o := on.(type) {
	case map[string]any:
		b, ok := base.(map[string]any)
		if !ok {
			return o, true
		}
		out := map[string]any{}
		for k, v := range o {
			if bv, had := b[k]; !had {
				out[k] = v
			} else if d, changed := diff(bv, v); changed {
				out[k] = d
			}
		}
		return out, len(out) > 0
	case []any:
		b, ok := base.([]any)
		if !ok {
			return o, true
		}
		var add []any
		for _, e := range o {
			if !containsDeep(b, e) {
				add = append(add, e)
			}
		}
		return add, len(add) > 0
	}
	return on, !reflect.DeepEqual(base, on)
}

func apply(cur, d any) any {
	switch dv := d.(type) {
	case map[string]any:
		cm, ok := cur.(map[string]any)
		if !ok {
			return dv
		}
		for k, v := range dv {
			cm[k] = apply(cm[k], v)
		}
		return cm
	case []any:
		ca, ok := cur.([]any)
		if !ok {
			return dv
		}
		for _, e := range dv {
			if !containsDeep(ca, e) {
				ca = append(ca, e)
			}
		}
		return ca
	}
	return d
}

func containsDeep(s []any, e any) bool {
	for _, x := range s {
		if reflect.DeepEqual(x, e) {
			return true
		}
	}
	return false
}
