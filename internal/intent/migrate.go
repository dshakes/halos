package intent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/yamledit"
)

// Migrate rewrites every document's top-level apiVersion from
// policy.APIVersionV1Alpha1 to policy.APIVersion, in place: each value is
// spliced byte for byte (yamledit), so comments, formatting, quoting and the
// other documents of a file are untouched. A repo already on v1 yields an
// empty Change, so running it twice is a no-op. It walks the files the loader
// reads (*.yaml/*.yml, halos.yaml included, dot-directories skipped).
func Migrate(dir string) (*Change, error) {
	c := newChange(dir)
	walkRoot := dir // like policy.Load: walk a symlinked root's target
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		walkRoot = r
	}
	err := filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != walkRoot && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel, err := filepath.Rel(walkRoot, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p) //nolint:gosec // walks the operator-owned policy repo
		if err != nil {
			return err
		}
		out, err := migrateFile(filepath.Join(dir, rel), data)
		if err != nil {
			return err
		}
		if !bytes.Equal(out, data) {
			c.Files[filepath.ToSlash(rel)] = out
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("intent: migrate %s: %w", dir, err)
	}
	return c, nil
}

// migrateFile returns data with every document's v1alpha1 apiVersion set to
// v1. Each splice stays on its own line, so later documents' positions hold.
func migrateFile(path string, data []byte) ([]byte, error) {
	var maps []*yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode {
			maps = append(maps, doc.Content[0])
		}
	}
	for _, m := range maps {
		_, v := yamledit.Scalar(m, "apiVersion")
		if v == nil || v.Kind != yaml.ScalarNode || v.Value != policy.APIVersionV1Alpha1 {
			continue
		}
		d := &yamledit.Doc{Path: path, Data: data, Mapping: m}
		out, err := d.SetPath([]string{"apiVersion"}, yamledit.Quote(policy.APIVersion, v.Style))
		if err != nil {
			return nil, err
		}
		data = out
	}
	return data, nil
}
