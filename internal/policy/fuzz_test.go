package policy

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// FuzzLoadValidate feeds arbitrary halos.yaml + policy documents through
// Load and Validate. Neither may panic, and a policy that validates without
// errors must satisfy the no-bypass invariant on every resolved profile and
// pass every default guardrail on its own. Seeded from every example repo.
func FuzzLoadValidate(f *testing.F) {
	roots, _ := filepath.Glob("../../examples/*/halos.yaml")
	for _, root := range roots {
		rb, err := os.ReadFile(root)
		if err != nil {
			f.Fatal(err)
		}
		var all [][]byte
		_ = filepath.WalkDir(filepath.Dir(root), func(p string, d fs.DirEntry, err error) error {
			if err != nil || p == root {
				return err
			}
			if d.IsDir() && d.Name() != filepath.Base(filepath.Dir(root)) && d.Name()[0] == '.' {
				return filepath.SkipDir
			}
			if ext := filepath.Ext(p); ext == ".yaml" || ext == ".yml" {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				all = append(all, b)
				f.Add(rb, b)
			}
			return nil
		})
		f.Add(rb, bytes.Join(all, []byte("\n---\n")))
	}
	f.Add([]byte("org: x\n"), []byte("kind: Profile\nmetadata: {name: p}\npermissions: {mode: bypassPermissions}\n"))

	f.Fuzz(func(t *testing.T, root, docs []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, RootFile), root, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), docs, 0o600); err != nil {
			t.Fatal(err)
		}
		o, err := Load(dir)
		if err != nil {
			return
		}
		if HasErrors(o.Validate()) {
			return
		}
		for _, name := range sortedKeys(o.Profiles) {
			p, err := o.ResolveProfile(name)
			if err != nil {
				t.Fatalf("profile %q validated but does not resolve: %v", name, err)
			}
			if p.Permissions.Mode == "bypassPermissions" || forbiddenValue(p.Env) {
				t.Fatalf("profile %q validated with a bypass mode: %+v", name, p.Permissions)
			}
			if s := p.Permissions.Sandbox; s != "" && !slices.Contains(sandboxModes, s) {
				t.Fatalf("profile %q validated with sandbox %q", name, s)
			}
			for h, spec := range p.Harnesses {
				if forbiddenValue(spec.Overrides) {
					t.Fatalf("profile %q validated with a forbidden %s override: %v", name, h, spec.Overrides)
				}
			}
		}
		for _, r := range o.Rings {
			if p, err := o.ResolveProfile(r.Profile); err == nil && !p.Permissions.DisableBypass {
				t.Fatalf("ring %q validated without disableBypass", r.Name)
			}
		}
		for i, g := range DefaultGuardrails {
			if HasErrors(g(o)) {
				t.Fatalf("guardrail %d reports errors on a validated policy: %v", i, g(o))
			}
		}
	})
}
