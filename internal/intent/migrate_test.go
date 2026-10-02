package intent

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func TestMigrateFile(t *testing.T) {
	cases := []struct {
		name, in, want, err string
	}{
		{"plain", "apiVersion: halos.dev/v1alpha1\nkind: Ring\n", "apiVersion: halos.dev/v1\nkind: Ring\n", ""},
		{"comments and quotes kept",
			"# head\napiVersion: \"halos.dev/v1alpha1\" # tail\nkind: Ring\n",
			"# head\napiVersion: \"halos.dev/v1\" # tail\nkind: Ring\n", ""},
		{"single quoted", "kind: Ring\napiVersion: 'halos.dev/v1alpha1'\n", "kind: Ring\napiVersion: 'halos.dev/v1'\n", ""},
		{"multi-document, later docs shift",
			"apiVersion: halos.dev/v1alpha1\nkind: Ring\n---\n# two\napiVersion: halos.dev/v1alpha1\nkind: Profile\nname: x # keep\n",
			"apiVersion: halos.dev/v1\nkind: Ring\n---\n# two\napiVersion: halos.dev/v1\nkind: Profile\nname: x # keep\n", ""},
		{"already v1", "apiVersion: halos.dev/v1\nkind: Ring\n", "apiVersion: halos.dev/v1\nkind: Ring\n", ""},
		{"other version untouched", "apiVersion: example.com/v9\n", "apiVersion: example.com/v9\n", ""},
		{"nested apiVersion untouched", "kind: Ring\nspec:\n  apiVersion: halos.dev/v1alpha1\n", "kind: Ring\nspec:\n  apiVersion: halos.dev/v1alpha1\n", ""},
		{"not a mapping", "- a\n- b\n", "- a\n- b\n", ""},
		{"empty", "", "", ""},
		{"parse error", "apiVersion: [\n", "", "parse x.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := migrateFile("x.yaml", []byte(tc.in))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

// TestMigrateExample downgrades a full example to v1alpha1 and checks the
// whole contract: it loads with identical semantics and only deprecation
// warnings, Migrate restores the v1 bytes exactly, and a second run is a no-op.
func TestMigrateExample(t *testing.T) {
	src := filepath.Join("..", "..", "examples", "acme-corp")
	dir := copyRepo(t, src)
	orig := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (filepath.Ext(p) != ".yaml" && filepath.Ext(p) != ".yml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		down := bytes.ReplaceAll(b, []byte("apiVersion: "+policy.APIVersion+"\n"), []byte("apiVersion: "+policy.APIVersionV1Alpha1+"\n"))
		if bytes.Equal(down, b) {
			return nil
		}
		orig[p] = b
		return os.WriteFile(p, down, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}

	want, err := policy.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := policy.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := policy.Compile(want)
	if err != nil {
		t.Fatal(err)
	}
	gs, err := policy.Compile(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ws, gs) {
		t.Error("v1alpha1 copy compiles to a different snapshot than v1")
	}
	issues := got.Validate()
	if len(issues) != len(orig) {
		t.Errorf("issues = %d, want one deprecation per file (%d): %v", len(issues), len(orig), issues)
	}
	for _, is := range issues {
		if is.Severity != policy.SeverityWarning || !strings.Contains(is.Message, "halo migrate") {
			t.Errorf("unexpected issue: %v", is)
		}
	}

	ch, err := Migrate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Files) != len(orig) {
		t.Errorf("migrate changed %d files, want %d", len(ch.Files), len(orig))
	}
	if err := ch.Apply(); err != nil {
		t.Fatal(err)
	}
	for p, b := range orig {
		if after, err := os.ReadFile(p); err != nil || !bytes.Equal(after, b) {
			t.Errorf("%s not restored byte for byte (err %v)", p, err)
		}
	}
	again, err := Migrate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Files) != 0 {
		t.Errorf("second migrate not a no-op: %v", again.Files)
	}
}

func TestMigrateMissingDir(t *testing.T) {
	if _, err := Migrate(filepath.Join(t.TempDir(), "nope")); err == nil || !strings.Contains(err.Error(), "intent: migrate") {
		t.Fatalf("err = %v", err)
	}
}
