package docgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func fixtureTree() *cobra.Command {
	root := &cobra.Command{Use: "halo", Short: "root"}
	root.PersistentFlags().String("output", "text", "format: text|json")
	grp := &cobra.Command{Use: "grp", Short: "group <x>"}
	leaf := &cobra.Command{
		Use: "leaf [flags]", Short: "leaf | cmd", Long: "Use <name> and `<kept>`.",
		Example: "halo grp leaf --n 3", Run: func(*cobra.Command, []string) {},
	}
	leaf.Flags().IntP("n", "n", 3, "count {a|b}")
	hidden := &cobra.Command{Use: "secret", Short: "h", Hidden: true, Run: func(*cobra.Command, []string) {}}
	grp.AddCommand(leaf)
	root.AddCommand(grp, hidden)
	return root
}

func read(t *testing.T, p ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(p...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCLI(t *testing.T) {
	dir := t.TempDir()
	n, err := CLI(fixtureTree(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("pages = %d, want 3 (index, grp, grp-leaf; hidden skipped)", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "secret.md")); err == nil {
		t.Error("hidden command rendered")
	}
	leaf := read(t, dir, "grp-leaf.md")
	for _, want := range []string{
		`title: "halo grp leaf"`, `description: "leaf | cmd"`, "```console\nhalo grp leaf [flags]",
		"| `--n` | `-n` | int | 3 | count &#123;a\\|b} |", "## Global flags", "`--output`",
		"## Examples", "Use &lt;name> and `<kept>`", "[`halo grp`](/halos/reference/cli/grp/)",
	} {
		if !strings.Contains(leaf, want) {
			t.Errorf("grp-leaf.md missing %q:\n%s", want, leaf)
		}
	}
	if idx := read(t, dir, "index.md"); !strings.Contains(idx, "[`halo grp`](/halos/reference/cli/grp/) | group &lt;x>") {
		t.Errorf("index missing grp row:\n%s", idx)
	}
}

func TestPolicyFixture(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	schema := `{"title":"T","description":"d","type":"object","required":["a"],
	"$defs":{"d":{"type":"object","properties":{"z":{"type":"string","default":"q"}}}},
	"properties":{"a":{"type":"string","enum":["x","y"],"description":"a|b"},
	"l":{"type":"array","items":{"$ref":"#/$defs/d"}},
	"m":{"type":"object","additionalProperties":{"type":"integer","minimum":1}}},
	"oneOf":[{"required":["a"]},{"required":["l"]}]}`
	if err := os.WriteFile(filepath.Join(src, "foo.schema.json"), []byte(schema), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Policy(src, dst); err != nil {
		t.Fatal(err)
	}
	got := read(t, dst, "foo.md")
	for _, want := range []string{
		"| `a` | string | yes |  | x, y |  | a\\|b |", "| `l[].z` | string |  | q |", "| `m.*` | integer |", "minimum 1",
		"exactly one of `a` or `l`",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("foo.md missing %q:\n%s", want, got)
		}
	}
}

func TestPolicyAllSchemasRender(t *testing.T) {
	schemas, err := filepath.Glob("../../schemas/*.schema.json")
	if err != nil || len(schemas) == 0 {
		t.Fatalf("no schemas found: %v", err)
	}
	dst := t.TempDir()
	n, err := Policy("../../schemas", dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(schemas)+1 {
		t.Fatalf("pages = %d, want %d", n, len(schemas)+1)
	}
	for _, s := range schemas {
		kind := strings.TrimSuffix(filepath.Base(s), ".schema.json")
		if page := read(t, dst, kind+".md"); strings.Count(page, "\n| `") < 1 {
			t.Errorf("%s rendered no field rows", kind)
		}
	}
}

func TestPolicyErrors(t *testing.T) {
	if _, err := Policy(t.TempDir(), t.TempDir()); err == nil {
		t.Error("empty schema dir: want error")
	}
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "bad.schema.json"), []byte("{"), 0o644)
	if _, err := Policy(src, t.TempDir()); err == nil {
		t.Error("bad json: want error")
	}
}
