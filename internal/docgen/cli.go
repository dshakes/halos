// Package docgen renders the CLI (cobra tree) and policy (JSON Schema)
// reference pages for the docs site. Output is deterministic: sorted, no
// timestamps.
package docgen

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const cliBase = "/halos/reference/cli/"

// esc makes s safe inside a markdown table cell.
func esc(s string) string {
	r := strings.NewReplacer("|", `\|`, "<", "&lt;", "{", "&#123;", "\n", " ")
	return r.Replace(strings.TrimSpace(s))
}

// escText escapes "<" in prose, leaving fenced blocks, indented code and
// inline code spans alone.
func escText(s string) string {
	lines := strings.Split(s, "\n")
	fence := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			fence = !fence
			continue
		}
		if fence || strings.HasPrefix(l, "    ") || strings.HasPrefix(l, "\t") {
			continue
		}
		parts := strings.Split(l, "`")
		for j := 0; j < len(parts); j += 2 { // even parts are outside code spans
			parts[j] = strings.ReplaceAll(parts[j], "<", "&lt;")
		}
		lines[i] = strings.Join(parts, "`")
	}
	return strings.Join(lines, "\n")
}

func frontmatter(title, desc string) string {
	return "---\ntitle: " + strconv.Quote(title) + "\ndescription: " + strconv.Quote(desc) + "\n---\n\n"
}

// cmdSlug maps "halo release build" to "release-build"; the root is "index".
func cmdSlug(c *cobra.Command) string {
	p := strings.Fields(c.CommandPath())
	if len(p) <= 1 {
		return "index"
	}
	return strings.Join(p[1:], "-")
}

func cmdURL(c *cobra.Command) string {
	if s := cmdSlug(c); s != "index" {
		return cliBase + s + "/"
	}
	return cliBase
}

// subs returns the documented children of c: sorted, no hidden, help or completion.
func subs(c *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, s := range c.Commands() {
		if s.Hidden || s.Name() == "help" || s.Name() == "completion" || !s.IsAvailableCommand() {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

func flagTable(b *strings.Builder, fs *pflag.FlagSet) {
	var rows []string
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		sh := ""
		if f.Shorthand != "" {
			sh = "`-" + f.Shorthand + "`"
		}
		rows = append(rows, fmt.Sprintf("| `--%s` | %s | %s | %s | %s |\n", f.Name, sh, f.Value.Type(), esc(f.DefValue), esc(f.Usage)))
	})
	if len(rows) == 0 {
		b.WriteString("None.\n\n")
		return
	}
	b.WriteString("| Flag | Shorthand | Type | Default | Description |\n|---|---|---|---|---|\n")
	for _, r := range rows {
		b.WriteString(r)
	}
	b.WriteString("\n")
}

func cmdPage(c *cobra.Command, index bool) string {
	var b strings.Builder
	title := c.CommandPath()
	if index {
		b.WriteString(frontmatter("CLI reference", "Every halo command and flag, generated from the code."))
		b.WriteString(indexIntro)
	} else {
		b.WriteString(frontmatter(title, c.Short))
	}
	if c.Short != "" && !index {
		b.WriteString(escText(c.Short) + "\n\n")
	}
	if c.Long != "" {
		b.WriteString(escText(strings.TrimSpace(c.Long)) + "\n\n")
	}
	b.WriteString("## Usage\n\n```console\n" + c.UseLine() + "\n```\n\n")
	if len(c.Aliases) > 0 {
		b.WriteString("Aliases: `" + strings.Join(c.Aliases, "`, `") + "`\n\n")
	}
	b.WriteString("## Flags\n\n")
	flagTable(&b, c.NonInheritedFlags())
	if inh := c.InheritedFlags(); inh.HasFlags() && !index {
		b.WriteString("## Global flags\n\n")
		flagTable(&b, inh)
	}
	if c.Example != "" {
		b.WriteString("## Examples\n\n```console\n" + strings.TrimSpace(c.Example) + "\n```\n\n")
	}
	if kids := subs(c); len(kids) > 0 {
		b.WriteString("## Commands\n\n| Command | Description |\n|---|---|\n")
		for _, k := range kids {
			fmt.Fprintf(&b, "| [`%s`](%s) | %s |\n", k.CommandPath(), cmdURL(k), esc(k.Short))
		}
		b.WriteString("\n")
	}
	if c.HasParent() {
		b.WriteString("## Parent\n\n")
		fmt.Fprintf(&b, "[`%s`](%s)\n", c.Parent().CommandPath(), cmdURL(c.Parent()))
	}
	return b.String()
}

const indexIntro = `Generated from the command tree in ` + "`cmd/halo`" + `; do not edit. Regenerate with ` + "`make docs-gen`" + `.

Global flag: ` + "`--output text|json`" + `. Commands that read a policy repo take ` + "`--policy-dir D`" + ` (default ` + "`.`" + `). ` + "`halo validate`" + ` exits 0 when valid and 2 on validation errors; other failures exit 1 with ` + "`error: ...`" + ` on stderr.

The other binaries (` + "`halod`, `halo-proxy`, `halo-server`, `halo-shadow`" + `) are covered in [Binaries and runtime configuration](/halos/reference/binaries/).

`

// CLI writes one page per command under dir (index.md for the root) and
// returns the number of pages. Existing *.md files in dir are removed first so
// renamed commands leave nothing stale.
func CLI(root *cobra.Command, dir string) (int, error) {
	if err := resetDir(dir); err != nil {
		return 0, err
	}
	n := 0
	var walk func(c *cobra.Command) error
	walk = func(c *cobra.Command) error {
		p := filepath.Join(dir, cmdSlug(c)+".md")
		if err := os.WriteFile(p, []byte(cmdPage(c, c == root)), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", p, err)
		}
		n++
		for _, k := range subs(c) {
			if err := walk(k); err != nil {
				return err
			}
		}
		return nil
	}
	return n, walk(root)
}

func resetDir(dir string) error {
	old, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("remove %s: %w", f, err)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}
