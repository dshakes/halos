package docgen

// Drift checks for the Architecture > Deep dive pages: the tech-stack tables
// must match go.mod and the two package.json files, and the package graph the
// dependency-map diagram is drawn from (assets/src/pkgdeps.json) must match
// `go list`. Regenerate the graph with:
//
//	go test ./internal/docgen -run TestPackageGraph -update && python3 assets/src/build.py

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite assets/src/pkgdeps.json from go list")

const (
	repoRoot  = "../.."
	modPath   = "github.com/dshakes/halos"
	techStack = "docs/src/content/docs/architecture/tech-stack.md"
	pkgDeps   = "assets/src/pkgdeps.json"
)

// goosList: build-tagged files (e.g. golang.org/x/sys/windows) only show up under their GOOS.
var goosList = []string{"linux", "darwin", "windows"}

func goList(t *testing.T, goos string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-e"}, args...)...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS="+goos)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v (GOOS=%s): %v\n%s", args, goos, err, stderr.String())
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// directDeps parses go.mod: every required module not marked // indirect.
func directDeps(t *testing.T) map[string]string {
	t.Helper()
	deps := map[string]string{}
	inBlock := false
	for _, l := range strings.Split(read(t, repoRoot, "go.mod"), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "require (":
			inBlock = true
			continue
		case inBlock && l == ")":
			inBlock = false
			continue
		case strings.HasPrefix(l, "require "):
			l = strings.TrimPrefix(l, "require ")
		case !inBlock:
			continue
		}
		if strings.Contains(l, "// indirect") {
			continue
		}
		if f := strings.Fields(l); len(f) >= 2 {
			deps[f[0]] = f[1]
		}
	}
	return deps
}

type users struct{ prod, test map[string]bool }

// moduleUsers maps each module to the halos packages importing it, split into
// production imports and test-only imports, over every GOOS halos ships for.
func moduleUsers(t *testing.T) map[string]*users {
	t.Helper()
	mod := map[string]string{} // import path -> module path
	type pkg struct{ path, imports, tests string }
	var pkgs []pkg
	for _, goos := range goosList {
		for _, l := range goList(t, goos, "-deps", "-test", "-f", "{{.ImportPath}}\t{{with .Module}}{{.Path}}{{end}}", "./...") {
			if p := strings.Split(l, "\t"); len(p) == 2 && p[1] != "" {
				mod[p[0]] = p[1]
			}
		}
		for _, l := range goList(t, goos, "-f", "{{.ImportPath}}\t{{join .Imports \",\"}}\t{{join .TestImports \",\"}},{{join .XTestImports \",\"}}", "./...") {
			if p := strings.Split(l, "\t"); len(p) == 3 {
				pkgs = append(pkgs, pkg{strings.TrimPrefix(p[0], modPath+"/"), p[1], p[2]})
			}
		}
	}
	out := map[string]*users{}
	get := func(m string) *users {
		if out[m] == nil {
			out[m] = &users{map[string]bool{}, map[string]bool{}}
		}
		return out[m]
	}
	for _, p := range pkgs {
		for _, i := range strings.Split(p.imports, ",") {
			if m := mod[i]; m != "" && m != modPath {
				get(m).prod[p.path] = true
			}
		}
		for _, i := range strings.Split(p.tests, ",") {
			if m := mod[i]; m != "" && m != modPath {
				get(m).test[p.path] = true
			}
		}
	}
	for _, u := range out {
		for p := range u.prod {
			delete(u.test, p)
		}
	}
	return out
}

var tick = regexp.MustCompile("`([^`]+)`")

func ticked(s string) []string {
	var out []string
	for _, m := range tick.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// section returns the table rows of every block between <!-- check: name -->
// and <!-- /check --> (a source may be split over several grouped tables).
func section(t *testing.T, doc, name string) [][]string {
	t.Helper()
	open := "<!-- check: " + name + " -->"
	parts := strings.Split(doc, open)
	if len(parts) < 2 {
		t.Fatalf("%s: marker %q missing", techStack, open)
	}
	var lines []string
	for _, p := range parts[1:] {
		body, _, ok := strings.Cut(p, "<!-- /check -->")
		if !ok {
			t.Fatalf("%s: a %q block is not closed", techStack, open)
		}
		lines = append(lines, strings.Split(body, "\n")...)
	}
	var rows [][]string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "|") || strings.HasPrefix(l, "| ---") || strings.HasPrefix(l, "|---") {
			continue
		}
		cells := strings.Split(strings.Trim(l, "|"), "|")
		for k := range cells {
			cells[k] = strings.TrimSpace(cells[k])
		}
		if len(ticked(cells[0])) == 0 { // header row
			continue
		}
		rows = append(rows, cells)
	}
	return rows
}

func setOf(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestTechStackGoModules(t *testing.T) {
	doc := read(t, repoRoot, techStack)
	want := directDeps(t)
	us := moduleUsers(t)
	seen := map[string]bool{}
	for _, r := range section(t, doc, "go.mod") {
		if len(r) != 4 {
			t.Errorf("row %q: want 4 cells (module | version | used for | used by)", r)
			continue
		}
		m, v := ticked(r[0]), ticked(r[1])
		if len(m) != 1 || len(v) != 1 {
			t.Errorf("row %q: module and version must each be one `code` span", r)
			continue
		}
		seen[m[0]] = true
		if want[m[0]] == "" {
			t.Errorf("%s is listed but is not a direct requirement in go.mod", m[0])
			continue
		}
		if v[0] != want[m[0]] {
			t.Errorf("%s: doc says %s, go.mod says %s", m[0], v[0], want[m[0]])
		}
		prodCell, testCell, _ := strings.Cut(r[3], "tests:")
		u := us[m[0]]
		if u == nil {
			u = &users{}
		}
		if got, exp := setOf(ticked(prodCell)), u.prod; !maps(got, exp) {
			t.Errorf("%s used by: doc %v, go list %v", m[0], keys(got), keys(exp))
		}
		if got, exp := setOf(ticked(testCell)), u.test; !maps(got, exp) {
			t.Errorf("%s used by (tests only): doc %v, go list %v", m[0], keys(got), keys(exp))
		}
	}
	for m := range want {
		if !seen[m] {
			t.Errorf("go.mod requires %s directly; add a row to %s", m, techStack)
		}
	}
}

func maps(a, b map[string]bool) bool {
	return slices.Equal(keys(a), keys(b))
}

func TestTechStackNPM(t *testing.T) {
	doc := read(t, repoRoot, techStack)
	for _, name := range []string{"web/package.json", "docs/package.json"} {
		var pj struct{ Dependencies, DevDependencies map[string]string }
		if err := json.Unmarshal([]byte(read(t, repoRoot, name)), &pj); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := map[string]string{}
		for k, v := range pj.Dependencies {
			want[k] = v
		}
		for k, v := range pj.DevDependencies {
			want[k] = v
		}
		seen := map[string]bool{}
		for _, r := range section(t, doc, name) {
			p, v := ticked(r[0]), ticked(r[1])
			if len(p) != 1 || len(v) != 1 {
				t.Errorf("%s row %q: package and range must each be one `code` span", name, r)
				continue
			}
			seen[p[0]] = true
			switch {
			case want[p[0]] == "":
				t.Errorf("%s: %s is listed but not in package.json", name, p[0])
			case want[p[0]] != v[0]:
				t.Errorf("%s: %s doc %s, package.json %s", name, p[0], v[0], want[p[0]])
			}
		}
		for p := range want {
			if !seen[p] {
				t.Errorf("%s: add a row for %s", name, p)
			}
		}
	}
}

// pkgGraph is assets/src/pkgdeps.json: every package under cmd/ and internal/
// with its direct (non-test) imports of other halos packages.
type pkgGraph struct {
	Note     string    `json:"note"`
	Packages []pkgNode `json:"packages"`
}

type pkgNode struct {
	Path    string   `json:"path"`
	Imports []string `json:"imports"`
}

func TestPackageGraph(t *testing.T) {
	deps := map[string]map[string]bool{}
	for _, goos := range goosList {
		for _, l := range goList(t, goos, "-f", "{{.ImportPath}}\t{{join .Imports \",\"}}", "./cmd/...", "./internal/...") {
			p := strings.Split(l, "\t")
			if len(p) != 2 {
				continue
			}
			from := strings.TrimPrefix(p[0], modPath+"/")
			if deps[from] == nil {
				deps[from] = map[string]bool{}
			}
			for _, i := range strings.Split(p[1], ",") {
				if to, ok := strings.CutPrefix(i, modPath+"/"); ok {
					deps[from][to] = true
				}
			}
		}
	}
	g := pkgGraph{Note: "generated by go test ./internal/docgen -run TestPackageGraph -update; do not edit"}
	paths := make([]string, 0, len(deps))
	for p := range deps {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		g.Packages = append(g.Packages, pkgNode{Path: p, Imports: keys(deps[p])})
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join(repoRoot, pkgDeps)
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if got := read(t, path); got != string(b) {
		t.Errorf("%s is stale; run: go test ./internal/docgen -run TestPackageGraph -update && python3 assets/src/build.py", pkgDeps)
	}
}

var srcLink = regexp.MustCompile(`https://github\.com/dshakes/halos/(?:blob|tree)/main/([^)#\s]+)(?:#L(\d+)(?:-L(\d+))?)?`)

// TestArchitectureCitations: every source link on the Architecture pages names
// a file or directory that exists and, for #Lx-Ly anchors, lines it has.
func TestArchitectureCitations(t *testing.T) {
	dir := filepath.Join(repoRoot, "docs/src/content/docs/architecture")
	pages, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil || len(pages) == 0 {
		t.Fatalf("no architecture pages under %s: %v", dir, err)
	}
	n := 0
	for _, page := range pages {
		b, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range srcLink.FindAllStringSubmatch(string(b), -1) {
			n++
			p := filepath.Join(repoRoot, filepath.FromSlash(m[1]))
			fi, err := os.Stat(p)
			if err != nil {
				t.Errorf("%s: %s does not exist", filepath.Base(page), m[1])
				continue
			}
			if m[2] == "" || fi.IsDir() {
				continue
			}
			last := m[2]
			if m[3] != "" {
				last = m[3]
			}
			src, _ := os.ReadFile(p)
			lines := strings.Count(string(src), "\n") + 1
			if end := atoi(last); end > lines || atoi(m[2]) > end {
				t.Errorf("%s: %s#L%s-L%s is outside the file (%d lines)", filepath.Base(page), m[1], m[2], last, lines)
			}
		}
	}
	if n == 0 {
		t.Fatal("no source citations found")
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s) // the regexp only captures digits
	return n
}
