package toggle

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// Known answers: the toggle salt namespace and assign.Bucket are a fleet-wide
// contract; if this fails, every percent rollout reshuffles.
func TestBucketKnownAnswer(t *testing.T) {
	for _, tc := range []struct {
		name, subject string
		want          int
	}{
		{"github-mcp", "alice@acme.example", 3861},
		{"github-mcp", "bob@acme.example", 1963},
		{"other", "alice@acme.example", 2180}, // a different toggle hashes independently
		{"other", "bob@acme.example", 3978},
	} {
		if got := Bucket(tc.name, tc.subject); got != tc.want {
			t.Errorf("Bucket(%q, %q) = %d, want %d", tc.name, tc.subject, got, tc.want)
		}
	}
	if Salt("x") != "halos/toggles/x" {
		t.Errorf("Salt = %q", Salt("x"))
	}
}

func TestEval(t *testing.T) {
	alice := Subject{ID: "alice@acme.example", Groups: []string{"eng"}, Ring: "ring1"} // bucket 3861 under salt "github-mcp"
	rules := func(rs ...policy.ToggleRule) []policy.ToggleRule { return rs }
	tests := []struct {
		name    string
		toggle  string
		def     bool
		rules   []policy.ToggleRule
		sub     Subject
		killed  bool
		wantOn  bool
		wantIdx int
	}{
		{"no rules default off", "t", false, nil, alice, false, false, -1},
		{"no rules default on", "t", true, nil, alice, false, true, -1},
		{"ring match", "t", false, rules(policy.ToggleRule{Rings: []string{"ring1"}}), alice, false, true, 0},
		{"ring miss", "t", false, rules(policy.ToggleRule{Rings: []string{"ring0"}}), alice, false, false, -1},
		{"group match", "t", false, rules(policy.ToggleRule{Groups: []string{"ops", "eng"}}), alice, false, true, 0},
		{"user match", "t", false, rules(policy.ToggleRule{Users: []string{"alice@acme.example"}}), alice, false, true, 0},
		{"conditions are ANDed", "t", false, rules(policy.ToggleRule{Rings: []string{"ring1"}, Groups: []string{"ops"}}), alice, false, false, -1},
		{"empty rule matches everyone", "t", false, rules(policy.ToggleRule{}), Subject{}, false, true, 0},
		{"first match wins", "t", true, rules(
			policy.ToggleRule{Users: []string{"alice@acme.example"}, Effect: policy.EffectOff},
			policy.ToggleRule{Rings: []string{"ring1"}}), alice, false, false, 0},
		{"off rule falls through to later on rule when unmatched", "t", false, rules(
			policy.ToggleRule{Users: []string{"bob@acme.example"}, Effect: policy.EffectOff},
			policy.ToggleRule{Rings: []string{"ring1"}}), alice, false, true, 1},
		{"percent in (bucket 3861 < 4000)", "github-mcp", false, rules(policy.ToggleRule{Percent: pct(40)}), alice, false, true, 0},
		{"percent out (bucket 3861 >= 3000)", "github-mcp", false, rules(policy.ToggleRule{Percent: pct(30)}), alice, false, false, -1},
		{"percent 100 is everyone with an id", "github-mcp", false, rules(policy.ToggleRule{Percent: pct(100)}), alice, false, true, 0},
		{"percent 0 matches nobody", "github-mcp", true, rules(policy.ToggleRule{Percent: pct(0)}), alice, false, true, -1}, // falls to default
		{"percent 0 matches no anonymous caller either", "github-mcp", false, rules(policy.ToggleRule{Percent: pct(0)}), Subject{}, false, false, -1},
		{"percent 0 with ring still matches nobody", "github-mcp", false, rules(policy.ToggleRule{Rings: []string{"ring1"}, Percent: pct(0)}), alice, false, false, -1},
		{"percent never matches without a subject id", "github-mcp", false, rules(policy.ToggleRule{Percent: pct(100)}), Subject{Ring: "ring1"}, false, false, -1},
		{"ring AND percent", "github-mcp", false, rules(policy.ToggleRule{Rings: []string{"ring0"}, Percent: pct(100)}), alice, false, false, -1},
		{"killed beats a matching rule", "t", true, rules(policy.ToggleRule{}), alice, true, false, 0},
		{"killed beats default on", "t", true, nil, alice, true, false, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Eval(tc.toggle, tc.def, tc.rules, tc.sub, tc.killed)
			if d.On != tc.wantOn || d.Rule != tc.wantIdx || d.Killed != tc.killed {
				t.Fatalf("got on=%v rule=%d killed=%v (%s), want on=%v rule=%d", d.On, d.Rule, d.Killed, d.Why, tc.wantOn, tc.wantIdx)
			}
			if d.Why == "" {
				t.Error("empty Why")
			}
			if len(tc.rules) > 0 && len(d.Trace) == 0 {
				t.Error("empty trace")
			}
		})
	}
}

func TestEvalDeterministicAndIndependentOfOrder(t *testing.T) {
	rules := []policy.ToggleRule{{Percent: pct(25)}}
	first := Eval("github-mcp", false, rules, Subject{ID: "bob@acme.example"}, false)
	for i := 0; i < 50; i++ {
		if got := Eval("github-mcp", false, rules, Subject{ID: "bob@acme.example"}, false); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs: %+v vs %+v", i, got, first)
		}
	}
	if !first.On { // bucket 1963 < 2500
		t.Fatalf("bob (bucket 1963) should be in a 25%% rollout: %+v", first)
	}
	if !strings.Contains(strings.Join(first.Trace, "\n"), "bucket 1963 < 2500") {
		t.Errorf("trace lacks the bucket arithmetic: %v", first.Trace)
	}
}

// A 10% rule must select about 10% of a population (and be stable per subject).
func TestPercentSelectsRoughlyThatShare(t *testing.T) {
	on := 0
	const n = 20000
	for i := 0; i < n; i++ {
		if Eval("t", false, []policy.ToggleRule{{Percent: pct(10)}}, Subject{ID: "u" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + itoa(i)}, false).On {
			on++
		}
	}
	if on < n*8/100 || on > n*12/100 {
		t.Fatalf("10%% rule selected %d of %d", on, n)
	}
}

func pct(f float64) *float64 { return &f }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestDeltaMerge(t *testing.T) {
	base := []byte(`{"env":{"A":"1"},"allowedMcpServers":[{"serverUrl":"https://a"}],"hooks":{"PreToolUse":[{"matcher":"Bash"}]}}`)
	on1 := []byte(`{"env":{"A":"1","B":"2"},"allowedMcpServers":[{"serverUrl":"https://a"},{"serverUrl":"https://b"}],"hooks":{"PreToolUse":[{"matcher":"Bash"}]}}`)
	on2 := []byte(`{"env":{"A":"1"},"allowedMcpServers":[{"serverUrl":"https://a"},{"serverUrl":"https://c"}],"hooks":{"PreToolUse":[{"matcher":"Bash"}],"PostToolUse":[{"matcher":"Edit"}]}}`)
	d1, err := Delta("x.json", base, on1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Delta("x.json", base, on2)
	if err != nil {
		t.Fatal(err)
	}
	// Two toggles touching the same array both land, in either order.
	for _, ds := range [][][]byte{{d1, d2}, {d2, d1}} {
		out, err := Merge("x.json", base, ds...)
		if err != nil {
			t.Fatal(err)
		}
		s := string(out)
		for _, want := range []string{`"B": "2"`, "https://b", "https://c", "PostToolUse", "https://a"} {
			if !strings.Contains(s, want) {
				t.Errorf("merged output lacks %q:\n%s", want, s)
			}
		}
		if strings.Count(s, "https://a") != 1 {
			t.Errorf("base element duplicated:\n%s", s)
		}
	}
	if d, _ := Delta("x.json", base, base); d != nil {
		t.Errorf("identical files must give no delta, got %s", d)
	}
	// Merging is idempotent: applying a fragment twice changes nothing.
	once, _ := Merge("x.json", base, d1)
	twice, _ := Merge("x.json", once, d1)
	if string(once) != string(twice) {
		t.Errorf("merge is not idempotent:\n%s\n%s", once, twice)
	}
}

func TestDeltaMergeTOMLAndNewFile(t *testing.T) {
	base := []byte("model = \"a\"\n[tui]\ntheme = \"x\"\n")
	on := []byte("model = \"a\"\n[tui]\ntheme = \"x\"\n[mcp_servers.gh]\nurl = \"https://gh\"\n")
	d, err := Delta("config.toml", base, on)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Merge("config.toml", base, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "https://gh") || !strings.Contains(string(out), `theme = 'x'`) && !strings.Contains(string(out), `theme = "x"`) {
		t.Fatalf("toml merge lost data:\n%s", out)
	}
	// A file the toggle adds (absent from the base) is its whole content.
	nd, err := Delta("new.json", nil, []byte(`{"mcpServers":{"gh":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Merge("new.json", nil, nd); err != nil || !strings.Contains(string(got), "mcpServers") {
		t.Fatalf("new file: %s %v", got, err)
	}
	if _, err := Delta("CLAUDE.md", []byte("a"), []byte("b")); err == nil {
		t.Fatal("toggles must not change unstructured files")
	}
	if _, err := Merge("x.json", []byte("{"), nil); err == nil {
		t.Fatal("corrupt base must error")
	}
}
