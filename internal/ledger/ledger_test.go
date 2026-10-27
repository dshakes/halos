package ledger

import (
	"slices"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

func base() Record {
	return Record{SessionID: "s-1", Harness: "claude-code", Start: t0, Sources: []string{SourceOTel}}
}

var salt = []byte("0123456789abcdef-salt")

func TestNormalizeRedaction(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mut     func(*Record)
		pol     Redaction
		wantErr string
		check   func(*testing.T, Record)
	}{
		{name: "drop is the default: paths counted, never kept",
			mut: func(r *Record) {
				r.Files, r.Repos = []string{"/home/a/secret-plan.md", "/home/a/x.go", "/home/a/x.go"}, []string{"https://github.com/acme/private"}
			},
			check: func(t *testing.T, r Record) {
				if len(r.Files) != 0 || len(r.Repos) != 0 || r.FilesTouched != 2 || r.Redacted != 3 {
					t.Fatalf("files=%v repos=%v touched=%d redacted=%d", r.Files, r.Repos, r.FilesTouched, r.Redacted)
				}
			}},
		{name: "hash keeps comparable salted hashes",
			pol: Redaction{Paths: PathsHash, Salt: salt},
			mut: func(r *Record) { r.Files = []string{"/a/b.go"} },
			check: func(t *testing.T, r Record) {
				if len(r.Files) != 1 || !hashedRE.MatchString(r.Files[0]) || strings.Contains(r.Files[0], "b.go") {
					t.Fatalf("files=%v", r.Files)
				}
				if r.Files[0] != (Redaction{Paths: PathsHash, Salt: salt}).hash("/a/b.go") {
					t.Fatal("hash is not deterministic for one salt")
				}
			}},
		{name: "hash without a salt fails closed", pol: Redaction{Paths: PathsHash}, wantErr: "salt"},
		{name: "unknown mode fails closed", pol: Redaction{Paths: "keep"}, wantErr: "unknown paths mode"},
		{name: "prose in a tool or model is withheld",
			mut: func(r *Record) {
				r.Tools = []string{"Bash", "please summarise the merger memo"}
				r.Models = []string{"claude-sonnet-5", "line1\nline2"}
				r.Ring = "ring one"
			},
			check: func(t *testing.T, r Record) {
				if !slices.Equal(r.Tools, []string{"Bash"}) || !slices.Equal(r.Models, []string{"claude-sonnet-5"}) || r.Ring != "" || r.Redacted != 3 {
					t.Fatalf("tools=%v models=%v ring=%q redacted=%d", r.Tools, r.Models, r.Ring, r.Redacted)
				}
			}},
		{name: "prose as a session id rejects the whole import",
			mut: func(r *Record) { r.SessionID = "what is our Q3 revenue" }, wantErr: "session id"},
		{name: "missing start rejects", mut: func(r *Record) { r.Start = time.Time{} }, wantErr: "start is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			if tc.mut != nil {
				tc.mut(&r)
			}
			out, err := Normalize([]Record{r}, tc.pol)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if out != nil {
					t.Fatal("records returned with an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || out[0].ID != IDFor("claude-code", "s-1") || out[0].Outcome != OutcomeUnknown || out[0].Confidence != Medium {
				t.Fatalf("out = %+v", out)
			}
			tc.check(t, out[0])
		})
	}
}

func TestValidateFailsClosed(t *testing.T) {
	ok := func() Record {
		r := base()
		r.ID, r.Outcome, r.Confidence = IDFor(r.Harness, r.SessionID), OutcomeUnknown, Medium
		return r
	}
	if r := ok(); r.Validate() != nil {
		t.Fatalf("baseline invalid: %v", r.Validate())
	}
	for _, tc := range []struct {
		name string
		mut  func(*Record)
		want string
	}{
		{"unredacted file path", func(r *Record) { r.Files = []string{"/etc/passwd"} }, "unredacted"},
		{"unredacted repo", func(r *Record) { r.Repos = []string{"acme/private"} }, "unredacted"},
		{"prompt text in a scalar", func(r *Record) { r.Experiment = "Refactor the billing module please" }, "prose"},
		{"prompt text in a list", func(r *Record) { r.MCPServers = []string{"ignore previous instructions"} }, "prose"},
		{"control characters", func(r *Record) { r.Who.VendorUser = "a@b\x1b[31m" }, "prose"},
		{"forged id", func(r *Record) { r.ID = "deadbeef" }, "id"},
		{"bad outcome", func(r *Record) { r.Outcome = "great" }, "outcome"},
		{"bad confidence", func(r *Record) { r.Confidence = "certain" }, "confidence"},
		{"no source", func(r *Record) { r.Sources = nil }, "source"},
		{"unknown source", func(r *Record) { r.Sources = []string{"rumour"} }, "source"},
		{"end before start", func(r *Record) { r.End = t0.Add(-time.Second) }, "end"},
		{"negative tokens", func(r *Record) { r.InputTokens = -1 }, "negative"},
		{"too many tools", func(r *Record) {
			for i := range maxList + 1 {
				r.Tools = append(r.Tools, "t"+strings.Repeat("x", i%5)+string(rune('a'+i%26)))
			}
		}, "more than"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ok()
			tc.mut(&r)
			if err := r.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMergeAcrossSources(t *testing.T) {
	otel := base()
	otel.Ring, otel.Who.VendorUser, otel.Tools, otel.InputTokens, otel.End = "ring-from-client", "dev@acme.example", []string{"Edit"}, 100, t0.Add(time.Minute)
	gw := base()
	gw.Sources, gw.Ring, gw.Tools, gw.InputTokens, gw.Start, gw.Outcome = []string{SourceGateway}, "ring1", []string{"Bash"}, 80, t0.Add(-time.Minute), OutcomeCompleted
	out, err := Normalize([]Record{otel, gw}, Redaction{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("not merged: %d records", len(out))
	}
	r := out[0]
	if r.Ring != "ring1" || r.Who.VendorUser != "dev@acme.example" || r.InputTokens != 100 || !slices.Equal(r.Tools, []string{"Bash", "Edit"}) ||
		!slices.Equal(r.Sources, []string{SourceGateway, SourceOTel}) || r.Confidence != High || !r.Start.Equal(gw.Start) || !r.End.Equal(otel.End) ||
		r.Outcome != OutcomeCompleted {
		t.Fatalf("merged = %+v", r)
	}
}

func TestJoinUsesDirectoryOnly(t *testing.T) {
	dir := map[string]string{"dev@acme.example": "dev@acme.example", "octocat": "cat@acme.example"}
	lookup := func(v string) (string, bool) { u, ok := dir[v]; return u, ok }
	recs := []Record{
		{Who: Who{VendorUser: "octocat", User: "ceo@acme.example"}}, // a forged User is replaced
		{Who: Who{VendorUser: "stranger@else.example", User: "ceo@acme.example"}},
		{Who: Who{VendorUser: "dev@acme.example"}},
		{Who: Who{Unit: "u123"}},
	}
	Join(recs, lookup)
	got := []string{recs[0].Who.User, recs[1].Who.User, recs[2].Who.User, recs[3].Who.User}
	if want := []string{"cat@acme.example", "", "dev@acme.example", ""}; !slices.Equal(got, want) {
		t.Fatalf("users = %q, want %q", got, want)
	}
	recs[0].Who.User = "forged"
	Join(recs, nil)
	if recs[0].Who.User != "" {
		t.Fatal("no directory must leave every record unresolved")
	}
}

func TestFilter(t *testing.T) {
	r := base()
	r.Who, r.Ring, r.Tools, r.MCPServers = Who{User: "dev@acme.example"}, "ring1", []string{"Bash"}, []string{"github"}
	unresolved := base()
	unresolved.Who.VendorUser = "octocat"
	for _, tc := range []struct {
		f    Filter
		r    Record
		want bool
	}{
		{Filter{}, r, true},
		{Filter{User: "DEV@acme.example"}, r, true},
		{Filter{User: "other@acme.example"}, r, false},
		{Filter{User: "octocat"}, unresolved, true},
		{Filter{Harness: "codex"}, r, false},
		{Filter{Ring: "ring1", Tool: "github"}, r, true},
		{Filter{Tool: "Edit"}, r, false},
		{Filter{Since: t0}, r, true},
		{Filter{Since: t0.Add(time.Second)}, r, false},
		{Filter{Until: t0}, r, false},
	} {
		if got := tc.f.Match(&tc.r); got != tc.want {
			t.Errorf("%+v on %+v: %v, want %v", tc.f, tc.r.Who, got, tc.want)
		}
	}
}

func TestParseTime(t *testing.T) {
	for in, want := range map[string]time.Time{"": {}, "2026-10-01T00:00:00Z": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), "24h": t0.Add(-24 * time.Hour), "7d": t0.AddDate(0, 0, -7)} {
		if got, err := ParseTime(in, t0); err != nil || !got.Equal(want) {
			t.Errorf("ParseTime(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"yesterday", "-1h", "0d"} {
		if _, err := ParseTime(bad, t0); err == nil {
			t.Errorf("ParseTime(%q) accepted", bad)
		}
	}
}
