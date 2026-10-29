package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestImportServerJSON(t *testing.T) {
	sha := "sha256:" + strings.Repeat("d", 64)
	// A registry API response (GET /v0/servers/{name}/versions/latest), as served for playwright-mcp.
	playwright := `{"server":{"name":"io.github.microsoft/playwright-mcp","version":"0.0.82",
		"packages":[{"registryType":"npm","identifier":"@playwright/mcp","version":"0.0.82","transport":{"type":"stdio"}}]},"_meta":{}}`
	both := `{"name":"io.example/Ticket_Desk","version":"2.1.0",
		"packages":[{"registryType":"nuget","identifier":"X","version":"1.0.0","transport":{"type":"stdio"}},
		            {"registryType":"pypi","identifier":"ticket-desk","version":"2.1.0","transport":{"type":"stdio"},
		             "packageArguments":[{"type":"positional","value":"serve"},{"type":"named","name":"--token"}],
		             "environmentVariables":[{"name":"DESK_TOKEN","isRequired":true}]}],
		"remotes":[{"type":"sse","url":"https://desk.example/sse"},{"type":"streamable-http","url":"https://desk.example/mcp","headers":[{"name":"X-Desk-Key"}]}]}`
	for _, tc := range []struct {
		name, in string
		o        ImportOptions
		want     func(s RegistryServer) bool
		notes    []string
		err      string
	}{
		{"registry response, npm", playwright, ImportOptions{}, func(s RegistryServer) bool {
			return s.ID == "playwright-mcp" && s.RegistryName == "io.github.microsoft/playwright-mcp" && s.Version == "0.0.82" &&
				slices.Equal(s.Resolved().Command, []string{"npx", "-y", "@playwright/mcp@0.0.82"})
		}, []string{"set rings"}, ""},
		{"pypi with args, env and a skipped nuget", both, ImportOptions{}, func(s RegistryServer) bool {
			return s.ID == "ticket-desk" && slices.Equal(s.Resolved().Command, []string{"uvx", "ticket-desk==2.1.0", "serve"})
		}, []string{"nuget", "--token", "DESK_TOKEN"}, ""},
		{"remote", both, ImportOptions{Remote: true, ID: "desk"}, func(s RegistryServer) bool {
			return s.ID == "desk" && s.URL == "https://desk.example/mcp" && s.Package == nil
		}, []string{"sse", "X-Desk-Key"}, ""},
		{"oci needs a digest", `{"name":"io.example/img","version":"1.0.0","packages":[{"registryType":"oci","identifier":"ghcr.io/acme/img:1.0.0","transport":{"type":"stdio"}}]}`,
			ImportOptions{}, nil, nil, "--sha256"},
		{"oci pinned by digest", `{"name":"io.example/img","version":"1.0.0","packages":[{"registryType":"oci","identifier":"ghcr.io/acme/img:1.0.0","transport":{"type":"stdio"}}]}`,
			ImportOptions{SHA256: sha}, func(s RegistryServer) bool {
				return slices.Equal(s.Resolved().Command, []string{"docker", "run", "-i", "--rm", "ghcr.io/acme/img@" + sha}) && s.Package.Version == "1.0.0"
			}, nil, ""},
		{"npm range", `{"name":"a/b","version":"1","packages":[{"registryType":"npm","identifier":"b","version":"^1.0.0","transport":{"type":"stdio"}}]}`,
			ImportOptions{}, nil, nil, "not an exact version"},
		{"templated remote", `{"name":"a/b","version":"1","remotes":[{"type":"streamable-http","url":"https://{tenant}.example/mcp"}]}`,
			ImportOptions{}, nil, nil, "template"},
		{"plain http remote", `{"name":"a/b","version":"1","remotes":[{"type":"streamable-http","url":"http://b.example/mcp"}]}`,
			ImportOptions{}, nil, nil, "https"},
		{"no version", `{"name":"a/b"}`, ImportOptions{}, nil, nil, "name and version"},
		{"bad id", playwright, ImportOptions{ID: "Play_wright"}, nil, nil, "--id"},
		{"not json", `nope`, ImportOptions{}, nil, nil, "server.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, notes, err := ImportServerJSON([]byte(tc.in), tc.o)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want ~%q", err, tc.err)
				}
				return
			}
			if err != nil || !tc.want(s) {
				t.Fatalf("got %+v (package %+v), %v", s, s.Package, err)
			}
			for _, n := range tc.notes {
				if !slices.ContainsFunc(notes, func(x string) bool { return strings.Contains(x, n) }) {
					t.Errorf("notes %v lack %q", notes, n)
				}
			}
		})
	}
}
