package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudAgentsConfig(t *testing.T) {
	dir := t.TempDir()
	file := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	long := strings.Repeat("s", 32)
	tests := []struct {
		name    string
		o       options
		secrets int
		err     string
	}{
		{"off", options{}, 0, ""},
		{"one secret", options{cloudWebhookSecretFile: file("one", long+"\n")}, 1, ""},
		{"rotation", options{cloudWebhookSecretFile: file("two", "# old then new\n"+long+"\n"+long+"x\n")}, 2, ""},
		{"three", options{cloudWebhookSecretFile: file("three", long+"\n"+long+"a\n"+long+"b\n")}, 0, "two while rotating"},
		{"short", options{cloudWebhookSecretFile: file("short", "abc\n")}, 0, "at least 16"},
		{"empty", options{cloudWebhookSecretFile: file("empty", "\n")}, 0, "want one secret"},
		{"missing file", options{cloudGitHubTokenFile: filepath.Join(dir, "nope")}, 0, "--cloud-github-token-file"},
		{"http base", options{cloudGitHubTokenFile: file("gh", "t"), cloudGitHubBaseURL: "http://api.example.com"}, 0, "must be https"},
		{"clients", options{cloudGitHubTokenFile: file("gh2", "t"), cloudCursorTokenFile: file("cu", "k"), cloudCursorUser: "bob"}, 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secrets, cl, err := cloudAgentsConfig(tc.o)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(secrets) != tc.secrets {
				t.Fatalf("%d secrets", len(secrets))
			}
			if tc.name == "clients" && (cl.GitHub == nil || cl.Cursor == nil || cl.CursorUser != "bob") {
				t.Fatalf("clients %+v", cl)
			}
		})
	}
}
