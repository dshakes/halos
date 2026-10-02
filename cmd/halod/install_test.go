package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/release"
)

// ADR-0008 (8f): artifact downloads refuse redirects to non-https URLs and
// bodies larger than the declared size.
func TestDownloadRefusals(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, plain.URL, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer tls.Close()
	a := &Agent{Download: tls.Client()}

	tests := []struct {
		name string
		art  release.Artifact
		want string
	}{
		{"redirect to http", release.Artifact{URL: tls.URL + "/redir"}, "refusing redirect"},
		{"body exceeds declared size", release.Artifact{URL: tls.URL + "/big", Size: 10}, "size 11, want 10"},
		{"ok", release.Artifact{URL: tls.URL + "/big", Size: 100}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := a.download(t.Context(), tc.art, filepath.Join(t.TempDir(), "art"))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
