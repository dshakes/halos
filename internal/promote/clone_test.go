package promote

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSyncClone(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	tests := []struct {
		name      string
		top       string
		failOn    string
		wantErr   string
		wantCalls []string
	}{
		{name: "ok", top: root, wantCalls: []string{"rev-parse --show-toplevel", "fetch origin main", "checkout -f -B main origin/main", "clean -fd"}},
		{name: "not root", top: other, wantErr: "not a git work tree root", wantCalls: []string{"rev-parse --show-toplevel"}},
		{name: "not a repo", failOn: "rev-parse", wantErr: "policy clone", wantCalls: []string{"rev-parse --show-toplevel"}},
		{name: "fetch fails", top: root, failOn: "fetch", wantErr: "fetch", wantCalls: []string{"rev-parse --show-toplevel", "fetch origin main"}},
		{name: "checkout fails", top: root, failOn: "checkout", wantErr: "reset policy clone", wantCalls: []string{"rev-parse --show-toplevel", "fetch origin main", "checkout -f -B main origin/main"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			run := func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
				calls = append(calls, strings.Join(args, " "))
				if args[0] == tc.failOn {
					return nil, errors.New("boom")
				}
				return []byte(tc.top + "\n"), nil
			}
			err := SyncClone(context.Background(), run, root, "main")
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err=%v want %q", err, tc.wantErr)
			}
			if !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Fatalf("calls=%q want %q", calls, tc.wantCalls)
			}
		})
	}
}
