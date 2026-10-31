package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/promote"
)

func TestForgeFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		kind string
		err  string
	}{
		{nil, promote.ForgeAuto, ""},
		{[]string{"--forge", "gitlab", "--forge-base-url", "https://gitlab.corp/api/v4"}, promote.ForgeGitLab, ""},
		{[]string{"--forge", "GitHub"}, promote.ForgeGitHub, ""},
		{[]string{"--forge", "bitbucket"}, "", "unknown forge"},
		{[]string{"--forge", "gitlab", "--forge-base-url", "http://gitlab.corp/api/v4"}, "", "loopback"},
	} {
		var fg forgeFlags
		c := &cobra.Command{Use: "x"}
		fg.add(c)
		if err := c.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		f, err := fg.forge()
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%v: err = %v, want %q", tc.args, err, tc.err)
			}
			continue
		}
		if err != nil || f.Kind != tc.kind {
			t.Errorf("%v: %+v %v", tc.args, f, err)
		}
	}
}
