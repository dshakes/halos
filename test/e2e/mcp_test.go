//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/halos-dev/halos/internal/policy"
)

// TestMCPServe drives `halo mcp serve` over stdio with the MCP Go SDK client.
func TestMCPServe(t *testing.T) {
	pol := filepath.Join(t.TempDir(), "policy")
	newPolicy(t, pol)
	org, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	sess, err := c.Connect(ctx, &mcp.CommandTransport{Command: exec.Command(filepath.Join(binDir, "halo"), "mcp", "serve", "--policy-dir", pol)}, nil)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer sess.Close()
	if got := sess.InitializeResult().ServerInfo.Name; got != "halos" {
		t.Fatalf("server name %q", got)
	}

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tl := range tools.Tools {
		have[tl.Name] = true
	}
	for _, want := range []string{"validate", "whoami"} {
		if !have[want] {
			t.Fatalf("tools/list lacks %q: %v", want, have)
		}
	}
	if have["propose_rollback"] {
		t.Fatal("write tool exposed without --allow-writes")
	}

	call := func(name string, args map[string]any, out any) {
		t.Helper()
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.IsError {
			b, _ := json.Marshal(res.Content)
			t.Fatalf("%s returned a tool error: %s", name, b)
		}
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s structured content %s: %v", name, b, err)
		}
	}
	var v struct {
		OK     bool
		Errors int
	}
	call("validate", map[string]any{}, &v)
	if !v.OK || v.Errors != 0 {
		t.Fatalf("validate: %+v", v)
	}
	user := usersByRing(t, org)["ring0-canary"]
	var who struct{ User, Ring, Profile string }
	call("whoami", map[string]any{"user": user}, &who)
	if who.User != user || who.Ring != "ring0-canary" || who.Profile != "base" {
		t.Fatalf("whoami: %+v", who)
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "whoami", Arguments: map[string]any{}})
	if err == nil && !res.IsError {
		t.Fatal("whoami without user succeeded")
	}
}
