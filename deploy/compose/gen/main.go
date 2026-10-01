// Command gen renders kong.yml from policy.json: go run ./deploy/compose/gen
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dshakes/halos/internal/gateway/kong"
	"github.com/dshakes/halos/internal/policy"
)

func main() {
	dir := "deploy/compose/"
	b, err := os.ReadFile(dir + "policy.json")
	if err != nil {
		fail(err)
	}
	var org policy.Org
	if err := json.Unmarshal(b, &org); err != nil {
		fail(err)
	}
	out, err := kong.Generate(&org, kong.Options{PolicyPath: "/etc/halos/policy.json", ShadowURL: "http://halo-shadow:8090/mirror",
		AllowHTTP: true}) // compose Kong listens on plain http; token comes from HALO_SHADOW_TOKEN (env vault)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(dir+"kong.yml", out, 0o644); err != nil {
		fail(err)
	}
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
