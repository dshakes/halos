// Command genopenapi writes the OpenAPI 3.1 description of halo-server's HTTP
// API, generated from internal/server:
//
//	go run ./internal/tools/genopenapi --out api/openapi.yaml --out docs/public/openapi.yaml
//
// Run it from the repo root (`make openapi`). go test ./internal/server fails
// while a written copy differs from what this prints.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dshakes/halos/internal/server"
)

type outs []string

func (o *outs) String() string     { return fmt.Sprint(*o) }
func (o *outs) Set(v string) error { *o = append(*o, v); return nil }

func main() {
	var out outs
	flag.Var(&out, "out", "file to write (repeatable)")
	flag.Parse()
	if len(out) == 0 {
		fmt.Fprintln(os.Stderr, "genopenapi: --out is required")
		os.Exit(2)
	}
	b, err := server.OpenAPI()
	if err != nil {
		fmt.Fprintln(os.Stderr, "genopenapi:", err)
		os.Exit(1)
	}
	for _, f := range out {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "genopenapi:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(f, b, 0o644); err != nil { //nolint:gosec // published docs are world-readable
			fmt.Fprintln(os.Stderr, "genopenapi:", err)
			os.Exit(1)
		}
	}
}
