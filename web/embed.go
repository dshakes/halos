//go:build webdist

// Package web exposes the built console. Build with `-tags webdist` after `npm run build`.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built console; ok is false when it is not embedded.
func Dist() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	return sub, err == nil
}
