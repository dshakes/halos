//go:build !webdist

// Package web exposes the built console. Build with `-tags webdist` after `npm run build`.
package web

import "io/fs"

// Dist reports no embedded console; the server serves a placeholder page.
func Dist() (fs.FS, bool) { return nil, false }
