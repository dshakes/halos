package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/dshakes/halos/internal/server"
)

// serverCredential is the halo-server credential from the environment, never
// a flag: HALO_TOKEN (a service-account API token, ADR-0036) wins over
// HALO_SESSION (a halo_session cookie value copied from a browser).
func serverCredential() string {
	if t := strings.TrimSpace(os.Getenv("HALO_TOKEN")); t != "" {
		return t
	}
	return strings.TrimSpace(os.Getenv("HALO_SESSION"))
}

// authorize attaches cred to req: a service-account token as a bearer
// token, anything else as the halo_session cookie.
func authorize(req *http.Request, cred string) {
	if strings.HasPrefix(cred, server.ServiceTokenPrefix) {
		req.Header.Set("Authorization", "Bearer "+cred)
		return
	}
	req.AddCookie(&http.Cookie{Name: "halo_session", Value: cred}) //nolint:gosec // outgoing request cookie; Secure/HttpOnly only apply to Set-Cookie
}
