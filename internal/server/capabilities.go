package server

import (
	"net/http"
	"net/url"
	"strings"
)

// routeRegistered reports whether m has a method-specific route for method+path
// (the "/api/" and "/" catch-alls do not count).
func routeRegistered(m *http.ServeMux, method, path string) bool {
	_, pat := m.Handler(&http.Request{Method: method, URL: &url.URL{Path: path}})
	return strings.HasPrefix(pat, method+" ")
}

// capabilities (GET /api/v1/capabilities) tells the console which optional
// endpoints this build serves, so it never has to probe them with a real POST
// (an OPTIONS probe cannot tell, the "/api/" catch-all answers 404 for everything).
func (s *Server) capabilities(m *http.ServeMux) authedHandler {
	return func(w http.ResponseWriter, _ *http.Request, _ Principal) {
		writeJSON(w, http.StatusOK, map[string]bool{
			// Registered is not enough: without a signing key nothing reaches gateways.
			"killSwitch": s.cfg.KillKey != nil && routeRegistered(m, http.MethodPost, "/api/v1/experiments/x/kill"),
		})
	}
}
