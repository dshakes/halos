package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// routeRegistered reports whether m has a method-specific route for method+path
// (the "/api/" and "/" catch-alls do not count).
func routeRegistered(m *http.ServeMux, method, path string) bool {
	_, pat := m.Handler(&http.Request{Method: method, URL: &url.URL{Path: path}})
	return strings.HasPrefix(pat, method+" ")
}

// Capabilities is GET /api/v1/capabilities.
type Capabilities struct {
	KillSwitch bool `json:"killSwitch"`
	// Roles and Permissions are the caller's (ADR-0015), so the console hides
	// actions the server would refuse. The server enforces regardless.
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	// Bindings say over which rings and units each role holds (ADR-0037);
	// a permission may hold only for some resources.
	Bindings []policy.Grant `json:"bindings"`
}

// capabilities (GET /api/v1/capabilities) tells the console which optional
// endpoints this build serves, so it never has to probe them with a real POST
// (an OPTIONS probe cannot tell, the "/api/" catch-all answers 404 for everything).
func (s *Server) capabilities(m *http.ServeMux) authedHandler {
	return func(w http.ResponseWriter, _ *http.Request, p Principal) {
		writeJSON(w, http.StatusOK, Capabilities{
			// Registered is not enough: without a signing key nothing reaches gateways.
			KillSwitch:  s.cfg.KillKey != nil && routeRegistered(m, http.MethodPost, "/api/v1/experiments/x/kill"),
			Roles:       p.Roles,
			Permissions: p.permissions(),
			Bindings:    p.Bindings,
		})
	}
}
