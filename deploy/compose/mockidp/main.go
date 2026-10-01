// Command mockidp is a demo OIDC issuer standing in for Okta/Entra/Keycloak:
// it serves discovery + JWKS and mints signed JWTs at GET /token. DEMO ONLY:
// /token hands a token to anyone. halo-kong / halo-proxy verify these tokens
// exactly as they would a real IdP's, so client-supplied headers never matter.
//
//	curl 'localhost:8081/token?user=alice@acme.com&groups=ai-platform,eng'
//
// It also serves an interactive authorization-code login for halo-server's
// console (make demo): GET /authorize without user= shows a demo-user picker;
// with user= it auto-approves that user. PUBLIC_URL, when set, is the
// browser-facing base advertised as authorization_endpoint, while the issuer,
// token and JWKS endpoints stay on ISSUER (the in-network name).
package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
)

func main() {
	issuer := os.Getenv("ISSUER") // must equal identity.issuer in the policy, e.g. http://mock-idp:8080
	aud := os.Getenv("AUDIENCE")
	if issuer == "" || aud == "" {
		log.Fatal("ISSUER and AUDIENCE are required")
	}
	iss, err := identitytest.NewIssuer("demo-1")
	if err != nil {
		log.Fatal(err)
	}
	iss.URL = issuer
	log.Printf("mockidp issuer=%s audience=%s", issuer, aud) //nolint:gosec // dev mock logging its own env config
	h := handler(iss, aud, strings.TrimRight(os.Getenv("PUBLIC_URL"), "/"))
	log.Fatal((&http.Server{Addr: ":8080", Handler: h, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

// handler serves the issuer, the demo login (/authorize) and GET /token.
// pub, when set, is the browser-facing base advertised as authorization_endpoint.
func handler(iss *identitytest.Issuer, aud, pub string) http.Handler {
	inner := iss.Handler()
	mux := http.NewServeMux()
	mux.Handle("/", inner)
	if pub != "" {
		mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			inner.ServeHTTP(rec, r)
			var doc map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			doc["authorization_endpoint"] = pub + "/authorize"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
		})
	}
	var loginMu sync.Mutex // ponytail: one login at a time keeps SetLogin+authorize atomic; fine for a demo IdP
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if user == "" {
			userPicker(w, r.URL.Query())
			return
		}
		groups, ok := demoUsers[user]
		if g := r.URL.Query().Get("groups"); g != "" || !ok {
			groups = splitNonEmpty(g)
		}
		loginMu.Lock()
		defer loginMu.Unlock()
		iss.SetLogin(map[string]any{"email": user, "groups": groups})
		inner.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if user == "" {
			http.Error(w, "user= required", http.StatusBadRequest)
			return
		}
		claims := map[string]any{"aud": aud, "email": user, "groups": splitNonEmpty(r.URL.Query().Get("groups"))}
		tok, err := iss.Mint(claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, tok)
	})
	return mux
}

// demoUsers are the picker's one-click logins; any other user= works with groups=.
var demoUsers = map[string][]string{
	"alice@acme.com":   {"ai-platform"}, // admin, ring0-harness-team
	"bob@acme.com":     {"eng"},         // ring2-early
	"mallory@acme.com": {"eng"},         // ring1-canary
	"dave@acme.com":    {"eng"},         // ring3-ga
}

func userPicker(w http.ResponseWriter, q url.Values) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>Halos demo IdP</title><body style="font-family:sans-serif;max-width:32rem;margin:3rem auto">
<h1>Halos demo IdP</h1><p>DEV ONLY: no passwords. Sign in as:</p><ul>`)
	for _, u := range []string{"alice@acme.com", "bob@acme.com", "mallory@acme.com", "dave@acme.com"} {
		q.Set("user", u)
		fmt.Fprintf(w, `<li><a href="/authorize?%s">%s</a> (%s)</li>`, html.EscapeString(q.Encode()), u, strings.Join(demoUsers[u], ","))
	}
	fmt.Fprint(w, `</ul></body>`)
}

func splitNonEmpty(s string) []string {
	out := []string{}
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
