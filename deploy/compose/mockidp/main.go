// Command mockidp is a demo OIDC issuer standing in for Okta/Entra/Keycloak:
// it serves discovery + JWKS and mints signed JWTs at GET /token. DEMO ONLY:
// /token hands a token to anyone. halo-kong / halo-proxy verify these tokens
// exactly as they would a real IdP's, so client-supplied headers never matter.
//
//	curl 'localhost:8081/token?user=alice@acme.com&groups=ai-platform,eng'
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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
	mux := http.NewServeMux()
	mux.Handle("/", iss.Handler())
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
	log.Printf("mockidp issuer=%s audience=%s", issuer, aud) //nolint:gosec // dev mock logging its own env config
	log.Fatal((&http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
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
