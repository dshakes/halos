// Command uatidp is the mock OIDC issuer for `make uat-k8s`: discovery, JWKS,
// auth-code+PKCE (/authorize auto-approves the identity set by PUT /_uat/login)
// and GET /mint, which hands out a gateway JWT for any user. TEST ONLY: it runs
// inside the throwaway kind cluster and is never shipped.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
)

func main() {
	issuer, aud := os.Getenv("ISSUER"), os.Getenv("AUDIENCE")
	if issuer == "" || aud == "" {
		log.Fatal("ISSUER and AUDIENCE are required")
	}
	iss, err := identitytest.NewIssuer("uat-1")
	if err != nil {
		log.Fatal(err)
	}
	iss.URL = issuer
	mux := http.NewServeMux()
	mux.Handle("/", iss.Handler())
	mux.HandleFunc("GET /mint", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		claims := map[string]any{"aud": aud, "email": q.Get("user"), "groups": split(q.Get("groups"))}
		if a := q.Get("aud"); a != "" {
			claims["aud"] = a
		}
		tok, err := iss.Mint(claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, tok)
	})
	// The identity /authorize approves next (portal login); "null" makes it refuse.
	mux.HandleFunc("PUT /_uat/login", func(w http.ResponseWriter, r *http.Request) {
		var claims map[string]any
		if err := json.NewDecoder(r.Body).Decode(&claims); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		iss.SetLogin(claims)
	})
	log.Printf("uatidp issuer=%s audience=%s", issuer, aud) //nolint:gosec // test mock logging its own env config
	log.Fatal((&http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

func split(s string) []string {
	out := []string{}
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
