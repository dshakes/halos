package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/identity/identitytest"
)

// The demo login: discovery advertises the browser-facing /authorize, no user=
// shows the picker, user= auto-approves and redirects back with a code.
func TestDemoLogin(t *testing.T) {
	iss, err := identitytest.NewIssuer("t")
	if err != nil {
		t.Fatal(err)
	}
	iss.URL = "http://mock-idp:8080"
	srv := httptest.NewServer(handler(iss, "aud", "http://localhost:18081"))
	defer srv.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := c.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc["authorization_endpoint"] != "http://localhost:18081/authorize" || doc["issuer"] != "http://mock-idp:8080" || doc["token_endpoint"] != "http://mock-idp:8080/token" {
		t.Fatalf("discovery: %v", doc)
	}

	q := url.Values{"response_type": {"code"}, "client_id": {"halos-portal"}, "redirect_uri": {"http://localhost:18080/auth/callback"},
		"state": {"s1"}, "code_challenge": {"x"}, "code_challenge_method": {"S256"}}
	resp, err = c.Get(srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "alice@acme.com") {
		t.Fatalf("picker: %d %s", resp.StatusCode, b)
	}

	q.Set("user", "alice@acme.com")
	resp, err = c.Get(srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Host != "localhost:18080" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "s1" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}
}
