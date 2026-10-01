package identitytest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCodeFlowPKCE(t *testing.T) {
	iss, err := NewIssuer("k1")
	if err != nil {
		t.Fatal(err)
	}
	srv := iss.Serve()
	defer srv.Close()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := "verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	authorize := func() url.Values {
		t.Helper()
		q := url.Values{"response_type": {"code"}, "client_id": {"portal"}, "redirect_uri": {"http://app/cb"}, "state": {"st"},
			"nonce": {"n1"}, "code_challenge": {b64(sum[:])}, "code_challenge_method": {"S256"}}
		resp, err := noRedirect.Get(iss.URL + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc.Host != "app" || loc.Query().Get("state") != "st" {
			t.Fatalf("authorize: %s -> %s", resp.Status, loc)
		}
		return loc.Query()
	}
	exchange := func(code, v string) (int, map[string]any) {
		t.Helper()
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://app/cb"}, "code_verifier": {v}, "client_id": {"portal"}}
		resp, err := http.Post(iss.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	if q := authorize(); q.Get("error") != "access_denied" {
		t.Fatalf("no SetLogin: want access_denied, got %v", q)
	}
	iss.SetLogin(map[string]any{"email": "a@x"})
	code := authorize().Get("code")
	if st, m := exchange(code, "wrong-verifier"); st != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("bad verifier: %d %v", st, m)
	}
	code = authorize().Get("code")
	st, m := exchange(code, verifier)
	idt, _ := m["id_token"].(string)
	if st != 200 || idt == "" {
		t.Fatalf("exchange: %d %v", st, m)
	}
	parts := strings.Split(idt, ".")
	var claims map[string]any
	if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil || json.Unmarshal(raw, &claims) != nil {
		t.Fatalf("id_token payload: %v", err)
	}
	if claims["nonce"] != "n1" || claims["aud"] != "portal" || claims["email"] != "a@x" || claims["iss"] != iss.URL {
		t.Fatalf("claims %v", claims)
	}
	if st, _ := exchange(code, verifier); st != 400 {
		t.Fatalf("code reuse: %d", st)
	}
}
