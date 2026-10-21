package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Auth modes for a fuzzed SCIM request.
const (
	scimFuzzNone    = iota // no credential
	scimFuzzToken          // the SCIM bearer token
	scimFuzzSession        // an admin console session: never a SCIM credential
	scimFuzzWrong          // a wrong bearer token
	scimFuzzModes
)

// FuzzSCIMJSONDecoders drives every SCIM body decoder (create, replace and
// PATCH of users and groups) through the real handler. Properties: no panic,
// no 500, a 2xx only with the SCIM token and a body that is one JSON object,
// every error is a SCIM error document, and the directory stays consistent
// (unique userNames, members are provisioned users).
func FuzzSCIMJSONDecoders(f *testing.F) {
	e := scimEnv(f, true, nil)
	uid := e.createSCIMUser(f, "fuzz@acme.example", true)
	gid := e.createSCIMGroup(f, "fuzz-group", uid)
	paths := []struct{ method, path string }{
		{"POST", "/scim/v2/Users"},
		{"PUT", "/scim/v2/Users/" + uid},
		{"PATCH", "/scim/v2/Users/" + uid},
		{"POST", "/scim/v2/Groups"},
		{"PUT", "/scim/v2/Groups/" + gid},
		{"PATCH", "/scim/v2/Groups/" + gid},
	}
	seeds := map[int][]string{
		0: {`{"userName":"new@acme.example","active":"True","emails":[{"value":"n@acme.example","primary":"true"}]}`, `{"userName":""}`, `{`, ``},
		1: {`{"userName":"fuzz@acme.example","active":false}`, `{"userName":"fuzz@acme.example","name":{"givenName":"F"}}`},
		2: {`{"Operations":[{"op":"Replace","path":"active","value":"False"}]}`, `{"Operations":[{"op":"replace","value":{"active":true}}]}`,
			`{"Operations":[{"op":"Replace","path":"emails[type eq \"work\"].value","value":"x@acme.example"}]}`, `{"Operations":[{"op":"remove","path":"emails[type eq \"w"}]}`},
		3: {`{"displayName":"g2","members":[{"value":"USER"}]}`, `{"displayName":"g3","members":[{"value":"nope"}]}`},
		4: {`{"displayName":"fuzz-group","members":[]}`},
		5: {`{"Operations":[{"op":"Add","path":"members","value":[{"$ref":null,"value":"USER"}]}]}`, `{"Operations":[{"op":"remove","path":"members[value eq \"USER\"]"}]}`,
			`{"Operations":[{"op":"replace","value":{"id":"x","displayName":"renamed"}}]}`, `{"Operations":[{"op":"remove","path":"members[value eq \"x\"]extra"}]}`},
	}
	for ep, bodies := range seeds {
		for _, b := range bodies {
			for mode := range uint8(scimFuzzModes) {
				f.Add(uint8(ep), mode, []byte(b))
			}
		}
	}
	session := e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Add(time.Hour).Unix()})
	f.Fuzz(func(t *testing.T, epi, mode uint8, body []byte) {
		ep := paths[int(epi)%len(paths)]
		mode %= scimFuzzModes
		e.s.authFails.mu.Lock()
		e.s.authFails.m = nil // each input starts with a clean budget
		e.s.authFails.mu.Unlock()
		body = bytes.ReplaceAll(body, []byte("USER"), []byte(uid))
		r := httptest.NewRequest(ep.method, ep.path, bytes.NewReader(body))
		switch mode {
		case scimFuzzToken:
			r.Header.Set("Authorization", "Bearer "+scimTok)
		case scimFuzzSession:
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
		case scimFuzzWrong:
			r.Header.Set("Authorization", "Bearer "+scimTok+"x")
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if w.Code == http.StatusInternalServerError {
			t.Fatalf("%s %s mode %d: 500 %s", ep.method, ep.path, mode, w.Body)
		}
		if mode != scimFuzzToken && w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s mode %d: %d without the SCIM token", ep.method, ep.path, mode, w.Code)
		}
		if w.Code < 300 && !decodeFirst(body, new(map[string]json.RawMessage)) {
			t.Fatalf("%s %s: %d for a body that is not a JSON object: %q", ep.method, ep.path, w.Code, body)
		}
		if w.Code >= 400 {
			var se scimErr
			if json.Unmarshal(w.Body.Bytes(), &se) != nil || len(se.Schemas) != 1 || se.Schemas[0] != scimErrorSchema || se.Status == "" {
				t.Fatalf("%s %s: %d is not a SCIM error: %s", ep.method, ep.path, w.Code, w.Body)
			}
		}
		names := map[string]bool{}
		for _, u := range e.s.scim.store.Users() {
			n := strings.ToLower(u.UserName)
			if names[n] || checkText("userName", u.UserName, true) != nil {
				t.Fatalf("directory corrupted: userName %q", u.UserName)
			}
			names[n] = true
		}
		for _, g := range e.s.scim.store.Groups() {
			for _, m := range g.Members {
				if _, ok := e.s.scim.store.User(m); !ok {
					t.Fatalf("group %q holds unknown member %q", g.DisplayName, m)
				}
			}
		}
	})
}
