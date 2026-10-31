package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// These tests keep api/openapi.yaml honest. The file is generated from this
// package (OpenAPI), so the checks here are the ones a generator cannot make
// for itself: that the route table matches what the mux serves, that the
// permissions match routePerms, that examples decode into the Go types, that
// the document is valid OpenAPI 3.1, and that real handlers answer what the
// document says. Run them after adding or changing a route:
//
//	go test ./internal/server -run OpenAPI
const (
	specFile   = "../../api/openapi.yaml"
	docsCopy   = "../../docs/public/openapi.yaml"
	oasSchema  = "testdata/openapi-3.1-schema.json" // https://spec.openapis.org/oas/3.1/schema/2022-10-07 (Apache-2.0), vendored so the check runs offline
	oasSchemaU = "https://spec.openapis.org/oas/3.1/schema/2022-10-07"
	specURL    = "file:///openapi.json"
)

// catchAlls are mux patterns that are not operations: they answer unknown
// paths (404 JSON), the console's files and unknown SCIM endpoints.
var catchAlls = []string{"/api/", "/", "/scim/v2/"}

func loadSpec(t testing.TB) (raw []byte, doc map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(specFile)
	if err != nil {
		t.Fatalf("%v: run `make openapi`", err)
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not YAML: %v", specFile, err)
	}
	return raw, doc
}

// specOps lists "METHOD /path" -> operation object of doc.
func specOps(t testing.TB, doc map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	paths, _ := doc["paths"].(map[string]any)
	for p, item := range paths {
		for m, op := range item.(map[string]any) {
			out[strings.ToUpper(m)+" "+p] = op.(map[string]any)
		}
	}
	return out
}

func opByRoute(route string) *apiOp {
	for i := range apiOps {
		if apiOps[i].route == route {
			return &apiOps[i]
		}
	}
	return nil
}

func TestOpenAPIFileCurrent(t *testing.T) {
	want, err := OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{specFile, docsCopy} {
		got, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%v: run `make openapi`", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale: run `make openapi` and commit the result", f)
		}
	}
}

// TestOpenAPICoversMux: every pattern the mux registers is an operation in the
// file with the same method and path, and every operation in the file is
// registered. A route added without documentation fails here.
func TestOpenAPICoversMux(t *testing.T) {
	_, doc := loadSpec(t)
	ops := specOps(t, doc)
	m := newEnv(t, nil).s.mux()
	for _, p := range m.patterns {
		if slices.Contains(catchAlls, p) {
			continue
		}
		if _, ok := ops[p]; !ok {
			t.Errorf("%s is registered but not in %s: add it to apiOps (internal/server/openapi_ops.go) and run `make openapi`", p, specFile)
		}
	}
	for r := range ops {
		if !slices.Contains(m.patterns, r) {
			t.Errorf("%s is in %s but no such route is registered", r, specFile)
		}
	}
	seen := map[string]bool{}
	for _, o := range apiOps {
		if seen[o.route] {
			t.Errorf("apiOps documents %s twice", o.route)
		}
		seen[o.route] = true
	}
}

// TestOpenAPIPermissions: x-halo-permission is exactly routePerms, absent on
// routes outside it, and x-halo-roles is exactly rolePerms.
func TestOpenAPIPermissions(t *testing.T) {
	_, doc := loadSpec(t)
	for route, op := range specOps(t, doc) {
		got, has := op["x-halo-permission"].(string)
		want, guarded := routePerms[route]
		switch {
		case guarded && (!has || got != string(want)):
			t.Errorf("%s: x-halo-permission %q, routePerms says %q", route, got, want)
		case !guarded && has:
			t.Errorf("%s: x-halo-permission %q but the route is not in routePerms", route, got)
		}
		sec, _ := op["security"].([]any)
		if guarded != (len(sec) == 2 && secName(sec[0]) == "sessionCookie" && secName(sec[1]) == "serviceToken") {
			t.Errorf("%s: security %v does not match routePerms membership (%v)", route, sec, guarded)
		}
		if st := op["x-halo-stability"]; st != "stable" {
			t.Errorf("%s: x-halo-stability %v", route, st)
		}
	}
	for route := range routePerms {
		if _, ok := specOps(t, doc)[route]; !ok {
			t.Errorf("routePerms has %s but the spec does not", route)
		}
	}
	roles, _ := doc["x-halo-roles"].(map[string]any)
	if !reflect.DeepEqual(normalize(t, roles), normalize(t, rolePermsDoc())) {
		t.Errorf("x-halo-roles %v differs from rolePerms %v", roles, rolePermsDoc())
	}
}

func secName(v any) string {
	for k := range v.(map[string]any) {
		return k
	}
	return ""
}

func normalize(t testing.TB, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// example returns the example of the body under content[ct] in a request body
// or response object, or nil.
func exampleOf(obj any) (ex any, ct string, ok bool) {
	content, _ := obj.(map[string]any)["content"].(map[string]any)
	for c, mt := range content {
		if e, has := mt.(map[string]any)["example"]; has {
			return e, c, true
		}
	}
	return nil, "", false
}

func strictDecodes(b []byte, typ any) error {
	v := reflect.New(reflect.TypeOf(typ))
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v.Interface())
}

// TestOpenAPIExamples: every JSON example in the file decodes, strictly (an
// unknown field fails), into the Go type the handler uses, and validates
// against the schema generated for it. Stable operations must carry an
// example on every typed JSON success response and request body.
func TestOpenAPIExamples(t *testing.T) {
	_, doc := loadSpec(t)
	sc := specCompiler(t, doc)
	n := 0
	for route, op := range specOps(t, doc) {
		o := opByRoute(route)
		if o == nil {
			continue // TestOpenAPICoversMux reports it
		}
		check := func(what string, obj any, b *body) {
			if b == nil {
				return
			}
			ex, ct, has := exampleOf(obj)
			typed := (b.typ != nil || len(b.one) > 0) && strings.Contains(cmpOr(b.ct, "application/json"), "json")
			if !has {
				if typed && !isLoose(b.typ) && !slices.Contains(noExample, route) {
					t.Errorf("%s %s: stable operations need an example", route, what)
				}
				return
			}
			if !strings.Contains(ct, "json") {
				return
			}
			raw, err := json.Marshal(ex)
			if err != nil {
				t.Fatal(err)
			}
			alts := b.one
			if b.typ != nil {
				alts = []any{b.typ}
			}
			var errs []string
			ok := len(alts) == 0
			for _, a := range alts {
				if err := strictDecodes(raw, a); err != nil {
					errs = append(errs, err.Error())
					continue
				}
				ok = true
			}
			if !ok {
				t.Errorf("%s %s: example does not decode into %T: %s\n%s", route, what, alts[0], strings.Join(errs, "; "), raw)
			}
			n++
		}
		if rb, ok := op["requestBody"]; ok {
			check("request", rb, o.req)
		}
		resps, _ := op["responses"].(map[string]any)
		for _, r := range o.ok {
			if resp, ok := resps[strconv.Itoa(r.code)]; ok {
				b := r.body
				check("response "+strconv.Itoa(r.code), resp, &b)
			}
		}
		// And against the generated schema.
		for code, resp := range resps {
			if ex, ct, has := exampleOf(resp); has && strings.Contains(ct, "json") {
				validateAt(t, sc, schemaPtr(route, "responses/"+code, ct), ex, route+" response "+code+" example")
			}
		}
		if rb, ok := op["requestBody"]; ok {
			if ex, ct, has := exampleOf(rb); has && strings.Contains(ct, "json") {
				validateAt(t, sc, schemaPtr(route, "requestBody", ct), ex, route+" request example")
			}
		}
	}
	if n < 40 {
		t.Fatalf("only %d examples checked; the walk is broken", n)
	}
}

// noExample lists operations whose bodies embed policy or controller documents
// too large to maintain by hand as examples. TestOpenAPILiveConformance
// validates their real responses against the schema instead.
var noExample = []string{
	"GET /api/v1/experiments", "GET /api/v1/experiments/{name}", "GET /api/v1/freeze", "GET /api/v1/harnesses", "GET /api/v1/policy",
	"GET /api/v1/rollouts", "GET /api/v1/rollouts/{name}", "GET /api/v1/rollouts/{name}/approvals", "GET /api/v1/toggles/{name}",
	"POST /api/v1/rollouts/{name}/approve",
}

// isLoose: bodies whose schema is deliberately open (maps of any), where an
// example would add nothing.
func isLoose(typ any) bool {
	if typ == nil {
		return false
	}
	t := reflect.TypeOf(typ)
	return t.Kind() == reflect.Map && t.Elem().Kind() == reflect.Interface
}

// specCompiler registers the spec as a schema resource so a JSON pointer into
// it (a media type's schema) can be compiled and validated against.
func specCompiler(t testing.TB, doc map[string]any) *jsonschema.Compiler {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(specJSON(t, doc)))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(specURL, inst); err != nil {
		t.Fatal(err)
	}
	return c
}

func specJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var ptrEsc = strings.NewReplacer("~", "~0", "/", "~1")

// schemaPtr is the URL of the schema of content[ct] under paths[route's path][method]/<sub>.
func schemaPtr(route, sub, ct string) string {
	method, path, _ := strings.Cut(route, " ")
	frag := "/paths/" + ptrEsc.Replace(path) + "/" + strings.ToLower(method) + "/" + sub + "/content/" + ptrEsc.Replace(ct) + "/schema"
	return specURL + "#" + (&url.URL{Fragment: frag}).EscapedFragment()
}

func validateAt(t testing.TB, c *jsonschema.Compiler, loc string, v any, what string) {
	t.Helper()
	sch, err := c.Compile(loc)
	if err != nil {
		t.Errorf("%s: compile %s: %v", what, loc, err)
		return
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(specJSON(t, v)))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("%s does not match its schema: %v", what, err)
	}
}

// TestOpenAPIValid: the file is valid OpenAPI 3.1, checked against the
// vendored OpenAPI 3.1 schema, and the check can fail (a mutated copy is rejected).
func TestOpenAPIValid(t *testing.T) {
	f, err := os.Open(oasSchema)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	meta, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(oasSchemaU, meta); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(oasSchemaU)
	if err != nil {
		t.Fatalf("compile the OpenAPI 3.1 schema: %v", err)
	}
	_, doc := loadSpec(t)
	validate := func(d map[string]any) error {
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(specJSON(t, d)))
		if err != nil {
			t.Fatal(err)
		}
		return sch.Validate(inst)
	}
	if err := validate(doc); err != nil {
		t.Fatalf("%s is not valid OpenAPI 3.1: %v", specFile, err)
	}
	// Negative controls: the validator rejects a broken document.
	bad := normalize(t, doc).(map[string]any)
	delete(bad, "info")
	if validate(bad) == nil {
		t.Error("a document without info passed validation: the check is not effective")
	}
	bad = normalize(t, doc).(map[string]any)
	bad["paths"].(map[string]any)["/healthz"].(map[string]any)["get"].(map[string]any)["responses"] = 7
	if validate(bad) == nil {
		t.Error("a document with a non-object responses passed validation: the check is not effective")
	}
	// Every $ref in the file resolves, and every operation id is unique.
	ids := map[string]string{}
	for route, op := range specOps(t, doc) {
		id, _ := op["operationId"].(string)
		if id == "" || ids[id] != "" {
			t.Errorf("%s: operationId %q is empty or already used by %s", route, id, ids[id])
		}
		ids[id] = route
	}
	checkRefs(t, doc, doc)
}

func checkRefs(t testing.TB, root map[string]any, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		if r, ok := x["$ref"].(string); ok {
			cur := any(root)
			for _, seg := range strings.Split(strings.TrimPrefix(r, "#/"), "/") {
				m, _ := cur.(map[string]any)
				if cur = m[strings.NewReplacer("~1", "/", "~0", "~").Replace(seg)]; cur == nil {
					t.Errorf("dangling $ref %s", r)
					break
				}
			}
		}
		for _, c := range x {
			checkRefs(t, root, c)
		}
	case []any:
		for _, c := range x {
			checkRefs(t, root, c)
		}
	}
}

// TestOpenAPIServed: the server serves the file, unauthenticated, read-only.
func TestOpenAPIServed(t *testing.T) {
	e := newEnv(t, nil)
	raw, _ := loadSpec(t)
	w := e.as(Principal{}, "GET", "/api/v1/openapi.yaml", "")
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), raw) {
		t.Fatalf("GET /api/v1/openapi.yaml: %d, %d bytes (want the %d bytes of %s)", w.Code, w.Body.Len(), len(raw), specFile)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Errorf("content type %q", ct)
	}
	if w := e.as(Principal{}, "POST", "/api/v1/openapi.yaml", "{}"); w.Code == http.StatusOK {
		t.Errorf("POST /api/v1/openapi.yaml answered 200")
	}
}

// TestOpenAPILiveConformance calls every documented operation against a real
// server and holds the answer to the document: the status must be one the
// operation lists, and a JSON body must match that status's schema. Requests
// carry the operation's own example, so a request body that stops decoding
// shows up as an undocumented 400. This is what pins the hand-written wire
// shapes (openapi_ops.go) to the handlers.
//
// Two passes: the first only reads, on a server with no data beyond one
// enrolled device, so every empty list must encode as [] and never null;
// the second runs every operation, mutations included (SCIM objects are
// created before they are read, replaced and deleted).
func TestOpenAPILiveConformance(t *testing.T) {
	_, doc := loadSpec(t)
	sc := specCompiler(t, doc)
	ops := specOps(t, doc)
	routes := make([]string, 0, len(ops))
	for r := range ops {
		routes = append(routes, r)
	}
	rank := map[string]int{"GET": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}
	sort.Slice(routes, func(i, j int) bool {
		mi, _, _ := strings.Cut(routes[i], " ")
		mj, _, _ := strings.Cut(routes[j], " ")
		if rank[mi] != rank[mj] {
			return rank[mi] < rank[mj]
		}
		return routes[i] < routes[j]
	})
	for _, pass := range []struct {
		name     string
		readOnly bool
		min2xx   int
	}{{"empty state, reads only", true, 40}, {"all operations", false, 70}} {
		t.Run(pass.name, func(t *testing.T) {
			liveWalk(t, doc, sc, ops, routes, pass.readOnly, pass.min2xx)
		})
	}
}

func liveWalk(t *testing.T, doc map[string]any, sc *jsonschema.Compiler, ops map[string]map[string]any, routes []string, readOnly bool, min2xx int) {
	_, killKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const gw = "gateway-token-0123456789-0123456789-0123456789"
	e := newEnv(t, func(c *Config) {
		c.KillKey, c.GatewayToken, c.SCIMTokenSHA256 = killKey, gw, []string{sha256Hex(scimTok)}
	})
	org, _, err := e.s.pol.Get()
	if err != nil || org == nil {
		t.Fatalf("policy: %v", err)
	}
	devTok, device, err := e.s.devices.mint(dev, *e.now)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{"experiments": org.Experiments[0].Name, "toggles": org.Toggles[0].Name, "rollouts": org.Rollouts[0].Name}
	// Provision the device's user, or the device is refused ("not provisioned") once SCIM is on.
	if w := e.scim("POST", "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+dev.ID+`","active":true}`); w.Code != http.StatusCreated {
		t.Fatalf("provision %s: %d %s", dev.ID, w.Code, w.Body.String())
	}
	ids := map[string]string{"/scim/v2/Users/": "x", "/scim/v2/Groups/": "x", "/api/v1/devices/": device.ID,
		"/scim/v2/ResourceTypes/": "User", "/scim/v2/Schemas/": "urn:ietf:params:scim:schemas:core:2.0:User"}
	hits := map[string][]int{}
	for _, route := range routes {
		op := ops[route]
		method, path, _ := strings.Cut(route, " ")
		if readOnly && method != "GET" {
			continue
		}
		for _, kind := range []string{"experiments", "toggles", "rollouts"} {
			path = strings.Replace(path, "/"+kind+"/{name}", "/"+kind+"/"+names[kind], 1)
		}
		for prefix, id := range ids {
			path = strings.Replace(path, prefix+"{id}", prefix+id, 1)
		}
		path = strings.NewReplacer("{id}", "x", "{launcher}", "laptop", "{name}", "x").Replace(path)
		payload, ct := "", "application/json"
		if rb, ok := op["requestBody"]; ok {
			if ex, c, has := exampleOf(rb); has {
				ct = c
				if s, isStr := ex.(string); isStr {
					payload = s
				} else {
					payload = string(specJSON(t, ex))
				}
			} else {
				payload = "{}"
			}
		}
		if route == "POST /api/v1/requests" { // the example names a ring the fixture may not offer as opt-in
			payload = `{"kind":"ring-opt-in","item":"` + optInRing(t, e) + `","justification":"please"}`
		}
		if q, _ := op["parameters"].([]any); q != nil {
			vals := url.Values{}
			for _, p := range q {
				pm := p.(map[string]any)
				if pm["in"] == "query" && (pm["required"] == true || pm["name"] == "subject") {
					vals.Set(pm["name"].(string), "dev@acme.example")
				}
			}
			if len(vals) > 0 {
				path += "?" + vals.Encode()
			}
		}
		r := httptest.NewRequest(method, path, strings.NewReader(payload))
		r.Header.Set("Content-Type", ct)
		sec, _ := op["security"].([]any)
		switch {
		case len(sec) == 2 && secName(sec[0]) == "sessionCookie":
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Add(3600e9).Unix()})})
		case len(sec) == 1 && secName(sec[0]) == "gatewayToken":
			r.Header.Set("Authorization", "Bearer "+gw)
		case len(sec) == 2 && secName(sec[0]) == "fleetToken":
			r.Header.Set("Authorization", "Bearer "+tok)
		case len(sec) == 1 && secName(sec[0]) == "deviceToken":
			r.Header.Set("Authorization", "Bearer "+devTok)
		case len(sec) == 1 && secName(sec[0]) == "scimToken":
			r.Header.Set("Authorization", "Bearer "+scimTok)
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)

		resps, _ := op["responses"].(map[string]any)
		code := strconv.Itoa(w.Code)
		resp, ok := resps[code].(map[string]any)
		if !ok {
			t.Errorf("%s answered %d, which the spec does not list (%v): %.200s", route, w.Code, keys(resps), w.Body.String())
			continue
		}
		hits[route] = append(hits[route], w.Code)
		if w.Code >= 400 && strings.HasPrefix(path, "/scim/v2/") && method == "POST" {
			t.Logf("DEBUG %s %d %s", route, w.Code, w.Body.String())
		}
		if method == "POST" && w.Code == http.StatusCreated { // later operations on {id} use what this one made
			var created struct {
				ID           string
				ServiceToken struct{ ID string }
			}
			_ = json.Unmarshal(w.Body.Bytes(), &created)
			ids[path+"/"] = cmpOr(created.ID, created.ServiceToken.ID)
		}
		loc := func(c string) string { return schemaPtr(route, "responses/"+code, c) }
		if ref, isRef := resp["$ref"].(string); isRef { // components/responses/*
			resp, _ = lookup(doc, ref).(map[string]any)
			loc = func(c string) string {
				return specURL + "#" + (&url.URL{Fragment: strings.TrimPrefix(ref, "#") + "/content/" + ptrEsc.Replace(c) + "/schema"}).EscapedFragment()
			}
		}
		content, _ := resp["content"].(map[string]any)
		for c := range content {
			if !strings.Contains(c, "json") || w.Body.Len() == 0 {
				continue
			}
			var body any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Errorf("%s %d: body is not JSON: %v: %.200s", route, w.Code, err, w.Body.String())
				continue
			}
			validateAt(t, sc, loc(c), body, route+" "+code+" body")
		}
	}
	ok2xx := 0
	for _, route := range routes {
		codes := hits[route]
		if slices.ContainsFunc(codes, func(c int) bool { return c/100 == 2 }) {
			ok2xx++
		} else if len(codes) > 0 {
			t.Logf("no success response: %s answered %v", route, codes)
		}
	}
	t.Logf("%d of %d operations answered a 2xx; the rest answered a documented error", ok2xx, len(hits))
	if ok2xx < min2xx {
		t.Errorf("only %d operations reached a success response (want %d): the fixtures are too thin to test the schemas", ok2xx, min2xx)
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lookup(root map[string]any, ref string) any {
	cur := any(root)
	for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, _ := cur.(map[string]any)
		cur = m[seg]
	}
	return cur
}
