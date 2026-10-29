package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ServerJSON is the part of the official MCP Registry's server.json
// (https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json)
// that `halo mcp registry import` reads.
type ServerJSON struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Packages []struct {
		RegistryType string `json:"registryType"`
		Identifier   string `json:"identifier"`
		Version      string `json:"version"`
		Transport    struct {
			Type string `json:"type"`
		} `json:"transport"`
		PackageArguments     []serverJSONArg `json:"packageArguments"`
		RuntimeArguments     []serverJSONArg `json:"runtimeArguments"`
		EnvironmentVariables []struct {
			Name       string `json:"name"`
			IsRequired bool   `json:"isRequired"`
		} `json:"environmentVariables"`
	} `json:"packages"`
	Remotes []struct {
		Type    string `json:"type"`
		URL     string `json:"url"`
		Headers []struct {
			Name string `json:"name"`
		} `json:"headers"`
	} `json:"remotes"`
}

type serverJSONArg struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ImportOptions picks what ImportServerJSON pins.
type ImportOptions struct {
	ID     string // registry id; default derived from the server.json name
	Remote bool   // pin the remote (streamable HTTP) endpoint, not a package
	SHA256 string // image digest, required for an oci package
}

var idCharsRe = regexp.MustCompile(`[^a-z0-9-]+`)

// ImportServerJSON turns a server.json (or a registry API response wrapping
// one in "server") into a pinned registry entry: the remote URL, or the first
// npm, pypi or oci stdio package at its exact version. notes lists what the
// entry does not carry (arguments, environment, headers) and still needs a
// human: rings or units, auth, tools.
func ImportServerJSON(b []byte, o ImportOptions) (s RegistryServer, notes []string, err error) {
	var wrap struct {
		Server *ServerJSON `json:"server"`
	}
	var sj ServerJSON
	if err := json.Unmarshal(b, &wrap); err == nil && wrap.Server != nil {
		sj = *wrap.Server
	} else if err := json.Unmarshal(b, &sj); err != nil {
		return s, nil, fmt.Errorf("server.json: %w", err)
	}
	if sj.Name == "" || sj.Version == "" {
		return s, nil, errors.New("server.json: name and version are required")
	}
	s = RegistryServer{ID: o.ID, RegistryName: sj.Name, Version: sj.Version}
	if s.ID == "" {
		s.ID = strings.Trim(idCharsRe.ReplaceAllString(strings.ToLower(sj.Name[strings.LastIndex(sj.Name, "/")+1:]), "-"), "-")
	}
	if !mcpIDRe.MatchString(s.ID) {
		return s, nil, fmt.Errorf("id %q is not a registry id (lowercase letters, digits, '-'); pass --id", s.ID)
	}
	if o.Remote || len(sj.Packages) == 0 {
		for _, r := range sj.Remotes {
			if r.Type != "streamable-http" {
				notes = append(notes, fmt.Sprintf("remote %s (%s) skipped: only streamable-http is rendered", r.URL, r.Type))
				continue
			}
			if strings.ContainsAny(r.URL, "{}") {
				return s, nil, fmt.Errorf("remote URL %q is a template; set url by hand", r.URL)
			}
			if _, ok := CanonicalResource(r.URL); !ok {
				return s, nil, fmt.Errorf("remote URL %q must be https without query or fragment", r.URL)
			}
			s.URL = r.URL
			for _, h := range r.Headers {
				notes = append(notes, fmt.Sprintf("header %s: set headers.%s to a ${VAR} reference (never a literal secret)", h.Name, h.Name))
			}
			break
		}
		if s.URL == "" {
			return s, notes, errors.New("server.json has no streamable-http remote")
		}
	} else {
		for _, p := range sj.Packages {
			typ := p.RegistryType
			if typ != MCPPackageNPM && typ != MCPPackagePyPI && typ != MCPPackageOCI || p.Transport.Type != "stdio" {
				notes = append(notes, fmt.Sprintf("package %s (%s, %s) skipped: only npm, pypi and oci stdio packages are pinned", p.Identifier, typ, p.Transport.Type))
				continue
			}
			pkg := &MCPPackage{Type: typ, Identifier: p.Identifier, Version: p.Version}
			if typ == MCPPackageOCI {
				ref, tag, _ := strings.Cut(p.Identifier[strings.LastIndex(p.Identifier, "/")+1:], ":")
				pkg.Identifier = p.Identifier[:strings.LastIndex(p.Identifier, "/")+1] + ref
				if pkg.Version == "" {
					pkg.Version = tag
				}
				if !sha256Re.MatchString(o.SHA256) {
					return s, notes, fmt.Errorf("oci package %s: pass --sha256 sha256:<image digest> (a tag can be re-pushed)", p.Identifier)
				}
				pkg.SHA256 = o.SHA256
			} else if !exactVersionRe.MatchString(pkg.Version) {
				return s, notes, fmt.Errorf("package %s version %q is not an exact version", p.Identifier, pkg.Version)
			}
			for _, a := range p.PackageArguments {
				if a.Type == "positional" && a.Value != "" && !strings.ContainsAny(a.Value, "{}") {
					pkg.Args = append(pkg.Args, a.Value)
				} else {
					notes = append(notes, fmt.Sprintf("package argument %q not imported: add it to package.args if needed", a.Name+a.Value))
				}
			}
			if len(p.RuntimeArguments) > 0 {
				notes = append(notes, "runtime arguments not imported: the derived command line is npx/uvx/docker with the pinned version")
			}
			for _, e := range p.EnvironmentVariables {
				if e.IsRequired {
					notes = append(notes, fmt.Sprintf("environment variable %s is required: users set it (Halos never renders secrets)", e.Name))
				}
			}
			s.Package = pkg
			break
		}
		if s.Package == nil {
			return s, notes, errors.New("server.json has no npm, pypi or oci stdio package; try --remote")
		}
	}
	notes = append(notes, "set rings and/or units (none = approved only), and tools/auth if needed")
	return s, notes, nil
}
