package promote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	forgeMaxBody  = 4 << 20 // response cap
	forgeMaxPages = 10      // FindPR scans at most this many pages of 100, newest first
	forgePerPage  = 100
)

// httpAPI is the shared REST plumbing: auth, JSON, size caps and error text.
type httpAPI struct {
	base   string
	hc     *http.Client
	vars   []string // token variables in preference order
	getenv func(string) string
	auth   func(req *http.Request, token string)
	hint   func(status int) string
}

// token returns the first set variable. The error names every variable and
// never contains a value.
func (h *httpAPI) token() (string, error) {
	for _, v := range h.vars {
		if t := strings.TrimSpace(h.getenv(v)); t != "" {
			return t, nil
		}
	}
	return "", fmt.Errorf("promote: forge: no API token: set %s in the environment", strings.Join(h.vars, " or "))
}

// do sends one request. path is appended to the base verbatim (callers pass
// already-escaped segments, so a GitLab project path keeps its %2F). On a 2xx
// the JSON body is decoded into out (when non-nil) and the headers returned.
func (h *httpAPI) do(ctx context.Context, op, method, path string, body, out any) (http.Header, error) {
	tok, err := h.token()
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("promote: %s: %w", op, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, rd)
	if err != nil {
		return nil, fmt.Errorf("promote: %s: bad request URL: %w", op, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "halos")
	h.auth(req, tok)
	resp, err := h.hc.Do(req)
	if err != nil {
		// net/http errors quote the URL, never headers.
		return nil, fmt.Errorf("promote: %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, forgeMaxBody))
	if err != nil {
		return nil, fmt.Errorf("promote: %s: read response: %w", op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, h.statusError(op, resp.StatusCode, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("promote: %s: decode response: %w", op, err)
		}
	}
	return resp.Header, nil
}

func (h *httpAPI) statusError(op string, status int, data []byte) error {
	msg := apiMessage(data)
	e := fmt.Sprintf("promote: %s: HTTP %d", op, status)
	if msg != "" {
		e += ": " + msg
	}
	if hint := h.hint(status); hint != "" {
		e += " (" + hint + ")"
	}
	return fmt.Errorf("%s", e)
}

// apiMessage pulls a short human message out of a GitHub or GitLab error body.
func apiMessage(data []byte) string {
	var m struct {
		Message any    `json:"message"`
		Error   string `json:"error"`
		Errors  []any  `json:"errors"`
		Desc    string `json:"error_description"`
	}
	s := ""
	if json.Unmarshal(data, &m) == nil {
		switch v := m.Message.(type) {
		case string:
			s = v
		case nil:
		default:
			b, _ := json.Marshal(v)
			s = string(b)
		}
		if s == "" {
			s = m.Error
		}
		if s == "" && m.Desc != "" {
			s = m.Desc
		}
		if len(m.Errors) > 0 {
			b, _ := json.Marshal(m.Errors)
			s += " " + string(b)
		}
	} else {
		s = string(data)
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
