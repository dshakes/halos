package signer

import (
	"net/url"
	"runtime"
	"strings"
	"testing"
)

// Exec URI forms, parsed for each target OS on every OS (pure parsing).
// Windows uses the file-URI form exec:///C:/path/to/signer.exe.
func TestParseExecURIForms(t *testing.T) {
	for _, tc := range []struct {
		goos, uri, path, err string
	}{
		// Windows
		{goos: "windows", uri: "exec:///C:/Program%20Files/Halos/signer.exe?key=k", path: `C:\Program Files\Halos\signer.exe`},
		{goos: "windows", uri: "exec:///c:/tools/s.exe", path: `c:\tools\s.exe`},
		{goos: "windows", uri: "exec:///C:%5CTools%5Cs.exe", path: `C:\Tools\s.exe`},       // escaped backslashes
		{goos: "windows", uri: "exec:///C:/Tools%5Cbin/s.exe", path: `C:\Tools\bin\s.exe`}, // mixed
		{goos: "windows", uri: `exec://C:\Users\me\signer.exe?key=k`, err: "exec:///C:/path/to/signer.exe"},
		{goos: "windows", uri: "exec://C:/Users/me/signer.exe", err: "exec:///C:/path/to/signer.exe"},
		{goos: "windows", uri: "exec:////server/share/s.exe", err: "UNC"},
		{goos: "windows", uri: "exec:///%5C%5Cserver/share/s.exe", err: "UNC"},
		{goos: "windows", uri: "exec:///usr/bin/s", err: "no drive letter"},
		{goos: "windows", uri: "exec:///C:/a/../s.exe", err: "clean"},
		{goos: "windows", uri: "exec:///C:/a//s.exe", err: "clean"},
		{goos: "windows", uri: "exec:///C:/a/./s.exe", err: "clean"},
		{goos: "windows", uri: "exec:///C:/a/s.exe:stream", err: "clean"},
		{goos: "windows", uri: "exec:///C:", err: "no drive letter"},
		// Unix, unchanged
		{goos: "linux", uri: "exec:///usr/local/bin/s?key=k", path: "/usr/local/bin/s"},
		{goos: "darwin", uri: "exec:///opt/halos/signer", path: "/opt/halos/signer"},
		{goos: "linux", uri: "exec:///C:/Tools/s.exe", err: "Windows drive path"},
		{goos: "linux", uri: "exec:///usr/bin%5Cs", err: "clean"},
		{goos: "linux", uri: "exec:////server/share/s", err: "UNC"},
		{goos: "linux", uri: "exec://host/usr/bin/s", err: "three slashes"},
		{goos: "linux", uri: "exec:/usr/bin/s", err: "three slashes"},
	} {
		e, err := parseExecURIFor(tc.uri, tc.goos)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s %s: got %v, want %q", tc.goos, tc.uri, err, tc.err)
			}
			continue
		}
		if err != nil || e.path != tc.path {
			t.Errorf("%s %s: path %q err %v, want %q", tc.goos, tc.uri, e.path, err, tc.path)
		}
	}
}

// ExecURI builds the form parseExecURIFor accepts, for both path styles.
func TestExecURIRoundTrip(t *testing.T) {
	q := url.Values{"key": {"slot 0"}, "arg": {"--pin-env", "HSM_PIN"}}
	for _, tc := range []struct{ goos, path, want string }{
		{"windows", `C:\Program Files\Halos\signer.exe`, "exec:///C:/Program%20Files/Halos/signer.exe?"},
		{"windows", `D:/tools/s.exe`, "exec:///D:/tools/s.exe?"},
		{"linux", "/usr/local/bin/halos signer", "exec:///usr/local/bin/halos%20signer?"},
	} {
		uri := ExecURI(tc.path, q)
		if !strings.HasPrefix(uri, tc.want) {
			t.Errorf("ExecURI(%q) = %q, want prefix %q", tc.path, uri, tc.want)
		}
		e, err := parseExecURIFor(uri, tc.goos)
		want := tc.path
		if tc.goos == "windows" {
			want = strings.ReplaceAll(tc.path, "/", `\`)
		}
		if err != nil || e.path != want || e.keyID != "slot 0" || strings.Join(e.args, " ") != "--pin-env HSM_PIN" {
			t.Errorf("round trip %q: %+v %v", uri, e, err)
		}
	}
	if got := ExecURI("/usr/bin/s", nil); got != "exec:///usr/bin/s" {
		t.Errorf("no query: %q", got)
	}
	// the native form for this OS round-trips through the real parser too
	native := "/usr/bin/s"
	if runtime.GOOS == "windows" {
		native = `C:\Windows\System32\cmd.exe`
	}
	if e, err := parseExecURI(ExecURI(native, nil)); err != nil || e.path != native {
		t.Errorf("native %q: %+v %v", native, e, err)
	}
}
