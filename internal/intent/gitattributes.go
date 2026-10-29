package intent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// ArtifactAttrLine keeps artifact files byte-exact in every checkout.
const ArtifactAttrLine = "artifacts/** -text"

const artifactAttrComment = "# Artifact digests are sha256 over the committed bytes: no CRLF conversion."

// GitAttributes returns the .gitattributes content a new policy repo in dir
// needs: the existing file with ArtifactAttrLine appended, or a new file.
// ok is false when the line is already there. An existing file is never
// replaced, only extended.
func GitAttributes(dir string) (content []byte, ok bool, err error) {
	p := filepath.Join(dir, ".gitattributes")
	cur, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("read %s: %w", p, err)
	}
	for _, l := range bytes.Split(cur, []byte("\n")) {
		if string(bytes.TrimSpace(l)) == ArtifactAttrLine {
			return nil, false, nil
		}
	}
	if len(cur) > 0 && !bytes.HasSuffix(cur, []byte("\n")) {
		cur = append(cur, '\n')
	}
	return append(cur, artifactAttrComment+"\n"+ArtifactAttrLine+"\n"...), true, nil
}
