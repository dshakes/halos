package mcpserver

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/promote"
)

func diffFiles(dir string, files map[string][]byte) (string, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		old, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n)))
		if err != nil {
			return "", err
		}
		sb.WriteString(promote.UnifiedDiff(n, string(old), string(files[n])))
	}
	return sb.String(), nil
}
