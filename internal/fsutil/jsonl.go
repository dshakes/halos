package fsutil

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// OpenJSONL replays the append-only log at path line by line into replay,
// then returns it open for appending. A torn trailing line (crash mid-write)
// is handed to replay like any other (callers skip lines that don't decode)
// and then terminated with '\n', so the next record starts on its own line
// instead of being glued onto — and lost with — the torn one.
func OpenJSONL(path string, replay func([]byte)) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := RestrictToOwner(path); err != nil {
		_ = f.Close()
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		replay(sc.Bytes())
	}
	if err := sc.Err(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("replay %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if n := st.Size(); n > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, n-1); err != nil && err != io.EOF {
			_ = f.Close()
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if last[0] != '\n' {
			if _, err := f.Write([]byte{'\n'}); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("terminate torn line in %s: %w", path, err)
			}
		}
	}
	return f, nil
}
