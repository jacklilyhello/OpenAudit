package importer

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func ReadWordlist(path string) ([]string, error) {
	cleaned := filepath.Clean(path)
	f, err := os.Open(cleaned) // #nosec G304 -- legacy helper used with operator-provided local wordlist paths.
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || len(line) >= 1 && line[:1] == "#" || len(line) >= 2 && line[:2] == "//" || len(line) >= 1 && line[:1] == ";" {
			continue
		}
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	scanErr := sc.Err()
	closeErr := f.Close()
	if scanErr != nil {
		return nil, scanErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return out, nil
}
