package importer

import (
	"bufio"
	"github.com/openaudit/openaudit/internal/safepath"
	"strings"
)

func ReadWordlist(path string) ([]string, error) {
	root, target, err := safepath.NewFileTarget(path)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenRead(target)
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
