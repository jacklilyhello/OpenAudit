package safepath

import (
	"errors"
	"path/filepath"
	"strings"
)

type Path struct {
	abs string
}

func (p Path) String() string {
	return p.abs
}

func (p Path) Base() string {
	return filepath.Base(p.abs)
}

func (p Path) Dir() string {
	return filepath.Dir(p.abs)
}

func NewFileTarget(rawPath string, opts ...Option) (Root, Path, error) {
	targetAbs, err := cleanAbs(rawPath, true)
	if err != nil {
		return Root{}, Path{}, err
	}
	parent := filepath.Clean(filepath.Dir(targetAbs))
	if parent == "." || parent == string(filepath.Separator) && targetAbs == string(filepath.Separator) {
		return Root{}, Path{}, errors.New("file parent is invalid")
	}
	root, err := NewRoot(parent, opts...)
	if err != nil {
		return Root{}, Path{}, err
	}
	target, err := root.Resolve(targetAbs)
	if err != nil {
		return Root{}, Path{}, err
	}
	return root, target, nil
}

func safeJoinUnder(baseAbs string, elems ...string) (string, error) {
	if !filepath.IsAbs(baseAbs) {
		return "", errors.New("safe join base must be absolute")
	}
	cleanElems := make([]string, 0, len(elems))
	for _, elem := range elems {
		elem = strings.TrimSpace(elem)
		if elem == "" {
			return "", ErrEmptyPath
		}
		if strings.ContainsRune(elem, 0) {
			return "", ErrNULPath
		}
		if filepath.IsAbs(elem) {
			return "", errors.New("absolute path component rejected")
		}
		if containsParentTraversal(elem) {
			return "", ErrParentTraversal
		}
		cleaned := filepath.Clean(elem)
		if cleaned == "." {
			return "", ErrEmptyPath
		}
		if containsParentTraversal(cleaned) {
			return "", ErrParentTraversal
		}
		cleanElems = append(cleanElems, cleaned)
	}
	joined := filepath.Join(append([]string{baseAbs}, cleanElems...)...)
	joinedAbs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	joinedAbs = filepath.Clean(joinedAbs)
	rel, err := filepath.Rel(baseAbs, joinedAbs)
	if err != nil {
		return "", err
	}
	if relEscapesBase(rel) || filepath.IsAbs(rel) {
		return "", ErrPathEscape
	}
	return joinedAbs, nil
}

func containsParentTraversal(p string) bool {
	p = strings.ReplaceAll(filepath.ToSlash(p), "\\", "/")
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func relEscapesBase(rel string) bool {
	if rel == "." {
		return false
	}
	if filepath.IsAbs(rel) {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
