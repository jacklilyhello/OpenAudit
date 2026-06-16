package safepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	RuntimeDirPerm  os.FileMode = 0o750
	RuntimeFilePerm os.FileMode = 0o600
)

type Root struct {
	root string
}

type Option func(*options)

type options struct {
	requireExistingDir bool
	create             bool
	rejectTraversal    bool
}

func RequireExistingDir() Option {
	return func(o *options) { o.requireExistingDir = true }
}

func CreateRoot() Option {
	return func(o *options) { o.create = true }
}

func RejectParentTraversal() Option {
	return func(o *options) { o.rejectTraversal = true }
}

func NewRoot(rawRoot string, opts ...Option) (Root, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	rootAbs, err := cleanAbs(rawRoot, o.rejectTraversal)
	if err != nil {
		return Root{}, err
	}
	root := Root{root: rootAbs}
	rootPath := root.Path()
	info, err := root.lstat(rootPath)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return Root{}, fmt.Errorf("%w: root", ErrSymlink)
		}
		if !info.IsDir() {
			return Root{}, errors.New("root is not a directory")
		}
		return root, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Root{}, fmt.Errorf("stat root: %w", err)
	}
	if o.requireExistingDir {
		return Root{}, fmt.Errorf("stat root: %w", err)
	}
	if o.create {
		if err := root.MkdirAll(rootPath); err != nil {
			return Root{}, fmt.Errorf("create root: %w", err)
		}
	}
	return root, nil
}

func (r Root) String() string {
	return r.root
}

func (r Root) Path() Path {
	return Path{abs: r.root}
}

func (r Root) Resolve(raw string) (Path, error) {
	return r.resolve(raw, false)
}

func (r Root) ResolveAllowEmpty(raw string) (Path, error) {
	return r.resolve(raw, true)
}

func (r Root) Join(parts ...string) (Path, error) {
	if len(parts) == 0 {
		return Path{}, ErrEmptyPath
	}
	joinedAbs, err := safeJoinUnder(r.root, parts...)
	if err != nil {
		return Path{}, err
	}
	return r.validateAbs(joinedAbs)
}

func (r Root) Contains(p Path) bool {
	return r.ensureContains(p) == nil
}

func (r Root) Parent(p Path) (Path, error) {
	if err := r.ensureContains(p); err != nil {
		return Path{}, err
	}
	return r.validateAbs(filepath.Clean(filepath.Dir(p.abs)))
}

func (r Root) Rel(p Path) (string, error) {
	if err := r.ensureContains(p); err != nil {
		return "", err
	}
	return filepath.Rel(r.root, p.abs)
}

func (r Root) resolve(raw string, allowEmpty bool) (Path, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if allowEmpty {
			return r.Path(), nil
		}
		return Path{}, ErrEmptyPath
	}
	if strings.ContainsRune(raw, 0) {
		return Path{}, ErrNULPath
	}
	if containsParentTraversal(raw) {
		return Path{}, ErrParentTraversal
	}
	var candidate string
	if filepath.IsAbs(raw) {
		candidate = filepath.Clean(raw)
	} else {
		joined, err := safeJoinUnder(r.root, raw)
		if err != nil {
			return Path{}, err
		}
		candidate = joined
	}
	if containsParentTraversal(candidate) {
		return Path{}, ErrParentTraversal
	}
	return r.validateAbs(candidate)
}

func (r Root) validateAbs(candidate string) (Path, error) {
	if candidate == "" {
		return Path{}, ErrEmptyPath
	}
	if strings.ContainsRune(candidate, 0) {
		return Path{}, ErrNULPath
	}
	if !filepath.IsAbs(candidate) {
		return Path{}, errors.New("path must be absolute")
	}
	p := Path{abs: filepath.Clean(candidate)}
	if err := r.ensureContains(p); err != nil {
		return Path{}, err
	}
	return p, nil
}

func (r Root) ensureContains(p Path) error {
	if r.root == "" || strings.ContainsRune(r.root, 0) || !filepath.IsAbs(r.root) {
		return errors.New("validated root is invalid")
	}
	if p.abs == "" || strings.ContainsRune(p.abs, 0) || !filepath.IsAbs(p.abs) {
		return errors.New("validated path is invalid")
	}
	rel, err := filepath.Rel(filepath.Clean(r.root), filepath.Clean(p.abs))
	if err != nil {
		return fmt.Errorf("relative path check: %w", err)
	}
	if relEscapesBase(rel) || filepath.IsAbs(rel) {
		return fmt.Errorf("%w: %s", ErrPathEscape, p.abs)
	}
	return nil
}

func cleanAbs(raw string, rejectTraversal bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrEmptyPath
	}
	if strings.ContainsRune(raw, 0) {
		return "", ErrNULPath
	}
	if rejectTraversal && containsParentTraversal(raw) {
		return "", ErrParentTraversal
	}
	cleaned := filepath.Clean(raw)
	if cleaned == "." {
		return "", ErrEmptyPath
	}
	if rejectTraversal && containsParentTraversal(cleaned) {
		return "", ErrParentTraversal
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("absolute path: %w", err)
	}
	return filepath.Clean(abs), nil
}
