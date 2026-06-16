package safepath

import "errors"

var (
	ErrEmptyPath       = errors.New("path is empty")
	ErrNULPath         = errors.New("path contains NUL")
	ErrParentTraversal = errors.New("path contains parent traversal")
	ErrPathEscape      = errors.New("path escapes root")
	ErrSymlink         = errors.New("symlink rejected")
)
