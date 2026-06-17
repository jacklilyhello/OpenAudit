package safepath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

func (r Root) Walk(fn func(Path, fs.DirEntry) error) error {
	rootPath := r.Path()
	info, err := r.lstat(rootPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: root", ErrSymlink)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", rootPath.String())
	}
	return r.walkDir(rootPath, fn)
}

func (r Root) walkDir(dir Path, fn func(Path, fs.DirEntry) error) error {
	entries, err := r.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child, err := r.joinUnderPath(dir, entry.Name())
		if err != nil {
			return err
		}
		info, err := r.lstat(child)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlink, child.String())
		}
		if err := fn(child, entry); err != nil {
			if errors.Is(err, fs.SkipDir) {
				if info.IsDir() {
					continue
				}
				return nil
			}
			return err
		}
		if info.IsDir() {
			if err := r.walkDir(child, fn); err != nil {
				return err
			}
		}
	}
	return nil
}
