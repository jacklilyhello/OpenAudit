package safepath

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

func (r Root) MkdirAll(p Path) error {
	if err := r.ensureContains(p); err != nil {
		return err
	}
	if info, err := r.lstat(p); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: directory", ErrSymlink)
		}
		if !info.IsDir() {
			return errors.New("path exists and is not a directory")
		}
		if err := os.Chmod(p.abs, RuntimeDirPerm); err != nil {
			return fmt.Errorf("chmod directory: %w", err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(p.abs, RuntimeDirPerm); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	if err := os.Chmod(p.abs, RuntimeDirPerm); err != nil {
		return fmt.Errorf("chmod directory: %w", err)
	}
	return nil
}

func (r Root) ReadFile(p Path) ([]byte, error) {
	f, err := r.OpenRead(p)
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(f)
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	return b, closeErr
}

func (r Root) OpenRead(p Path) (*os.File, error) {
	info, err := r.lstat(p)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: file", ErrSymlink)
	}
	if info.IsDir() {
		return nil, errors.New("path is a directory")
	}
	return os.Open(p.abs) // #nosec G304 -- p is a safepath.Path constrained under Root with symlink rejection before opening.
}

func (r Root) OpenFile(p Path, flag int, perm fs.FileMode) (*os.File, error) {
	if err := r.ensureContains(p); err != nil {
		return nil, err
	}
	if info, err := r.lstat(p); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: file", ErrSymlink)
		}
		if info.IsDir() {
			return nil, errors.New("path is a directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	parent, err := r.Parent(p)
	if err != nil {
		return nil, err
	}
	if flag&(os.O_CREATE|os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_TRUNC) != 0 {
		if err := r.MkdirAll(parent); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(p.abs, flag, perm) // #nosec G304 -- p is a safepath.Path constrained under Root with symlink rejection before opening.
	if err != nil {
		return nil, err
	}
	if flag&(os.O_CREATE|os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_TRUNC) != 0 {
		if err := f.Chmod(perm); err != nil {
			closeErr := f.Close()
			if closeErr != nil {
				return nil, fmt.Errorf("chmod file: %w; close file: %v", err, closeErr)
			}
			return nil, err
		}
	}
	return f, nil
}

func (r Root) Remove(p Path) error {
	if err := r.ensureContains(p); err != nil {
		return err
	}
	if info, err := r.lstat(p); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: file", ErrSymlink)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(p.abs) // #nosec G304 -- p is a safepath.Path constrained under Root.
}

func (r Root) Rename(oldPath Path, newPath Path) error {
	if err := r.ensureContains(oldPath); err != nil {
		return err
	}
	if err := r.ensureContains(newPath); err != nil {
		return err
	}
	if info, err := r.lstat(oldPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: file", ErrSymlink)
	} else if err != nil {
		return err
	}
	return os.Rename(oldPath.abs, newPath.abs) // #nosec G304 -- both paths are safepath.Path values constrained under the same Root.
}

func (r Root) ReadDir(p Path) ([]os.DirEntry, error) {
	info, err := r.lstat(p)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: directory", ErrSymlink)
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory")
	}
	return os.ReadDir(p.abs) // #nosec G304 -- p is a safepath.Path constrained under Root with symlink rejection before reading.
}

func (r Root) lstat(p Path) (fs.FileInfo, error) {
	if err := r.ensureContains(p); err != nil {
		return nil, err
	}
	return os.Lstat(p.abs) // #nosec G304 -- p is a safepath.Path constrained under Root.
}
