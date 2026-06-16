package safepath

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func (r Root) WriteFileAtomic(p Path, data []byte) error {
	if err := r.ensureContains(p); err != nil {
		return err
	}
	parent, err := r.Parent(p)
	if err != nil {
		return err
	}
	if err := r.MkdirAll(parent); err != nil {
		return err
	}
	tmpPath, err := r.tempFilePath(parent)
	if err != nil {
		return err
	}
	tmp, err := r.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, RuntimeFilePerm)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = r.Remove(tmpPath)
		}
	}()
	n, writeErr := tmp.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	chmodErr := error(nil)
	if writeErr == nil {
		chmodErr = tmp.Chmod(RuntimeFilePerm)
	}
	closeErr := tmp.Close()
	if writeErr != nil {
		if closeErr != nil {
			return fmt.Errorf("write temp file: %w; close temp file: %v", writeErr, closeErr)
		}
		return fmt.Errorf("write temp file: %w", writeErr)
	}
	if chmodErr != nil {
		if closeErr != nil {
			return fmt.Errorf("chmod temp file: %w; close temp file: %v", chmodErr, closeErr)
		}
		return fmt.Errorf("chmod temp file: %w", chmodErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close temp file: %w", closeErr)
	}
	if err := r.Rename(tmpPath, p); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	cleanup = false
	return nil
}

func (r Root) tempFilePath(parent Path) (Path, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return Path{}, fmt.Errorf("random temp suffix: %w", err)
	}
	tmpName := ".openaudit-" + hex.EncodeToString(suffix[:]) + ".tmp"
	return r.joinUnderPath(parent, tmpName)
}

func (r Root) joinUnderPath(base Path, elems ...string) (Path, error) {
	if err := r.ensureContains(base); err != nil {
		return Path{}, err
	}
	joinedAbs, err := safeJoinUnder(base.abs, elems...)
	if err != nil {
		return Path{}, err
	}
	return r.validateAbs(joinedAbs)
}
