package logstore

import (
	"encoding/json"
	"github.com/openaudit/openaudit/internal/safepath"
	"os"
	"sync"
)

type JSONL struct {
	mu   sync.Mutex
	root safepath.Root
	path safepath.Path
}

func NewJSONL(path string) (*JSONL, error) {
	root, target, err := safepath.NewFileTarget(path)
	if err != nil {
		return nil, err
	}
	parent, err := root.Parent(target)
	if err != nil {
		return nil, err
	}
	if err := root.MkdirAll(parent); err != nil {
		return nil, err
	}
	return &JSONL{root: root, path: target}, nil
}
func (j *JSONL) Append(e Entry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := j.root.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, safepath.RuntimeFilePerm)
	if err != nil {
		return err
	}
	encErr := json.NewEncoder(f).Encode(e)
	closeErr := f.Close()
	if encErr != nil {
		return encErr
	}
	return closeErr
}
