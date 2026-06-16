package logstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type JSONL struct {
	mu   sync.Mutex
	path string
}

func NewJSONL(path string) (*JSONL, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	return &JSONL{path: path}, nil
}
func (j *JSONL) Append(e Entry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	_, err = f.Write(append(b, '\n'))
	return err
}
