package rulehistory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openaudit/openaudit/internal/safepath"
	"os"
	"sort"
	"sync"
	"time"
)

type Store struct {
	path string
	max  int
	mu   sync.Mutex
}

func New(path string, max int) *Store { return &Store{path: path, max: max} }
func NewID(prefix string) string      { return fmt.Sprintf("%s_%d", prefix, time.Now().UTC().UnixNano()) }
func (s *Store) Append(c Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.ChangeID == "" {
		c.ChangeID = NewID("change")
	}
	if c.Timestamp.IsZero() {
		c.Timestamp = time.Now().UTC()
	}
	if c.Actor == "" {
		c.Actor = "api"
	}
	if c.Diff.Summary.AddedLines == 0 && c.Diff.Summary.RemovedLines == 0 && (c.Before != "" || c.After != "") {
		c.Diff = TextDiff(c.Before, c.After)
	}
	root, path, err := validatedStoreFile(s.path)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, safepath.RuntimeFilePerm)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(c); err != nil {
		closeErr := f.Close()
		if closeErr != nil {
			return fmt.Errorf("encode history: %w; close history: %v", err, closeErr)
		}
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if s.max > 0 {
		return s.trim()
	}
	return nil
}
func (s *Store) all() (changes []Change, err error) {
	root, path, err := validatedStoreFile(s.path)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenRead(path)
	if errors.Is(err, os.ErrNotExist) {
		return []Change{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	out := []Change{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024), 10*1024*1024)
	for sc.Scan() {
		if sc.Text() == "" {
			continue
		}
		var c Change
		if err := json.Unmarshal(sc.Bytes(), &c); err == nil {
			out = append(out, c)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Store) List(f Filter) ([]Change, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.all()
	if err != nil {
		return nil, 0, err
	}
	out := []Change{}
	for _, c := range all {
		if f.RuleID != "" && c.RuleID != f.RuleID {
			continue
		}
		if f.Action != "" && string(c.Action) != f.Action {
			continue
		}
		if f.Actor != "" && c.Actor != f.Actor {
			continue
		}
		if f.Source != "" && c.Source != f.Source {
			continue
		}
		if f.ImportBatchID != "" && c.ImportBatchID != f.ImportBatchID {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	count := len(out)
	lim := f.Limit
	if lim <= 0 {
		lim = 50
	}
	off := f.Offset
	if off < 0 {
		off = 0
	}
	if off >= len(out) {
		return []Change{}, count, nil
	}
	end := off + lim
	if end > len(out) {
		end = len(out)
	}
	return out[off:end], count, nil
}
func (s *Store) Get(id string) (Change, bool, error) {
	items, _, err := s.List(Filter{Limit: 1000000})
	if err != nil {
		return Change{}, false, err
	}
	for _, c := range items {
		if c.ChangeID == id {
			return c, true, nil
		}
	}
	return Change{}, false, nil
}
func (s *Store) Stats() (Stats, error) {
	items, _, err := s.List(Filter{Limit: 1000000})
	if err != nil {
		return Stats{}, err
	}
	st := Stats{TotalChanges: len(items), Actions: map[string]int{}, Actors: map[string]int{}, Sources: map[string]int{}}
	for _, c := range items {
		st.Actions[string(c.Action)]++
		if c.Actor != "" {
			st.Actors[c.Actor]++
		}
		src := c.Source
		if src == "" {
			src = "local"
		}
		st.Sources[src]++
	}
	if len(items) > 10 {
		st.RecentChanges = items[:10]
	} else {
		st.RecentChanges = items
	}
	return st, nil
}
func (s *Store) trim() error {
	all, err := s.all()
	if err != nil || len(all) <= s.max {
		return err
	}
	all = all[len(all)-s.max:]
	root, path, err := validatedStoreFile(s.path)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, c := range all {
		if err := enc.Encode(c); err != nil {
			return fmt.Errorf("encode trimmed history: %w", err)
		}
	}
	return root.WriteFileAtomic(path, buf.Bytes())
}

func validatedStoreFile(path string) (safepath.Root, safepath.Path, error) {
	root, target, err := safepath.NewFileTarget(path)
	if err != nil {
		return safepath.Root{}, safepath.Path{}, fmt.Errorf("history path: %w", err)
	}
	return root, target, nil
}
