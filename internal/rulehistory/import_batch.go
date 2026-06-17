package rulehistory

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openaudit/openaudit/internal/safepath"
	"github.com/openaudit/openaudit/internal/storage"
	"os"
	"sort"
	"sync"
	"time"
)

type ImportBatch struct {
	BatchID              string    `json:"batch_id"`
	Timestamp            time.Time `json:"timestamp"`
	Source               string    `json:"source"`
	InputPath            string    `json:"input_path"`
	OutputPath           string    `json:"output_path"`
	Category             string    `json:"category,omitempty"`
	RiskLevel            string    `json:"risk_level,omitempty"`
	Action               string    `json:"action,omitempty"`
	FilesScanned         int       `json:"files_scanned"`
	KeywordsRead         int       `json:"keywords_read"`
	KeywordsDeduplicated int       `json:"keywords_deduplicated"`
	RulesWritten         int       `json:"rules_written"`
	DryRun               bool      `json:"dry_run"`
	ReloadAfterImport    bool      `json:"reload_after_import"`
	Status               string    `json:"status"`
	Error                string    `json:"error,omitempty"`
	GeneratedFiles       []string  `json:"generated_files"`
}
type BatchFilter struct {
	Source, Status string
	Limit, Offset  int
}
type BatchStore struct {
	path    string
	mu      sync.Mutex
	backend storage.Store
}

func NewBatchStore(path string) *BatchStore { return &BatchStore{path: path} }
func (b *BatchStore) SetBackend(s storage.Store) {
	if b != nil {
		b.backend = s
	}
}
func (b *BatchStore) AppendBatch(x ImportBatch) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if x.BatchID == "" {
		x.BatchID = NewID("batch")
	}
	if x.Timestamp.IsZero() {
		x.Timestamp = time.Now().UTC()
	}
	root, path, err := validatedStoreFile(b.path)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, safepath.RuntimeFilePerm)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(x); err != nil {
		closeErr := f.Close()
		if closeErr != nil {
			return fmt.Errorf("encode import batch: %w; close import batch history: %v", err, closeErr)
		}
		return err
	}
	closeErr := f.Close()
	if b.backend != nil {
		raw, _ := json.Marshal(x)
		stats, _ := json.Marshal(map[string]any{"source": x.Source, "files_scanned": x.FilesScanned, "keywords_read": x.KeywordsRead, "keywords_deduplicated": x.KeywordsDeduplicated, "generated_files": x.GeneratedFiles})
		_ = b.backend.InsertImportBatch(context.Background(), storage.ImportBatch{BatchID: x.BatchID, CreatedAt: x.Timestamp, Status: x.Status, DryRun: x.DryRun, InputRoot: x.InputPath, OutputRoot: x.OutputPath, RulesSeen: x.KeywordsRead, RulesWritten: x.RulesWritten, RulesSkipped: x.KeywordsDeduplicated, ErrorsCount: boolErrCount(x.Error), StatsJSON: string(stats), ErrorsJSON: x.Error, RawJSON: string(raw)})
	}
	return closeErr
}
func boolErrCount(s string) int {
	if s == "" {
		return 0
	}
	return 1
}
func (b *BatchStore) all() (batches []ImportBatch, err error) {
	root, path, err := validatedStoreFile(b.path)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenRead(path)
	if errors.Is(err, os.ErrNotExist) {
		return []ImportBatch{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	out := []ImportBatch{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024), 10*1024*1024)
	for sc.Scan() {
		var x ImportBatch
		if err := json.Unmarshal(sc.Bytes(), &x); err == nil {
			out = append(out, x)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
func (b *BatchStore) List(f BatchFilter) ([]ImportBatch, int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	all, err := b.all()
	if err != nil {
		return nil, 0, err
	}
	out := []ImportBatch{}
	for _, x := range all {
		if f.Source != "" && x.Source != f.Source {
			continue
		}
		if f.Status != "" && x.Status != f.Status {
			continue
		}
		out = append(out, x)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	count := len(out)
	lim := f.Limit
	if lim <= 0 {
		lim = 50
	}
	off := f.Offset
	if off >= len(out) {
		return []ImportBatch{}, count, nil
	}
	end := off + lim
	if end > len(out) {
		end = len(out)
	}
	return out[off:end], count, nil
}
func (b *BatchStore) Get(id string) (ImportBatch, bool, error) {
	xs, _, err := b.List(BatchFilter{Limit: 1000000})
	if err != nil {
		return ImportBatch{}, false, err
	}
	for _, x := range xs {
		if x.BatchID == id {
			return x, true, nil
		}
	}
	return ImportBatch{}, false, nil
}
