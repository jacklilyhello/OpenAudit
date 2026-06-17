package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/safepath"
	"github.com/openaudit/openaudit/internal/storage"
	"github.com/openaudit/openaudit/internal/storage/migrations"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	Root        string
	Path        string
	AutoMigrate bool
}
type Store struct {
	db   *sql.DB
	path string
}

func Open(ctx context.Context, opt Options) (*Store, error) {
	if strings.TrimSpace(opt.Root) == "" {
		opt.Root = "./storage"
	}
	if strings.TrimSpace(opt.Path) == "" {
		opt.Path = "data/openaudit.db"
	}
	root, err := safepath.NewRoot(opt.Root, safepath.CreateRoot(), safepath.RejectParentTraversal())
	if err != nil {
		return nil, fmt.Errorf("sqlite root: %w", err)
	}
	p, err := root.Resolve(opt.Path)
	if err != nil {
		return nil, fmt.Errorf("sqlite path: %w", err)
	}
	parent, err := root.Parent(p)
	if err != nil {
		return nil, err
	}
	if err := root.MkdirAll(parent); err != nil {
		return nil, err
	}
	dsn := p.String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, path: dsn}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		_ = db.Close()
		return nil, err
	}
	_, _ = db.ExecContext(ctx, "PRAGMA journal_mode = WAL")
	_, _ = db.ExecContext(ctx, "PRAGMA busy_timeout = 5000")
	if opt.AutoMigrate {
		if err := s.Migrate(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	_ = os.Chmod(parent.String(), safepath.RuntimeDirPerm)
	if _, err := os.Stat(dsn); err == nil {
		_ = os.Chmod(dsn, safepath.RuntimeFilePerm)
	}
	return s, nil
}
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
func (s *Store) DB() *sql.DB  { return s.db }
func (s *Store) Path() string { return s.path }
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"); err != nil {
		return err
	}
	for _, m := range migrations.All {
		var id string
		e := tx.QueryRowContext(ctx, "SELECT id FROM schema_migrations WHERE id = ?", m.ID).Scan(&id)
		if e == nil {
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			err = e
			return err
		}
		if _, err = tx.ExecContext(ctx, m.SQL); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.ID, err)
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)", m.ID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}
func ts(t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func parseTS(v string) time.Time { t, _ := time.Parse(time.RFC3339Nano, v); return t }
func page(total, limit, offset int) storage.Page {
	return storage.Page{Limit: limit, Offset: offset, Total: total, HasMore: offset+limit < total}
}
func hitMeta(h engine.Hit) string { b, _ := json.Marshal(h); return string(b) }
func (s *Store) InsertAuditLog(ctx context.Context, a storage.AuditLog, hits []engine.Hit) (int64, error) {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.RequestID == "" {
		a.RequestID = fmt.Sprintf("audit_%d", a.CreatedAt.UnixNano())
	}
	if a.RuleHitCount == 0 {
		a.RuleHitCount = len(hits)
	}
	if a.MatchCount == 0 {
		a.MatchCount = len(hits)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (request_id,created_at,method,path,client_ip,api_key_id,decision,status_code,duration_ms,request_bytes,normalized_bytes,match_count,rule_hit_count,metadata_json,raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, a.RequestID, ts(a.CreatedAt), a.Method, a.Path, a.ClientIP, a.APIKeyID, a.Decision, a.StatusCode, a.DurationMS, a.RequestBytes, a.NormalizedBytes, a.MatchCount, a.RuleHitCount, a.MetadataJSON, a.RawJSON)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	for _, h := range hits {
		if _, err = tx.ExecContext(ctx, `INSERT INTO rule_hits (audit_log_id,request_id,rule_id,rule_name,category,severity,match_type,matched_text,normalized_text,start_pos,end_pos,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, id, a.RequestID, h.RuleID, h.Description, h.Category, h.RiskLevel, h.Type, h.Match, h.NormalizedMatch, h.Start, h.End, hitMeta(h)); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	}
	return id, tx.Commit()
}
func (s *Store) QueryAuditLogs(ctx context.Context, f storage.AuditFilter) (storage.AuditPage, error) {
	limit, offset := storage.NormalizeLimitOffset(f.Limit, f.Offset)
	where, args := []string{"1=1"}, []any{}
	if f.Action != "" {
		where = append(where, "decision = ?")
		args = append(args, f.Action)
	}
	if f.Matched != nil {
		if *f.Matched {
			where = append(where, "match_count > 0")
		} else {
			where = append(where, "match_count = 0")
		}
	}
	if f.RequestID != "" {
		where = append(where, "request_id = ?")
		args = append(args, f.RequestID)
	}
	if f.Query != "" {
		where = append(where, "(request_id LIKE ? OR raw_json LIKE ?)")
		q := "%" + f.Query + "%"
		args = append(args, q, q)
	}
	if f.Category != "" {
		where = append(where, "EXISTS (SELECT 1 FROM rule_hits WHERE rule_hits.audit_log_id = audit_logs.id AND category = ?)")
		args = append(args, f.Category)
	}
	wc := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE "+wc, args...).Scan(&total); err != nil {
		return storage.AuditPage{}, err
	}
	qargs := append(append([]any{}, args...), limit, offset)
	// #nosec G202 -- wc is assembled only from fixed internal predicates; request values are passed as SQL parameters.
	rows, err := s.db.QueryContext(ctx, "SELECT id,request_id,created_at,method,path,client_ip,api_key_id,decision,status_code,duration_ms,request_bytes,normalized_bytes,match_count,rule_hit_count,metadata_json,raw_json FROM audit_logs WHERE "+wc+" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", qargs...)
	if err != nil {
		return storage.AuditPage{}, err
	}
	defer rows.Close()
	items := []storage.AuditLog{}
	for rows.Next() {
		var a storage.AuditLog
		var created string
		if err := rows.Scan(&a.ID, &a.RequestID, &created, &a.Method, &a.Path, &a.ClientIP, &a.APIKeyID, &a.Decision, &a.StatusCode, &a.DurationMS, &a.RequestBytes, &a.NormalizedBytes, &a.MatchCount, &a.RuleHitCount, &a.MetadataJSON, &a.RawJSON); err != nil {
			return storage.AuditPage{}, err
		}
		a.CreatedAt = parseTS(created)
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return storage.AuditPage{}, err
	}
	return storage.AuditPage{Items: items, Page: page(total, limit, offset)}, nil
}
func (s *Store) QueryRuleHits(ctx context.Context, auditID int64, requestID string) ([]storage.RuleHit, error) {
	where, args := "audit_log_id = ?", []any{auditID}
	if auditID == 0 {
		where = "request_id = ?"
		args = []any{requestID}
	}
	// #nosec G202 -- where is selected from two fixed predicates; request_id/audit_log_id values are parameterized.
	rows, err := s.db.QueryContext(ctx, `SELECT id,audit_log_id,request_id,rule_id,rule_name,category,severity,match_type,matched_text,normalized_text,start_pos,end_pos,metadata_json FROM rule_hits WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.RuleHit
	for rows.Next() {
		var h storage.RuleHit
		if err := rows.Scan(&h.ID, &h.AuditLogID, &h.RequestID, &h.RuleID, &h.RuleName, &h.Category, &h.Severity, &h.MatchType, &h.MatchedText, &h.NormalizedText, &h.StartPos, &h.EndPos, &h.MetadataJSON); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
func (s *Store) InsertRuleChange(ctx context.Context, c storage.RuleChange) error {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO rule_changes (change_id,created_at,actor,operation,source,rule_id,rule_name,file_path,before_hash,after_hash,diff_json,metadata_json,raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, c.ChangeID, ts(c.CreatedAt), c.Actor, c.Operation, c.Source, c.RuleID, c.RuleName, c.FilePath, c.BeforeHash, c.AfterHash, c.DiffJSON, c.MetadataJSON, c.RawJSON)
	return err
}
func (s *Store) QueryRuleChanges(ctx context.Context, f storage.ChangeFilter) (storage.ChangePage, error) {
	limit, offset := storage.NormalizeLimitOffset(f.Limit, f.Offset)
	where, args := []string{"1=1"}, []any{}
	if f.RuleID != "" {
		where = append(where, "rule_id = ?")
		args = append(args, f.RuleID)
	}
	if f.Operation != "" {
		where = append(where, "operation = ?")
		args = append(args, f.Operation)
	}
	if f.Actor != "" {
		where = append(where, "actor = ?")
		args = append(args, f.Actor)
	}
	if f.Source != "" {
		where = append(where, "source = ?")
		args = append(args, f.Source)
	}
	if f.ImportBatchID != "" {
		where = append(where, "metadata_json LIKE ?")
		args = append(args, "%"+f.ImportBatchID+"%")
	}
	return queryChanges(ctx, s.db, strings.Join(where, " AND "), args, limit, offset)
}
func queryChanges(ctx context.Context, db *sql.DB, wc string, args []any, limit, offset int) (storage.ChangePage, error) {
	var total int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM rule_changes WHERE "+wc, args...).Scan(&total); err != nil {
		return storage.ChangePage{}, err
	}
	// #nosec G202 -- wc is assembled only from fixed internal predicates; request values are passed as SQL parameters.
	rows, err := db.QueryContext(ctx, "SELECT id,change_id,created_at,actor,operation,source,rule_id,rule_name,file_path,before_hash,after_hash,diff_json,metadata_json,raw_json FROM rule_changes WHERE "+wc+" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return storage.ChangePage{}, err
	}
	defer rows.Close()
	var items []storage.RuleChange
	for rows.Next() {
		var c storage.RuleChange
		var created string
		if err := rows.Scan(&c.ID, &c.ChangeID, &created, &c.Actor, &c.Operation, &c.Source, &c.RuleID, &c.RuleName, &c.FilePath, &c.BeforeHash, &c.AfterHash, &c.DiffJSON, &c.MetadataJSON, &c.RawJSON); err != nil {
			return storage.ChangePage{}, err
		}
		c.CreatedAt = parseTS(created)
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return storage.ChangePage{}, err
	}
	return storage.ChangePage{Items: items, Page: page(total, limit, offset)}, nil
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func (s *Store) InsertImportBatch(ctx context.Context, b storage.ImportBatch) error {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO import_batches (batch_id,created_at,started_at,finished_at,status,dry_run,input_root,output_root,report_path,report_format,rules_seen,rules_written,rules_skipped,errors_count,stats_json,errors_json,raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, b.BatchID, ts(b.CreatedAt), ts(b.StartedAt), ts(b.FinishedAt), b.Status, boolInt(b.DryRun), b.InputRoot, b.OutputRoot, b.ReportPath, b.ReportFormat, b.RulesSeen, b.RulesWritten, b.RulesSkipped, b.ErrorsCount, b.StatsJSON, b.ErrorsJSON, b.RawJSON)
	return err
}
func (s *Store) QueryImportBatches(ctx context.Context, f storage.BatchFilter) (storage.BatchPage, error) {
	limit, offset := storage.NormalizeLimitOffset(f.Limit, f.Offset)
	where, args := []string{"1=1"}, []any{}
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.Source != "" {
		where = append(where, "stats_json LIKE ?")
		args = append(args, "%"+f.Source+"%")
	}
	wc := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM import_batches WHERE "+wc, args...).Scan(&total); err != nil {
		return storage.BatchPage{}, err
	}
	// #nosec G202 -- wc is assembled only from fixed internal predicates; request values are passed as SQL parameters.
	rows, err := s.db.QueryContext(ctx, "SELECT id,batch_id,created_at,started_at,finished_at,status,dry_run,input_root,output_root,report_path,report_format,rules_seen,rules_written,rules_skipped,errors_count,stats_json,errors_json,raw_json FROM import_batches WHERE "+wc+" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return storage.BatchPage{}, err
	}
	defer rows.Close()
	var items []storage.ImportBatch
	for rows.Next() {
		var b storage.ImportBatch
		var created, started, finished string
		var dry int
		if err := rows.Scan(&b.ID, &b.BatchID, &created, &started, &finished, &b.Status, &dry, &b.InputRoot, &b.OutputRoot, &b.ReportPath, &b.ReportFormat, &b.RulesSeen, &b.RulesWritten, &b.RulesSkipped, &b.ErrorsCount, &b.StatsJSON, &b.ErrorsJSON, &b.RawJSON); err != nil {
			return storage.BatchPage{}, err
		}
		b.CreatedAt = parseTS(created)
		b.StartedAt = parseTS(started)
		b.FinishedAt = parseTS(finished)
		b.DryRun = dry != 0
		items = append(items, b)
	}
	if err := rows.Err(); err != nil {
		return storage.BatchPage{}, err
	}
	return storage.BatchPage{Items: items, Page: page(total, limit, offset)}, nil
}
func (s *Store) InsertAdminOperation(ctx context.Context, a storage.AdminOperation) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_operations (operation_id,created_at,actor,client_ip,operation,resource_type,resource_id,status,status_code,metadata_json,raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, a.OperationID, ts(a.CreatedAt), a.Actor, a.ClientIP, a.Operation, a.ResourceType, a.ResourceID, a.Status, a.StatusCode, a.MetadataJSON, a.RawJSON)
	return err
}
func (s *Store) QueryAdminOperations(ctx context.Context, f storage.AdminFilter) (storage.AdminPage, error) {
	limit, offset := storage.NormalizeLimitOffset(f.Limit, f.Offset)
	where, args := []string{"1=1"}, []any{}
	if f.Operation != "" {
		where = append(where, "operation = ?")
		args = append(args, f.Operation)
	}
	if f.Actor != "" {
		where = append(where, "actor = ?")
		args = append(args, f.Actor)
	}
	if f.ResourceType != "" {
		where = append(where, "resource_type = ?")
		args = append(args, f.ResourceType)
	}
	if f.ResourceID != "" {
		where = append(where, "resource_id = ?")
		args = append(args, f.ResourceID)
	}
	wc := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_operations WHERE "+wc, args...).Scan(&total); err != nil {
		return storage.AdminPage{}, err
	}
	// #nosec G202 -- wc is assembled only from fixed internal predicates; request values are passed as SQL parameters.
	rows, err := s.db.QueryContext(ctx, "SELECT id,operation_id,created_at,actor,client_ip,operation,resource_type,resource_id,status,status_code,metadata_json,raw_json FROM admin_operations WHERE "+wc+" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return storage.AdminPage{}, err
	}
	defer rows.Close()
	var items []storage.AdminOperation
	for rows.Next() {
		var a storage.AdminOperation
		var created string
		if err := rows.Scan(&a.ID, &a.OperationID, &created, &a.Actor, &a.ClientIP, &a.Operation, &a.ResourceType, &a.ResourceID, &a.Status, &a.StatusCode, &a.MetadataJSON, &a.RawJSON); err != nil {
			return storage.AdminPage{}, err
		}
		a.CreatedAt = parseTS(created)
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return storage.AdminPage{}, err
	}
	return storage.AdminPage{Items: items, Page: page(total, limit, offset)}, nil
}
func StorageRootFromDBPath(path string) (string, string) {
	clean := filepath.Clean(path)
	return filepath.Dir(clean), filepath.Base(clean)
}
