package sqlite

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/storage"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), Options{Root: t.TempDir(), Path: "data/openaudit.db", AutoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func TestOpenMigratesAndPermissions(t *testing.T) {
	root := t.TempDir()
	s, err := Open(context.Background(), Options{Root: root, Path: "data/openaudit.db", AutoMigrate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !strings.HasPrefix(s.Path(), filepath.Clean(root)) {
		t.Fatalf("db escaped root: %s", s.Path())
	}
	if st, err := os.Stat(filepath.Dir(s.Path())); err == nil && st.Mode().Perm() != 0o750 {
		t.Fatalf("dir perm=%o", st.Mode().Perm())
	}
	if st, err := os.Stat(s.Path()); err == nil && st.Mode().Perm() != 0o600 {
		t.Fatalf("file perm=%o", st.Mode().Perm())
	}
	var n int
	if err := s.DB().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM schema_migrations").Scan(&n); err != nil || n == 0 {
		t.Fatalf("migrations count=%d err=%v", n, err)
	}
}
func TestRepeatedMigrationIdempotent(t *testing.T) {
	s := newTestStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM schema_migrations").Scan(&n); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
func TestAuditLogsPaginationFiltersAndHits(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := time.Now().Add(-time.Hour)
	_, err := s.InsertAuditLog(ctx, storage.AuditLog{RequestID: "a", CreatedAt: old, Decision: "pass"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.InsertAuditLog(ctx, storage.AuditLog{RequestID: "b", CreatedAt: time.Now(), Decision: "block"}, []engine.Hit{{RuleID: "r1", Category: "cat", RiskLevel: "high", Type: "keyword", Match: "bad", NormalizedMatch: "bad", Start: 1, End: 4}})
	if err != nil {
		t.Fatal(err)
	}
	pg, err := s.QueryAuditLogs(ctx, storage.AuditFilter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if pg.Page.Total != 2 || !pg.Page.HasMore || pg.Items[0].RequestID != "b" {
		t.Fatalf("bad page: %+v", pg)
	}
	pg, err = s.QueryAuditLogs(ctx, storage.AuditFilter{Category: "cat", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Items) != 1 || pg.Items[0].RequestID != "b" {
		t.Fatalf("filter failed: %+v", pg)
	}
	hits, err := s.QueryRuleHits(ctx, id, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].RuleID != "r1" {
		t.Fatalf("hits=%+v", hits)
	}
	pg, err = s.QueryAuditLogs(ctx, storage.AuditFilter{Limit: 999999})
	if err != nil {
		t.Fatal(err)
	}
	if pg.Page.Limit != storage.MaxLimit {
		t.Fatalf("cap=%d", pg.Page.Limit)
	}
}
func TestRuleChangesImportBatchesAdminOperations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.InsertRuleChange(ctx, storage.RuleChange{ChangeID: "c1", Operation: "create", RuleID: "r1", Actor: "api"}); err != nil {
		t.Fatal(err)
	}
	cp, err := s.QueryRuleChanges(ctx, storage.ChangeFilter{RuleID: "r1", Limit: 10})
	if err != nil || len(cp.Items) != 1 {
		t.Fatalf("changes %+v %v", cp, err)
	}
	if err := s.InsertImportBatch(ctx, storage.ImportBatch{BatchID: "b1", Status: "success", RulesSeen: 3, RulesWritten: 2}); err != nil {
		t.Fatal(err)
	}
	bp, err := s.QueryImportBatches(ctx, storage.BatchFilter{Status: "success", Limit: 10})
	if err != nil || len(bp.Items) != 1 {
		t.Fatalf("batches %+v %v", bp, err)
	}
	if err := s.InsertAdminOperation(ctx, storage.AdminOperation{OperationID: "o1", Operation: "reload", Actor: "system", Status: "success"}); err != nil {
		t.Fatal(err)
	}
	ap, err := s.QueryAdminOperations(ctx, storage.AdminFilter{Operation: "reload", Limit: 10})
	if err != nil || len(ap.Items) != 1 {
		t.Fatalf("admin %+v %v", ap, err)
	}
}
func TestExportDataCSVCompatible(t *testing.T) {
	s := newTestStore(t)
	_, err := s.InsertAuditLog(context.Background(), storage.AuditLog{RequestID: "quoted", Decision: "pass", RawJSON: `{"x":"a,b"}`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pg, err := s.QueryAuditLogs(context.Background(), storage.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(pg.Items)
	if err != nil || !json.Valid(b) {
		t.Fatalf("json %v", err)
	}
	var xs []map[string]any
	if err := json.Unmarshal(b, &xs); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	w := csv.NewWriter(&out)
	_ = w.Write([]string{"request_id", "raw_json"})
	_ = w.Write([]string{pg.Items[0].RequestID, pg.Items[0].RawJSON})
	w.Flush()
	if _, err := csv.NewReader(strings.NewReader(out.String())).ReadAll(); err != nil {
		t.Fatal(err)
	}
}
func TestOpenRejectsTraversal(t *testing.T) {
	_, err := Open(context.Background(), Options{Root: t.TempDir(), Path: "../evil.db", AutoMigrate: true})
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}
