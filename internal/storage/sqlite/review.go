package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openaudit/openaudit/internal/storage"
)

func (s *Store) UpsertReviewPolicy(ctx context.Context, p storage.ReviewPolicyRecord) error {
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO review_policy (id,policy_json,version,updated_at,actor) VALUES (1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET policy_json=excluded.policy_json, version=excluded.version, updated_at=excluded.updated_at, actor=excluded.actor`, p.PolicyJSON, p.Version, ts(p.UpdatedAt), p.Actor)
	return err
}

func (s *Store) GetReviewPolicy(ctx context.Context) (storage.ReviewPolicyRecord, bool, error) {
	var p storage.ReviewPolicyRecord
	var updated string
	err := s.db.QueryRowContext(ctx, "SELECT policy_json,version,updated_at,actor FROM review_policy WHERE id = 1").Scan(&p.PolicyJSON, &p.Version, &updated, &p.Actor)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ReviewPolicyRecord{}, false, nil
	}
	if err != nil {
		return storage.ReviewPolicyRecord{}, false, err
	}
	p.UpdatedAt = parseTS(updated)
	return p, true, nil
}

func (s *Store) CreateReviewCase(ctx context.Context, c storage.ReviewCase, ev storage.ReviewCaseEvent) (storage.ReviewCase, bool, error) {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storage.ReviewCase{}, false, err
	}
	if c.ContextHash != "" {
		if existing, ok, err := getReviewCaseByContextTx(ctx, tx, c.ContextHash); err != nil {
			_ = tx.Rollback()
			return storage.ReviewCase{}, false, err
		} else if ok {
			_ = tx.Rollback()
			return existing, false, nil
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO review_cases (case_id,audit_id,source,status,priority,deterministic_decision,temporary_action,ai_score,ai_risk_level,ai_recommendation,variant_score,variant_risk_level,category,content_excerpt,content_hash,context_hash,matched_rules_json,ai_review_json,variant_review_json,decision_json,metadata_json,reviewer,operator_note,created_at,updated_at,decided_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, c.CaseID, c.AuditID, c.Source, c.Status, c.Priority, c.DeterministicDecision, c.TemporaryAction, c.AIScore, c.AIRiskLevel, c.AIRecommendation, c.VariantScore, c.VariantRiskLevel, c.Category, c.ContentExcerpt, c.ContentHash, c.ContextHash, c.MatchedRulesJSON, c.AIReviewJSON, c.VariantReviewJSON, c.DecisionJSON, c.MetadataJSON, c.Reviewer, c.OperatorNote, ts(c.CreatedAt), ts(c.UpdatedAt), nullableTS(c.DecidedAt), nullableTS(c.ExpiresAt))
	if err != nil {
		_ = tx.Rollback()
		return storage.ReviewCase{}, false, err
	}
	if ev.Action != "" {
		if ev.CreatedAt.IsZero() {
			ev.CreatedAt = c.CreatedAt
		}
		if _, err = insertReviewEventTx(ctx, tx, ev); err != nil {
			_ = tx.Rollback()
			return storage.ReviewCase{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return storage.ReviewCase{}, false, err
	}
	return c, true, nil
}

func getReviewCaseByContextTx(ctx context.Context, tx *sql.Tx, contextHash string) (storage.ReviewCase, bool, error) {
	row := tx.QueryRowContext(ctx, reviewCaseSelectSQL()+` WHERE context_hash = ? AND status IN ('pending','reviewing') ORDER BY created_at DESC, id DESC LIMIT 1`, contextHash)
	c, err := scanReviewCase(row)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ReviewCase{}, false, nil
	}
	if err != nil {
		return storage.ReviewCase{}, false, err
	}
	return c, true, nil
}

func (s *Store) QueryReviewCases(ctx context.Context, f storage.ReviewFilter) (storage.ReviewPage, error) {
	limit, offset := storage.NormalizeLimitOffset(f.Limit, f.Offset)
	where, args := reviewWhere(f)
	wc := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM review_cases WHERE "+wc, args...).Scan(&total); err != nil {
		return storage.ReviewPage{}, err
	}
	sortCol := reviewSortColumn(f.Sort)
	dir := "DESC"
	if strings.EqualFold(f.Direction, "asc") {
		dir = "ASC"
	}
	qargs := append(append([]any{}, args...), limit, offset)
	// #nosec G202 -- wc and sort are assembled from fixed allowlisted predicates and columns; request values are SQL parameters.
	rows, err := s.db.QueryContext(ctx, reviewCaseSelectSQL()+" WHERE "+wc+" ORDER BY "+sortCol+" "+dir+", id DESC LIMIT ? OFFSET ?", qargs...)
	if err != nil {
		return storage.ReviewPage{}, err
	}
	defer rows.Close()
	items := []storage.ReviewCase{}
	for rows.Next() {
		item, err := scanReviewCase(rows)
		if err != nil {
			return storage.ReviewPage{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return storage.ReviewPage{}, err
	}
	return storage.ReviewPage{Items: items, Page: page(total, limit, offset)}, nil
}

func reviewWhere(f storage.ReviewFilter) ([]string, []any) {
	where, args := []string{"1=1"}, []any{}
	add := func(col, v string) {
		if v != "" {
			where = append(where, col+" = ?")
			args = append(args, v)
		}
	}
	add("status", f.Status)
	add("priority", f.Priority)
	add("category", f.Category)
	add("source", f.Source)
	add("temporary_action", f.TemporaryAction)
	add("ai_risk_level", f.AIRiskLevel)
	add("variant_risk_level", f.VariantRiskLevel)
	if f.HasMinScore {
		where = append(where, "(ai_score >= ? OR variant_score >= ?)")
		args = append(args, f.MinScore, f.MinScore)
	}
	if f.HasMaxScore {
		where = append(where, "(ai_score <= ? OR variant_score <= ?)")
		args = append(args, f.MaxScore, f.MaxScore)
	}
	if !f.CreatedFrom.IsZero() {
		where = append(where, "created_at >= ?")
		args = append(args, ts(f.CreatedFrom))
	}
	if !f.CreatedTo.IsZero() {
		where = append(where, "created_at <= ?")
		args = append(args, ts(f.CreatedTo))
	}
	return where, args
}

func reviewSortColumn(sort string) string {
	switch sort {
	case "updated_at":
		return "updated_at"
	case "priority":
		return "priority"
	case "ai_score":
		return "ai_score"
	case "variant_score":
		return "variant_score"
	case "status":
		return "status"
	default:
		return "created_at"
	}
}

func (s *Store) GetReviewCase(ctx context.Context, caseID string) (storage.ReviewCase, []storage.ReviewCaseEvent, bool, error) {
	row := s.db.QueryRowContext(ctx, reviewCaseSelectSQL()+" WHERE case_id = ?", caseID)
	c, err := scanReviewCase(row)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ReviewCase{}, nil, false, nil
	}
	if err != nil {
		return storage.ReviewCase{}, nil, false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,case_id,created_at,actor,action,previous_status,new_status,note,metadata_json FROM review_case_events WHERE case_id = ? ORDER BY created_at ASC, id ASC`, caseID)
	if err != nil {
		return storage.ReviewCase{}, nil, false, err
	}
	defer rows.Close()
	var events []storage.ReviewCaseEvent
	for rows.Next() {
		ev, err := scanReviewEvent(rows)
		if err != nil {
			return storage.ReviewCase{}, nil, false, err
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return storage.ReviewCase{}, nil, false, err
	}
	return c, events, true, nil
}

func (s *Store) DecideReviewCase(ctx context.Context, caseID, action, actor, note, metadataJSON string) (storage.ReviewCase, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storage.ReviewCase{}, err
	}
	out, err := decideReviewCaseTx(ctx, tx, caseID, action, actor, note, metadataJSON)
	if err != nil {
		_ = tx.Rollback()
		return storage.ReviewCase{}, err
	}
	return out, tx.Commit()
}

func (s *Store) BulkDecideReviewCases(ctx context.Context, ids []string, action, actor, note string) ([]storage.ReviewCase, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make([]storage.ReviewCase, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			_ = tx.Rollback()
			return nil, fmt.Errorf("duplicate case_id %q", id)
		}
		seen[id] = true
		c, err := decideReviewCaseTx(ctx, tx, id, action, actor, note, `{"bulk":true}`)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		out = append(out, c)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func decideReviewCaseTx(ctx context.Context, tx *sql.Tx, caseID, action, actor, note, metadataJSON string) (storage.ReviewCase, error) {
	row := tx.QueryRowContext(ctx, reviewCaseSelectSQL()+" WHERE case_id = ?", caseID)
	c, err := scanReviewCase(row)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ReviewCase{}, fmt.Errorf("case_id %q not found", caseID)
	}
	if err != nil {
		return storage.ReviewCase{}, err
	}
	prev := c.Status
	next, decided := reviewStatusForAction(action, prev)
	now := time.Now().UTC()
	if next == "" {
		return storage.ReviewCase{}, fmt.Errorf("invalid review action %q", action)
	}
	if action == "add_note" {
		c.OperatorNote = appendNote(c.OperatorNote, note)
	} else {
		c.Status = next
		c.Reviewer = actor
		if note != "" {
			c.OperatorNote = appendNote(c.OperatorNote, note)
		}
		if decided {
			c.DecidedAt = now
		} else {
			c.DecidedAt = time.Time{}
		}
	}
	c.UpdatedAt = now
	_, err = tx.ExecContext(ctx, `UPDATE review_cases SET status=?, reviewer=?, operator_note=?, updated_at=?, decided_at=? WHERE case_id=?`, c.Status, c.Reviewer, c.OperatorNote, ts(c.UpdatedAt), nullableTS(c.DecidedAt), caseID)
	if err != nil {
		return storage.ReviewCase{}, err
	}
	_, err = insertReviewEventTx(ctx, tx, storage.ReviewCaseEvent{CaseID: caseID, CreatedAt: now, Actor: actor, Action: action, PreviousStatus: prev, NewStatus: c.Status, Note: note, MetadataJSON: metadataJSON})
	return c, err
}

func reviewStatusForAction(action, current string) (string, bool) {
	switch action {
	case "approve":
		return "approved", true
	case "reject":
		return "rejected", true
	case "ignore":
		return "ignored", true
	case "escalate":
		return "escalated", false
	case "reopen":
		return "pending", false
	case "add_note":
		return current, false
	default:
		return "", false
	}
}

func appendNote(existing, note string) string {
	note = strings.TrimSpace(note)
	if note == "" {
		return existing
	}
	if existing == "" {
		return note
	}
	return existing + "\n" + note
}

func (s *Store) ReviewStats(ctx context.Context) (storage.ReviewStats, error) {
	var st storage.ReviewStats
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM review_cases").Scan(&st.Total); err != nil {
		return storage.ReviewStats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM review_cases WHERE status IN ('pending','reviewing')").Scan(&st.Pending); err != nil {
		return storage.ReviewStats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM review_cases WHERE status IN ('pending','reviewing') AND priority = 'critical'").Scan(&st.CriticalPending); err != nil {
		return storage.ReviewStats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM review_cases WHERE temporary_action = 'temporary_block'").Scan(&st.TemporaryBlocked); err != nil {
		return storage.ReviewStats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM review_cases WHERE temporary_action = 'temporary_allow'").Scan(&st.TemporaryAllowed); err != nil {
		return storage.ReviewStats{}, err
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM review_cases WHERE decided_at >= ?", ts(today)).Scan(&st.ReviewedToday); err != nil {
		return storage.ReviewStats{}, err
	}
	var avg sql.NullFloat64
	if err := s.db.QueryRowContext(ctx, "SELECT AVG((julianday('now') - julianday(created_at)) * 24.0) FROM review_cases WHERE status IN ('pending','reviewing')").Scan(&avg); err != nil {
		return storage.ReviewStats{}, err
	}
	if avg.Valid {
		st.AverageAgeHours = avg.Float64
	}
	return st, nil
}

func insertReviewEventTx(ctx context.Context, tx *sql.Tx, ev storage.ReviewCaseEvent) (sql.Result, error) {
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	return tx.ExecContext(ctx, `INSERT INTO review_case_events (case_id,created_at,actor,action,previous_status,new_status,note,metadata_json) VALUES (?,?,?,?,?,?,?,?)`, ev.CaseID, ts(ev.CreatedAt), ev.Actor, ev.Action, ev.PreviousStatus, ev.NewStatus, ev.Note, ev.MetadataJSON)
}

func reviewCaseSelectSQL() string {
	return `SELECT id,case_id,audit_id,source,status,priority,deterministic_decision,temporary_action,ai_score,ai_risk_level,ai_recommendation,variant_score,variant_risk_level,category,content_excerpt,content_hash,context_hash,matched_rules_json,ai_review_json,variant_review_json,decision_json,metadata_json,reviewer,operator_note,created_at,updated_at,decided_at,expires_at FROM review_cases`
}

type scanner interface {
	Scan(dest ...any) error
}

func scanReviewCase(row scanner) (storage.ReviewCase, error) {
	var c storage.ReviewCase
	var created, updated string
	var decided, expires sql.NullString
	err := row.Scan(&c.ID, &c.CaseID, &c.AuditID, &c.Source, &c.Status, &c.Priority, &c.DeterministicDecision, &c.TemporaryAction, &c.AIScore, &c.AIRiskLevel, &c.AIRecommendation, &c.VariantScore, &c.VariantRiskLevel, &c.Category, &c.ContentExcerpt, &c.ContentHash, &c.ContextHash, &c.MatchedRulesJSON, &c.AIReviewJSON, &c.VariantReviewJSON, &c.DecisionJSON, &c.MetadataJSON, &c.Reviewer, &c.OperatorNote, &created, &updated, &decided, &expires)
	if err != nil {
		return storage.ReviewCase{}, err
	}
	c.CreatedAt = parseTS(created)
	c.UpdatedAt = parseTS(updated)
	if decided.Valid {
		c.DecidedAt = parseTS(decided.String)
	}
	if expires.Valid {
		c.ExpiresAt = parseTS(expires.String)
	}
	return c, nil
}

func scanReviewEvent(row scanner) (storage.ReviewCaseEvent, error) {
	var ev storage.ReviewCaseEvent
	var created string
	if err := row.Scan(&ev.ID, &ev.CaseID, &created, &ev.Actor, &ev.Action, &ev.PreviousStatus, &ev.NewStatus, &ev.Note, &ev.MetadataJSON); err != nil {
		return storage.ReviewCaseEvent{}, err
	}
	ev.CreatedAt = parseTS(created)
	return ev, nil
}

func nullableTS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return ts(t)
}
