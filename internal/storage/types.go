package storage

import (
	"context"
	"time"

	"github.com/openaudit/openaudit/internal/engine"
)

const (
	DefaultLimit = 50
	MaxLimit     = 500
	ExportMax    = 10000
)

type Page struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	Total   int  `json:"total"`
	HasMore bool `json:"has_more"`
}

func NormalizeLimitOffset(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
func NormalizeExportLimit(limit int) int {
	if limit <= 0 || limit > ExportMax {
		return ExportMax
	}
	return limit
}

type AuditLog struct {
	ID              int64     `json:"id"`
	RequestID       string    `json:"request_id"`
	CreatedAt       time.Time `json:"created_at"`
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	ClientIP        string    `json:"client_ip"`
	APIKeyID        string    `json:"api_key_id,omitempty"`
	Decision        string    `json:"decision"`
	StatusCode      int       `json:"status_code"`
	DurationMS      int64     `json:"duration_ms"`
	RequestBytes    int       `json:"request_bytes"`
	NormalizedBytes int       `json:"normalized_bytes"`
	MatchCount      int       `json:"match_count"`
	RuleHitCount    int       `json:"rule_hit_count"`
	MetadataJSON    string    `json:"metadata_json,omitempty"`
	RawJSON         string    `json:"raw_json,omitempty"`
	Hits            []RuleHit `json:"hits,omitempty"`
}
type RuleHit struct {
	ID             int64  `json:"id"`
	AuditLogID     int64  `json:"audit_log_id"`
	RequestID      string `json:"request_id"`
	RuleID         string `json:"rule_id"`
	RuleName       string `json:"rule_name"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	MatchType      string `json:"match_type"`
	MatchedText    string `json:"matched_text"`
	NormalizedText string `json:"normalized_text"`
	StartPos       int    `json:"start_pos"`
	EndPos         int    `json:"end_pos"`
	MetadataJSON   string `json:"metadata_json,omitempty"`
}
type AuditFilter struct {
	Action    string
	Matched   *bool
	Category  string
	Query     string
	RequestID string
	Limit     int
	Offset    int
}
type AuditPage struct {
	Items []AuditLog `json:"items"`
	Page  Page       `json:"page"`
}

type RuleChange struct {
	ID           int64     `json:"id"`
	ChangeID     string    `json:"change_id"`
	CreatedAt    time.Time `json:"created_at"`
	Actor        string    `json:"actor"`
	Operation    string    `json:"operation"`
	Source       string    `json:"source"`
	RuleID       string    `json:"rule_id"`
	RuleName     string    `json:"rule_name"`
	FilePath     string    `json:"file_path"`
	BeforeHash   string    `json:"before_hash"`
	AfterHash    string    `json:"after_hash"`
	DiffJSON     string    `json:"diff_json"`
	MetadataJSON string    `json:"metadata_json"`
	RawJSON      string    `json:"raw_json"`
}
type ChangeFilter struct {
	RuleID, Operation, Actor, Source, ImportBatchID string
	Limit, Offset                                   int
}
type ChangePage struct {
	Items []RuleChange `json:"items"`
	Page  Page         `json:"page"`
}

type ImportBatch struct {
	ID           int64     `json:"id"`
	BatchID      string    `json:"batch_id"`
	CreatedAt    time.Time `json:"created_at"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	Status       string    `json:"status"`
	DryRun       bool      `json:"dry_run"`
	InputRoot    string    `json:"input_root"`
	OutputRoot   string    `json:"output_root"`
	ReportPath   string    `json:"report_path"`
	ReportFormat string    `json:"report_format"`
	RulesSeen    int       `json:"rules_seen"`
	RulesWritten int       `json:"rules_written"`
	RulesSkipped int       `json:"rules_skipped"`
	ErrorsCount  int       `json:"errors_count"`
	StatsJSON    string    `json:"stats_json"`
	ErrorsJSON   string    `json:"errors_json"`
	RawJSON      string    `json:"raw_json"`
}
type BatchFilter struct {
	Source, Status string
	Limit, Offset  int
}
type BatchPage struct {
	Items []ImportBatch `json:"items"`
	Page  Page          `json:"page"`
}

type AdminOperation struct {
	ID           int64     `json:"id"`
	OperationID  string    `json:"operation_id"`
	CreatedAt    time.Time `json:"created_at"`
	Actor        string    `json:"actor"`
	ClientIP     string    `json:"client_ip"`
	Operation    string    `json:"operation"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Status       string    `json:"status"`
	StatusCode   int       `json:"status_code"`
	MetadataJSON string    `json:"metadata_json"`
	RawJSON      string    `json:"raw_json"`
}
type AdminFilter struct {
	Operation, Actor, ResourceType, ResourceID string
	Limit, Offset                              int
}
type AdminPage struct {
	Items []AdminOperation `json:"items"`
	Page  Page             `json:"page"`
}

type RuleLifecycle struct {
	ID           int64     `json:"id"`
	RuleID       string    `json:"rule_id"`
	State        string    `json:"state"`
	UpdatedAt    time.Time `json:"updated_at"`
	Actor        string    `json:"actor"`
	Source       string    `json:"source"`
	MetadataJSON string    `json:"metadata_json,omitempty"`
}
type LifecycleFilter struct {
	RuleID, State string
	Limit, Offset int
}
type LifecyclePage struct {
	Items []RuleLifecycle `json:"items"`
	Page  Page            `json:"page"`
}

type RuleRelease struct {
	ID             int64     `json:"id"`
	Version        string    `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	Actor          string    `json:"actor"`
	Status         string    `json:"status"`
	RuleCount      int       `json:"rule_count"`
	AddedCount     int       `json:"added_count"`
	UpdatedCount   int       `json:"updated_count"`
	RemovedCount   int       `json:"removed_count"`
	SnapshotPath   string    `json:"snapshot_path"`
	ValidationJSON string    `json:"validation_json,omitempty"`
	MetadataJSON   string    `json:"metadata_json,omitempty"`
}
type ReleaseFilter struct {
	Status        string
	Limit, Offset int
}
type ReleasePage struct {
	Items []RuleRelease `json:"items"`
	Page  Page          `json:"page"`
}
type RuleReleaseItem struct {
	ID           int64  `json:"id"`
	Version      string `json:"version"`
	RuleID       string `json:"rule_id"`
	Operation    string `json:"operation"`
	BeforeHash   string `json:"before_hash"`
	AfterHash    string `json:"after_hash"`
	FilePath     string `json:"file_path"`
	MetadataJSON string `json:"metadata_json,omitempty"`
}
type RuleValidationRun struct {
	ID             int64     `json:"id"`
	RunID          string    `json:"run_id"`
	CreatedAt      time.Time `json:"created_at"`
	Actor          string    `json:"actor"`
	TargetState    string    `json:"target_state"`
	TargetVersion  string    `json:"target_version"`
	Status         string    `json:"status"`
	ConflictsJSON  string    `json:"conflicts_json,omitempty"`
	SimulationJSON string    `json:"simulation_json,omitempty"`
	MetadataJSON   string    `json:"metadata_json,omitempty"`
}

type ReviewCase struct {
	ID                    int64     `json:"id,omitempty"`
	CaseID                string    `json:"case_id"`
	AuditID               string    `json:"audit_id,omitempty"`
	Source                string    `json:"source"`
	Status                string    `json:"status"`
	Priority              string    `json:"priority"`
	DeterministicDecision string    `json:"deterministic_decision,omitempty"`
	TemporaryAction       string    `json:"temporary_action"`
	AIScore               float64   `json:"ai_score,omitempty"`
	AIRiskLevel           string    `json:"ai_risk_level,omitempty"`
	AIRecommendation      string    `json:"ai_recommendation,omitempty"`
	VariantScore          float64   `json:"variant_score,omitempty"`
	VariantRiskLevel      string    `json:"variant_risk_level,omitempty"`
	Category              string    `json:"category,omitempty"`
	ContentExcerpt        string    `json:"content_excerpt,omitempty"`
	ContentHash           string    `json:"content_hash,omitempty"`
	ContextHash           string    `json:"context_hash,omitempty"`
	MatchedRulesJSON      string    `json:"matched_rules_json,omitempty"`
	AIReviewJSON          string    `json:"ai_review_json,omitempty"`
	VariantReviewJSON     string    `json:"variant_review_json,omitempty"`
	DecisionJSON          string    `json:"decision_json,omitempty"`
	MetadataJSON          string    `json:"metadata_json,omitempty"`
	Reviewer              string    `json:"reviewer,omitempty"`
	OperatorNote          string    `json:"operator_note,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	DecidedAt             time.Time `json:"decided_at,omitempty"`
	ExpiresAt             time.Time `json:"expires_at,omitempty"`
}
type ReviewCaseEvent struct {
	ID             int64     `json:"id,omitempty"`
	CaseID         string    `json:"case_id"`
	CreatedAt      time.Time `json:"created_at"`
	Actor          string    `json:"actor,omitempty"`
	Action         string    `json:"action"`
	PreviousStatus string    `json:"previous_status,omitempty"`
	NewStatus      string    `json:"new_status,omitempty"`
	Note           string    `json:"note,omitempty"`
	MetadataJSON   string    `json:"metadata_json,omitempty"`
}
type ReviewPolicyRecord struct {
	PolicyJSON string    `json:"policy_json"`
	Version    string    `json:"version"`
	UpdatedAt  time.Time `json:"updated_at"`
	Actor      string    `json:"actor,omitempty"`
}
type ReviewFilter struct {
	Status, Priority, Category, Source, TemporaryAction, AIRiskLevel, VariantRiskLevel string
	MinScore, MaxScore                                                                 float64
	HasMinScore, HasMaxScore                                                           bool
	CreatedFrom, CreatedTo                                                             time.Time
	Sort, Direction                                                                    string
	Limit, Offset                                                                      int
}
type ReviewPage struct {
	Items []ReviewCase `json:"items"`
	Page  Page         `json:"page"`
}
type ReviewStats struct {
	Pending          int     `json:"pending"`
	CriticalPending  int     `json:"critical_pending"`
	TemporaryBlocked int     `json:"temporary_blocked"`
	TemporaryAllowed int     `json:"temporary_allowed"`
	ReviewedToday    int     `json:"reviewed_today"`
	AverageAgeHours  float64 `json:"average_age_hours"`
	Total            int     `json:"total"`
}

type Store interface {
	Close() error
	InsertAuditLog(context.Context, AuditLog, []engine.Hit) (int64, error)
	QueryAuditLogs(context.Context, AuditFilter) (AuditPage, error)
	QueryRuleHits(context.Context, int64, string) ([]RuleHit, error)
	InsertRuleChange(context.Context, RuleChange) error
	QueryRuleChanges(context.Context, ChangeFilter) (ChangePage, error)
	InsertImportBatch(context.Context, ImportBatch) error
	QueryImportBatches(context.Context, BatchFilter) (BatchPage, error)
	InsertAdminOperation(context.Context, AdminOperation) error
	QueryAdminOperations(context.Context, AdminFilter) (AdminPage, error)
	UpsertRuleLifecycle(context.Context, RuleLifecycle) error
	QueryRuleLifecycle(context.Context, LifecycleFilter) (LifecyclePage, error)
	InsertRuleRelease(context.Context, RuleRelease, []RuleReleaseItem) error
	QueryRuleReleases(context.Context, ReleaseFilter) (ReleasePage, error)
	GetRuleRelease(context.Context, string) (RuleRelease, []RuleReleaseItem, bool, error)
	InsertRuleValidationRun(context.Context, RuleValidationRun) error
	UpsertReviewPolicy(context.Context, ReviewPolicyRecord) error
	GetReviewPolicy(context.Context) (ReviewPolicyRecord, bool, error)
	CreateReviewCase(context.Context, ReviewCase, ReviewCaseEvent) (ReviewCase, bool, error)
	QueryReviewCases(context.Context, ReviewFilter) (ReviewPage, error)
	GetReviewCase(context.Context, string) (ReviewCase, []ReviewCaseEvent, bool, error)
	DecideReviewCase(context.Context, string, string, string, string, string) (ReviewCase, error)
	BulkDecideReviewCases(context.Context, []string, string, string, string) ([]ReviewCase, error)
	ReviewStats(context.Context) (ReviewStats, error)
}
