package rulehistory

import "time"

type Action string

const (
	ActionCreate   Action = "create"
	ActionUpdate   Action = "update"
	ActionDelete   Action = "delete"
	ActionEnable   Action = "enable"
	ActionDisable  Action = "disable"
	ActionImport   Action = "import"
	ActionRollback Action = "rollback"
	ActionReload   Action = "reload"
)

type DiffSummary struct {
	AddedLines   int `json:"added_lines"`
	RemovedLines int `json:"removed_lines"`
}
type Diff struct {
	Added   []string    `json:"added"`
	Removed []string    `json:"removed"`
	Summary DiffSummary `json:"summary"`
}

type Change struct {
	ChangeID      string    `json:"change_id"`
	Timestamp     time.Time `json:"timestamp"`
	Actor         string    `json:"actor"`
	Action        Action    `json:"action"`
	RuleID        string    `json:"rule_id,omitempty"`
	RuleType      string    `json:"rule_type,omitempty"`
	Category      string    `json:"category,omitempty"`
	Source        string    `json:"source,omitempty"`
	Before        string    `json:"before,omitempty"`
	After         string    `json:"after,omitempty"`
	Diff          Diff      `json:"diff"`
	FilePath      string    `json:"file_path,omitempty"`
	ImportBatchID string    `json:"import_batch_id,omitempty"`
	ReloadSuccess bool      `json:"reload_success"`
	ReloadError   string    `json:"reload_error,omitempty"`
	Note          string    `json:"note,omitempty"`
	RemoteAddr    string    `json:"remote_addr,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
}

type Filter struct {
	RuleID, Action, Actor, Source, ImportBatchID string
	Limit, Offset                                int
}
type Stats struct {
	TotalChanges  int            `json:"total_changes"`
	Actions       map[string]int `json:"actions"`
	Actors        map[string]int `json:"actors"`
	Sources       map[string]int `json:"sources"`
	RecentChanges []Change       `json:"recent_changes"`
}
