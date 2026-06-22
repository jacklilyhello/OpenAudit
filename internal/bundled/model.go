package bundled

import "time"

const (
	SchemaVersion     = 1
	ProviderNetEase   = "netease"
	GeneratorName     = "openaudit-bundled-rules"
	GeneratorVersion  = "phase-a"
	PCRE2NotChecked   = "not_checked"
	PCRE2Compatible   = "compatible"
	PCRE2Incompatible = "incompatible"
)

type Limits struct {
	InputJSONBytes        int64
	CompressedPackBytes   int64
	UncompressedPackBytes int64
	RuleCount             int
	PatternBytes          int
	MetadataBytes         int
	ReportBytes           int64
}

func DefaultLimits() Limits {
	return Limits{InputJSONBytes: 4 << 20, CompressedPackBytes: 4 << 20, UncompressedPackBytes: 16 << 20, RuleCount: 20000, PatternBytes: 256 << 10, MetadataBytes: 64 << 10, ReportBytes: 2 << 20}
}

type Pack struct {
	SchemaVersion     int        `json:"schema_version"`
	Provider          string     `json:"provider"`
	Dataset           string     `json:"dataset"`
	SourceRepository  string     `json:"source_repository"`
	SourceCommit      string     `json:"source_commit"`
	SourceFilePath    string     `json:"source_file_path"`
	SourceInputSHA256 string     `json:"source_input_sha256"`
	LicenseIdentifier string     `json:"license_identifier"`
	SourceTimestamp   string     `json:"deterministic_source_timestamp"`
	GeneratorName     string     `json:"generator_name"`
	GeneratorVersion  string     `json:"generator_version"`
	Counts            Counts     `json:"counts"`
	Rules             []PackRule `json:"rules"`
}

type Counts struct {
	TotalSourceRules      int         `json:"total_source_rules"`
	ParsedRules           int         `json:"parsed_rules"`
	ImportedRecords       int         `json:"imported_records"`
	EmptyRecords          int         `json:"empty_records"`
	MalformedRecords      int         `json:"malformed_records"`
	UnknownRecords        int         `json:"unknown_records"`
	DuplicateIdentities   int         `json:"duplicate_identities"`
	DuplicateRegexContent int         `json:"duplicate_regex_content"`
	RE2Compatible         int         `json:"re2_compatible_rules"`
	RE2Incompatible       int         `json:"re2_incompatible_rules"`
	DisabledRules         int         `json:"disabled_rules"`
	ByDataset             []NameCount `json:"counts_by_dataset"`
	ByGroup               []NameCount `json:"counts_by_group"`
	PCRE2Status           []NameCount `json:"pcre2_status_counts"`
}
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}
type UnknownGroup struct {
	Name        string `json:"name"`
	RecordCount int    `json:"record_count"`
}
type MalformedRecord struct {
	Dataset    string `json:"dataset"`
	Group      string `json:"group"`
	UpstreamID string `json:"upstream_id"`
	Reason     string `json:"reason"`
	ValueType  string `json:"value_type"`
}

type PackRule struct {
	ID             string       `json:"id"`
	Provider       string       `json:"provider"`
	Dataset        string       `json:"dataset"`
	Group          string       `json:"group"`
	UpstreamID     string       `json:"upstream_id"`
	OriginalRegex  string       `json:"original_regex"`
	Type           string       `json:"type"`
	Category       string       `json:"category"`
	RiskLevel      string       `json:"risk_level"`
	Action         string       `json:"action"`
	Score          int          `json:"score"`
	Source         string       `json:"source"`
	Tags           []string     `json:"tags"`
	Description    string       `json:"description"`
	Enabled        bool         `json:"enabled"`
	Metadata       RuleMetadata `json:"metadata"`
	RE2Compatible  bool         `json:"re2_compatible"`
	RE2Error       string       `json:"re2_error,omitempty"`
	RE2FeatureHint string       `json:"re2_feature_hint,omitempty"`
	PCRE2Status    string       `json:"pcre2_status"`
	PCRE2Error     string       `json:"pcre2_error,omitempty"`
}
type RuleMetadata struct {
	UpstreamBehavior         string `json:"upstream_behavior"`
	ReplacementTextAvailable bool   `json:"replacement_text_available"`
}

type Report struct {
	SchemaVersion          int                    `json:"schema_version"`
	Provider               string                 `json:"provider"`
	Dataset                string                 `json:"dataset"`
	UpstreamRepository     string                 `json:"upstream_repository"`
	PinnedSourceCommit     string                 `json:"pinned_source_commit"`
	SourceFilePath         string                 `json:"source_file_path"`
	SourceInputBytes       int64                  `json:"source_input_bytes"`
	SourceInputSHA256      string                 `json:"source_input_sha256"`
	GeneratedPackPath      string                 `json:"generated_pack_path"`
	GeneratedReportPath    string                 `json:"generated_report_path"`
	GeneratedPackBytes     int64                  `json:"generated_pack_bytes"`
	GeneratedPackSHA256    string                 `json:"generated_pack_sha256"`
	TotalSourceRules       int                    `json:"total_source_rules"`
	ParsedRules            int                    `json:"parsed_rules"`
	ImportedRecords        int                    `json:"imported_records"`
	EmptyRecords           int                    `json:"empty_records"`
	MalformedRecords       int                    `json:"malformed_records"`
	UnknownRecords         int                    `json:"unknown_records"`
	MalformedRecordDetails []MalformedRecord      `json:"malformed_record_details"`
	DuplicateIdentities    int                    `json:"duplicate_identities"`
	DuplicateRegexContent  int                    `json:"duplicate_regex_content"`
	RE2CompatibleRules     int                    `json:"re2_compatible_rules"`
	RE2IncompatibleRules   int                    `json:"re2_incompatible_rules"`
	PCRE2StatusCounts      []NameCount            `json:"pcre2_status_counts"`
	DisabledRules          int                    `json:"disabled_rules"`
	CountsByDataset        []NameCount            `json:"counts_by_dataset"`
	CountsByGroup          []NameCount            `json:"counts_by_group"`
	UnknownGroups          []UnknownGroup         `json:"unknown_groups"`
	CompatibilityFailures  []CompatibilityFailure `json:"compatibility_failures"`
	GeneratedOutputFiles   []string               `json:"generated_output_files"`
}
type CompatibilityFailure struct {
	Dataset         string `json:"dataset"`
	Group           string `json:"group"`
	UpstreamID      string `json:"upstream_id"`
	GeneratedRuleID string `json:"generated_rule_id"`
	PatternSHA256   string `json:"pattern_sha256"`
	CompilerError   string `json:"compiler_error"`
	FeatureHint     string `json:"feature_hint,omitempty"`
}

type Options struct {
	Dataset, SourceRepository, SourceCommit, SourceFilePath, OutputPath, ReportPath string
	Timestamp                                                                       time.Time
	LicenseIdentifier                                                               string
	Limits                                                                          Limits
}
