package migrations

type Migration struct {
	ID  string
	SQL string
}

var All = []Migration{{ID: "001_phase10_core", SQL: `
CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, created_at TEXT NOT NULL, method TEXT, path TEXT, client_ip TEXT, api_key_id TEXT, decision TEXT, status_code INTEGER, duration_ms INTEGER, request_bytes INTEGER, normalized_bytes INTEGER, match_count INTEGER, rule_hit_count INTEGER, metadata_json TEXT, raw_json TEXT);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_decision ON audit_logs(decision);
CREATE INDEX IF NOT EXISTS idx_audit_logs_client_ip ON audit_logs(client_ip);
CREATE TABLE IF NOT EXISTS rule_hits (id INTEGER PRIMARY KEY AUTOINCREMENT, audit_log_id INTEGER, request_id TEXT, rule_id TEXT, rule_name TEXT, category TEXT, severity TEXT, match_type TEXT, matched_text TEXT, normalized_text TEXT, start_pos INTEGER, end_pos INTEGER, metadata_json TEXT, FOREIGN KEY(audit_log_id) REFERENCES audit_logs(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_rule_hits_audit_log_id ON rule_hits(audit_log_id);
CREATE INDEX IF NOT EXISTS idx_rule_hits_request_id ON rule_hits(request_id);
CREATE INDEX IF NOT EXISTS idx_rule_hits_rule_id ON rule_hits(rule_id);
CREATE TABLE IF NOT EXISTS rule_changes (id INTEGER PRIMARY KEY AUTOINCREMENT, change_id TEXT UNIQUE, created_at TEXT NOT NULL, actor TEXT, operation TEXT, source TEXT, rule_id TEXT, rule_name TEXT, file_path TEXT, before_hash TEXT, after_hash TEXT, diff_json TEXT, metadata_json TEXT, raw_json TEXT);
CREATE INDEX IF NOT EXISTS idx_rule_changes_created_at ON rule_changes(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_rule_changes_rule_id ON rule_changes(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_changes_operation ON rule_changes(operation);
CREATE INDEX IF NOT EXISTS idx_rule_changes_source ON rule_changes(source);
CREATE TABLE IF NOT EXISTS import_batches (id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT UNIQUE, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, status TEXT, dry_run INTEGER, input_root TEXT, output_root TEXT, report_path TEXT, report_format TEXT, rules_seen INTEGER, rules_written INTEGER, rules_skipped INTEGER, errors_count INTEGER, stats_json TEXT, errors_json TEXT, raw_json TEXT);
CREATE INDEX IF NOT EXISTS idx_import_batches_created_at ON import_batches(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_import_batches_batch_id ON import_batches(batch_id);
CREATE INDEX IF NOT EXISTS idx_import_batches_status ON import_batches(status);
CREATE TABLE IF NOT EXISTS admin_operations (id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT, created_at TEXT NOT NULL, actor TEXT, client_ip TEXT, operation TEXT, resource_type TEXT, resource_id TEXT, status TEXT, status_code INTEGER, metadata_json TEXT, raw_json TEXT);
CREATE INDEX IF NOT EXISTS idx_admin_operations_created_at ON admin_operations(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_admin_operations_operation ON admin_operations(operation);
CREATE INDEX IF NOT EXISTS idx_admin_operations_actor ON admin_operations(actor);
CREATE INDEX IF NOT EXISTS idx_admin_operations_resource_type ON admin_operations(resource_type);
CREATE INDEX IF NOT EXISTS idx_admin_operations_resource_id ON admin_operations(resource_id);
`}, {ID: "002_phase11_rule_release", SQL: `
CREATE TABLE IF NOT EXISTS rule_lifecycle (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, actor TEXT, source TEXT, metadata_json TEXT, UNIQUE(rule_id, state));
CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_rule_id ON rule_lifecycle(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_lifecycle_state ON rule_lifecycle(state);
CREATE TABLE IF NOT EXISTS rule_releases (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, actor TEXT, status TEXT, rule_count INTEGER, added_count INTEGER, updated_count INTEGER, removed_count INTEGER, snapshot_path TEXT, validation_json TEXT, metadata_json TEXT);
CREATE INDEX IF NOT EXISTS idx_rule_releases_created_at ON rule_releases(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_rule_releases_status ON rule_releases(status);
CREATE TABLE IF NOT EXISTS rule_release_items (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL, rule_id TEXT, operation TEXT, before_hash TEXT, after_hash TEXT, file_path TEXT, metadata_json TEXT, FOREIGN KEY(version) REFERENCES rule_releases(version) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_rule_release_items_version ON rule_release_items(version);
CREATE INDEX IF NOT EXISTS idx_rule_release_items_rule_id ON rule_release_items(rule_id);
CREATE TABLE IF NOT EXISTS rule_validation_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, actor TEXT, target_state TEXT, target_version TEXT, status TEXT, conflicts_json TEXT, simulation_json TEXT, metadata_json TEXT);
CREATE INDEX IF NOT EXISTS idx_rule_validation_runs_created_at ON rule_validation_runs(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_rule_validation_runs_target ON rule_validation_runs(target_state, target_version);
`}, {ID: "003_phase14_ai_review_logs", SQL: `
CREATE TABLE IF NOT EXISTS ai_audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, created_at TEXT NOT NULL, provider TEXT, model TEXT, status TEXT, action TEXT, confidence REAL, risk_level TEXT, category TEXT, latency_ms INTEGER, prompt_tokens INTEGER, completion_tokens INTEGER, total_tokens INTEGER, estimated_cost REAL, cache_hit INTEGER, error_class TEXT, metadata_json TEXT);
CREATE INDEX IF NOT EXISTS idx_ai_audit_logs_created_at ON ai_audit_logs(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_logs_request_id ON ai_audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_ai_audit_logs_provider ON ai_audit_logs(provider);
CREATE INDEX IF NOT EXISTS idx_ai_audit_logs_status ON ai_audit_logs(status);
`}}
