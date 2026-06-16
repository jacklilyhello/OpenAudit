package model

type AuditOptions struct {
	Normalize bool `json:"normalize"`
	Pinyin    bool `json:"pinyin"`
	Homophone bool `json:"homophone"`
	AI        bool `json:"ai"`
}
type AuditTextRequest struct {
	Text    string       `json:"text"`
	Options AuditOptions `json:"options"`
}
type AuditBatchRequest struct {
	Items   []string     `json:"items"`
	Options AuditOptions `json:"options"`
}
type AuditBatchResponse struct {
	Results any `json:"results"`
}
