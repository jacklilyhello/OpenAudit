package model

type AuditOptions struct {
	Normalize             *bool `json:"normalize,omitempty"`
	Pinyin                *bool `json:"pinyin,omitempty"`
	Homophone             *bool `json:"homophone,omitempty"`
	AI                    *bool `json:"ai,omitempty"`
	IncludeExplanations   *bool `json:"include_explanations,omitempty"`
	IncludeNormalizedText *bool `json:"include_normalized_text,omitempty"`
	IncludePositions      *bool `json:"include_positions,omitempty"`
	MaxHits               int   `json:"max_hits,omitempty"`
}

func BoolDefault(p *bool, d bool) bool {
	if p == nil {
		return d
	}
	return *p
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
