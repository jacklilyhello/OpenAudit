package logstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/storage"
	"time"
)

type Entry struct {
	ID          string       `json:"id"`
	Timestamp   time.Time    `json:"timestamp"`
	RequestType string       `json:"request_type"`
	Text        string       `json:"text,omitempty"`
	TextSHA256  string       `json:"text_sha256"`
	TextLength  int          `json:"text_length,omitempty"`
	Matched     bool         `json:"matched"`
	Action      string       `json:"action"`
	RiskScore   int          `json:"risk_score"`
	RiskDetail  any          `json:"risk_detail"`
	HitCount    int          `json:"hit_count"`
	Hits        []engine.Hit `json:"hits,omitempty"`
	DurationMS  int64        `json:"duration_ms"`
	RemoteAddr  string       `json:"remote_addr"`
	UserAgent   string       `json:"user_agent"`
}
type Options struct {
	LogRequestText bool
	LogHits        bool
}
type Store struct {
	mem     *Memory
	jsonl   *JSONL
	backend storage.Store
	opts    Options
}

func New(path string, max int, enabled bool, opts Options) (*Store, error) {
	s := &Store{mem: NewMemory(max), opts: opts}
	if enabled {
		j, err := NewJSONL(path)
		if err != nil {
			return s, err
		}
		s.jsonl = j
	}
	return s, nil
}
func (s *Store) SetBackend(b storage.Store) {
	if s != nil {
		s.backend = b
	}
}
func NewEntry(t, text string, res engine.Result, dur int64, remote, ua string, opts Options) Entry {
	sum := sha256.Sum256([]byte(text))
	e := Entry{ID: fmt.Sprintf("audit_%d", time.Now().UnixNano()), Timestamp: time.Now().UTC(), RequestType: t, TextSHA256: hex.EncodeToString(sum[:]), TextLength: len([]rune(text)), Matched: res.Matched, Action: res.Action, RiskScore: res.RiskScore, RiskDetail: res.RiskDetail, HitCount: len(res.Hits), DurationMS: dur, RemoteAddr: remote, UserAgent: ua}
	if opts.LogRequestText {
		e.Text = text
	}
	if opts.LogHits {
		e.Hits = res.Hits
	}
	return e
}
func (s *Store) Append(e Entry) {
	if s == nil {
		return
	}
	s.mem.Add(e)
	if s.backend != nil {
		raw, _ := json.Marshal(e)
		_, _ = s.backend.InsertAuditLog(context.Background(), storage.AuditLog{RequestID: e.ID, CreatedAt: e.Timestamp, Method: e.RequestType, Path: "/audit/" + e.RequestType, ClientIP: e.RemoteAddr, Decision: e.Action, StatusCode: 200, DurationMS: e.DurationMS, RequestBytes: e.TextLength, NormalizedBytes: e.TextLength, MatchCount: e.HitCount, RuleHitCount: e.HitCount, RawJSON: string(raw)}, e.Hits)
	}
	if s.jsonl != nil {
		_ = s.jsonl.Append(e)
	}
}
func (s *Store) Backend() storage.Store {
	if s == nil {
		return nil
	}
	return s.backend
}
func (s *Store) Recent() []Entry {
	if s == nil {
		return nil
	}
	return s.mem.Recent()
}
func (s *Store) Options() Options {
	if s == nil {
		return Options{LogRequestText: true, LogHits: true}
	}
	return s.opts
}

type Stats struct {
	Total         int            `json:"total"`
	Matched       int            `json:"matched"`
	Passed        int            `json:"passed"`
	Actions       map[string]int `json:"actions"`
	TopCategories []KV           `json:"top_categories"`
	TopRules      []KV           `json:"top_rules"`
}
type KV struct {
	Category string `json:"category,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	Count    int    `json:"count"`
}

func ComputeStats(es []Entry) Stats {
	st := Stats{Actions: map[string]int{}}
	cats := map[string]int{}
	rules := map[string]int{}
	for _, e := range es {
		st.Total++
		if e.Matched {
			st.Matched++
		} else {
			st.Passed++
		}
		st.Actions[e.Action]++
		for _, h := range e.Hits {
			cats[h.Category]++
			rules[h.RuleID]++
		}
	}
	for k, v := range cats {
		st.TopCategories = append(st.TopCategories, KV{Category: k, Count: v})
	}
	for k, v := range rules {
		st.TopRules = append(st.TopRules, KV{RuleID: k, Count: v})
	}
	return st
}
