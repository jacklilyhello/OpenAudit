package logstore

import (
	"github.com/openaudit/openaudit/internal/engine"
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryLimitRedactionStatsJSONL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	s, err := New(p, 2, true, Options{LogRequestText: false, LogHits: false})
	if err != nil {
		t.Fatal(err)
	}
	res := engine.Result{Matched: true, Action: "block", RiskScore: 90, Hits: []engine.Hit{{RuleID: "r1", Category: "c"}}}
	for i := 0; i < 3; i++ {
		s.Append(NewEntry("text", "secret", res, 1, "", "", s.Options()))
	}
	es := s.Recent()
	if len(es) != 2 {
		t.Fatal(len(es))
	}
	if es[0].Text != "" || es[0].TextSHA256 == "" || len(es[0].Hits) != 0 {
		t.Fatalf("redaction %#v", es[0])
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	st := ComputeStats(es)
	if st.Total != 2 || st.Matched != 2 {
		t.Fatalf("stats %#v", st)
	}
}
