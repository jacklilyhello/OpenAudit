package logstore

import (
	"github.com/openaudit/openaudit/internal/engine"
	"github.com/openaudit/openaudit/internal/safepath"
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryLimitRedactionStatsJSONL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs", "audit.log")
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
	fileInfo, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != safepath.RuntimeFilePerm {
		t.Fatalf("log mode = %o want %o", got, safepath.RuntimeFilePerm)
	}
	dirInfo, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != safepath.RuntimeDirPerm {
		t.Fatalf("log dir mode = %o want %o", got, safepath.RuntimeDirPerm)
	}
	st := ComputeStats(es)
	if st.Total != 2 || st.Matched != 2 {
		t.Fatalf("stats %#v", st)
	}
}
