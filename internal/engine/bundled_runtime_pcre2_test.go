//go:build pcre2

package engine

import (
	"path/filepath"
	"testing"

	"github.com/openaudit/openaudit/internal/bundled"
)

func TestBundledPCRE2ModeActivatesCompatibleRules(t *testing.T) {
	local := t.TempDir()
	write(t, filepath.Join(local, "k.yml"), "id: k\ntype: keyword\ncategory: c\nkeywords: [local]\n")
	dir := t.TempDir()
	makePack(t, dir, "g79", `{"regex":{"shield":{"1":"okhit","2":"a(?=b)","3":"(?<=a)b","4":"(a)\\1"}},"settings":{}}`)
	cfg := bundledCfg(dir)
	cfg.NetEase.Mode = "pcre2"
	cfg.NetEase.RegexEngine = "pcre2"

	e, err := NewWithOptions(local, Options{BundledRules: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"okhit", "ab", "aa"} {
		if !e.Audit(s, true).Matched {
			t.Fatalf("expected PCRE2 bundled rule to match %q", s)
		}
	}
	bst, ok := e.Stats().BundledRules.(bundled.RuntimeStats)
	if !ok {
		t.Fatalf("unexpected bundled stats type: %T", e.Stats().BundledRules)
	}
	st := bst.Providers["netease"]
	if st.RegexEngine != "pcre2" || st.ActivatedRules != 4 || st.PCRE2CompatibleRules != 4 || st.BackendUnavailableSkippedRules != 0 {
		t.Fatalf("bad PCRE2 bundled stats: %#v", st)
	}
}
