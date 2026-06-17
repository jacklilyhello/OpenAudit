package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestAuditAndMapping(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "k.yml"), "id: k\ntype: keyword\ncategory: c\nrisk_level: high\naction: block\nkeywords: [bad]\n")
	write(t, filepath.Join(dir, "p.yml"), "id: p\ntype: pinyin\ncategory: c\naction: review\nmapping:\n  法轮功: [flg]\n")
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := e.Audit("bad flg", true)
	if !res.Matched || len(res.Hits) != 2 {
		t.Fatalf("bad audit %#v", res)
	}
}
func TestReloadFailureKeepsOldRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.yml")
	write(t, path, "id: k\ntype: keyword\ncategory: c\nkeywords: [good]\n")
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, "id: r\ntype: regex\ncategory: c\npatterns: ['[']\n")
	if err := e.Reload(); err == nil {
		t.Fatal("expected reload failure")
	}
	if !e.Audit("good", true).Matched {
		t.Fatal("old rules were not kept")
	}
}

func TestPhase13VariantGeneratedPinyinReviewFirst(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "k.yml"), `id: v
type: keyword
category: c
risk_level: high
action: block
score: 90
description: Variant rule
keywords: [法轮功]
variant:
  enabled: true
  pinyin: true
  pinyin_initials: true
  min_score: 0.70
  action: review
  risk_level: medium
  initial_min_length: 3
  max_pinyin_variants: 4
`)
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := e.Audit("fǎ-lún-gōng", true)
	if !res.Matched || res.Action != "review" || len(res.Hits) != 1 {
		t.Fatalf("bad pinyin result %#v", res)
	}
	h := res.Hits[0]
	if h.Type != "pinyin" || h.VariantType != "pinyin" || h.Score != 70 || h.Explanation == "" {
		t.Fatalf("missing pinyin metadata %#v", h)
	}
	initials := e.Audit("f.l.g", true)
	if !initials.Matched || initials.Action != "review" {
		t.Fatalf("expected initials review match %#v", initials)
	}
}

func TestPhase13GeneratedHomophoneReviewFirst(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "k.yml"), `id: h
type: keyword
category: c
risk_level: high
action: block
keywords: [法轮功]
variant:
  enabled: true
  homophone: true
  min_score: 0.75
  action: review
  risk_level: medium
`)
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := e.Audit("发-轮-功", true)
	if !res.Matched || res.Action != "review" {
		t.Fatalf("bad homophone result %#v", res)
	}
	h := res.Hits[0]
	if h.Type != "homophone" || h.Score != 75 || h.Explanation == "" {
		t.Fatalf("missing homophone metadata %#v", h)
	}
}

func TestPhase13TraditionalRuleMatchesSimplifiedInput(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "k.yml"), "id: trad\ntype: keyword\ncategory: c\nrisk_level: high\naction: block\nkeywords: [法輪功]\n")
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Audit("法轮功", true).Matched {
		t.Fatal("traditional keyword should match simplified input after normalization")
	}
}
