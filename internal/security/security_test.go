package security

import (
	"net/http/httptest"
	"testing"
)

func TestChecker(t *testing.T) {
	r := httptest.NewRequest("GET", "/x", nil)
	if !New(false, nil).Valid(r) {
		t.Fatal("disabled should pass")
	}
	c := New(true, []string{"k"})
	if c.Valid(r) {
		t.Fatal("missing should fail")
	}
	r.Header.Set("X-API-Key", "k")
	if !c.Valid(r) {
		t.Fatal("valid x api key")
	}
	r.Header.Del("X-API-Key")
	r.Header.Set("Authorization", "Bearer k")
	if !c.Valid(r) {
		t.Fatal("valid bearer")
	}
}
