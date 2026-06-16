package security

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

type Checker struct {
	Enabled bool
	Keys    []string
}

func New(enabled bool, keys []string) Checker {
	out := []string{}
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return Checker{enabled, out}
}
func (c Checker) Valid(r *http.Request) bool {
	if !c.Enabled {
		return true
	}
	key := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if key == "" {
		const p = "Bearer "
		a := r.Header.Get("Authorization")
		if strings.HasPrefix(a, p) {
			key = strings.TrimSpace(strings.TrimPrefix(a, p))
		}
	}
	for _, k := range c.Keys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(k)) == 1 {
			return true
		}
	}
	return false
}
