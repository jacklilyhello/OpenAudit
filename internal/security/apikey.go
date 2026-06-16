package security

import "net/http"

type Checker struct {
	Enabled bool
	Keys    map[string]bool
}

func New(enabled bool, keys []string) Checker {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return Checker{enabled, m}
}
func (c Checker) Valid(r *http.Request) bool {
	if !c.Enabled {
		return true
	}
	key := r.Header.Get("X-API-Key")
	if key == "" {
		const p = "Bearer "
		a := r.Header.Get("Authorization")
		if len(a) > len(p) && a[:len(p)] == p {
			key = a[len(p):]
		}
	}
	return c.Keys[key]
}
