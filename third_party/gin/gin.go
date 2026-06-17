package gin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
)

type H map[string]any
type HandlerFunc func(*Context)
type MiddlewareFunc func(*Context) bool
type IRouter interface {
	GET(string, HandlerFunc)
	POST(string, HandlerFunc)
	PATCH(string, HandlerFunc)
	DELETE(string, HandlerFunc)
}
type Context struct {
	ResponseWriter http.ResponseWriter
	Request        *http.Request
	params         map[string]string
}

func (c *Context) JSON(code int, obj any) {
	c.ResponseWriter.Header().Set("Content-Type", "application/json")
	c.ResponseWriter.WriteHeader(code)
	_ = json.NewEncoder(c.ResponseWriter).Encode(obj)
}
func (c *Context) ShouldBindJSON(obj any) error { return json.NewDecoder(c.Request.Body).Decode(obj) }
func (c *Context) Param(name string) string {
	if c.params == nil {
		return ""
	}
	return c.params[name]
}

type route struct {
	method, path string
	h            HandlerFunc
}
type Engine struct {
	routes      []route
	mux         *http.ServeMux
	middlewares []MiddlewareFunc
}

func Default() *Engine                              { return &Engine{mux: http.NewServeMux()} }
func (e *Engine) GET(path string, h HandlerFunc)    { e.handle("GET", path, h) }
func (e *Engine) POST(path string, h HandlerFunc)   { e.handle("POST", path, h) }
func (e *Engine) PATCH(path string, h HandlerFunc)  { e.handle("PATCH", path, h) }
func (e *Engine) DELETE(path string, h HandlerFunc) { e.handle("DELETE", path, h) }
func (e *Engine) handle(method, path string, h HandlerFunc) {
	e.routes = append(e.routes, route{method, path, h})
}
func (e *Engine) Use(m MiddlewareFunc) { e.middlewares = append(e.middlewares, m) }
func (e *Engine) StaticFile(path, file string) {
	e.GET(path, func(c *Context) { http.ServeFile(c.ResponseWriter, c.Request, file) })
}
func (e *Engine) Static(prefix, root string) {
	e.mux.Handle(prefix+"/", http.StripPrefix(prefix, http.FileServer(http.Dir(filepath.Clean(root)))))
}
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, rt := range e.routes {
		if rt.method == r.Method {
			if p, ok := match(rt.path, r.URL.Path); ok {
				c := &Context{ResponseWriter: w, Request: r, params: p}
				for _, m := range e.middlewares {
					if !m(c) {
						return
					}
				}
				rt.h(c)
				return
			}
		}
	}
	e.mux.ServeHTTP(w, r)
}
func match(pattern, path string) (map[string]string, bool) {
	if pattern == path {
		return map[string]string{}, true
	}
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	sp := strings.Split(strings.Trim(path, "/"), "/")
	if len(pp) != len(sp) {
		return nil, false
	}
	m := map[string]string{}
	for i := range pp {
		if strings.HasPrefix(pp[i], ":") {
			m[strings.TrimPrefix(pp[i], ":")] = sp[i]
			continue
		}
		if pp[i] != sp[i] {
			return nil, false
		}
	}
	return m, true
}

// #nosec G114 -- production server startup uses cmd/server http.Server with explicit timeouts; this compatibility helper is retained for Gin API parity in tests/local callers.
func (e *Engine) Run(addr string) error { return http.ListenAndServe(addr, e) }
