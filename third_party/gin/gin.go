package gin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
)

type H map[string]any
type HandlerFunc func(*Context)
type IRouter interface{ GET(string, HandlerFunc); POST(string, HandlerFunc) }
type Context struct{ ResponseWriter http.ResponseWriter; Request *http.Request }
func (c *Context) JSON(code int, obj any){ c.ResponseWriter.Header().Set("Content-Type","application/json"); c.ResponseWriter.WriteHeader(code); _=json.NewEncoder(c.ResponseWriter).Encode(obj) }
func (c *Context) ShouldBindJSON(obj any) error{ return json.NewDecoder(c.Request.Body).Decode(obj) }
type Engine struct{ mux *http.ServeMux }
func Default()*Engine{ return &Engine{mux:http.NewServeMux()} }
func (e *Engine) GET(path string,h HandlerFunc){ e.handle("GET",path,h) }
func (e *Engine) POST(path string,h HandlerFunc){ e.handle("POST",path,h) }
func (e *Engine) handle(method,path string,h HandlerFunc){ e.mux.HandleFunc(path,func(w http.ResponseWriter,r *http.Request){ if r.Method!=method{ http.Error(w,http.StatusText(http.StatusMethodNotAllowed),http.StatusMethodNotAllowed); return }; h(&Context{ResponseWriter:w,Request:r}) }) }
func (e *Engine) StaticFile(path,file string){ e.GET(path,func(c *Context){ http.ServeFile(c.ResponseWriter,c.Request,file) }) }
func (e *Engine) Static(prefix,root string){ e.mux.Handle(prefix+"/", http.StripPrefix(prefix,http.FileServer(http.Dir(filepath.Clean(root))))) }
func (e *Engine) Run(addr string) error{ return http.ListenAndServe(addr,e.mux) }
