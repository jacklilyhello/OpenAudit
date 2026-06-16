package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/logstore"
	"strconv"
	"strings"
)

func RegisterLogs(r gin.IRouter, s *logstore.Store) {
	r.GET("/logs/recent", func(c *gin.Context) {
		q := c.Request.URL.Query()
		lim := atoi(q.Get("limit"), 50)
		items := []logstore.Entry{}
		for _, e := range s.Recent() {
			if q.Get("action") != "" && e.Action != q.Get("action") {
				continue
			}
			if q.Get("matched") != "" && strconv.FormatBool(e.Matched) != q.Get("matched") {
				continue
			}
			if cat := q.Get("category"); cat != "" && !entryHasCat(e, cat) {
				continue
			}
			if text := strings.ToLower(q.Get("q")); text != "" && !strings.Contains(strings.ToLower(e.Text+" "+e.TextSHA256), text) {
				continue
			}
			items = append(items, e)
			if len(items) >= lim {
				break
			}
		}
		c.JSON(200, gin.H{"items": items, "count": len(items)})
	})
	r.GET("/logs/stats", func(c *gin.Context) { c.JSON(200, logstore.ComputeStats(s.Recent())) })
}
func entryHasCat(e logstore.Entry, cat string) bool {
	for _, h := range e.Hits {
		if h.Category == cat {
			return true
		}
	}
	return false
}
