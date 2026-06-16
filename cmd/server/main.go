package main

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/admin"
	"github.com/openaudit/openaudit/internal/api"
	"github.com/openaudit/openaudit/internal/engine"
	"log"
)

func main() {
	e, err := engine.New("data")
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}
	r := gin.Default()
	api.RegisterHealth(r)
	api.RegisterAudit(r, e)
	api.RegisterBatch(r, e)
	api.RegisterRules(r, e)
	admin.Register(r)
	log.Println("OpenAudit listening on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
