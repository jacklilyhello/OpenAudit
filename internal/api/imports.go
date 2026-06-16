package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/importer"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"path/filepath"
)

type importRequest struct {
	InputPath          string `json:"input_path"`
	OutputPath         string `json:"output_path"`
	Source             string `json:"source"`
	Type               string `json:"type"`
	Category           string `json:"category"`
	RiskLevel          string `json:"risk_level"`
	Action             string `json:"action"`
	Strict             bool   `json:"strict"`
	MaxKeywordsPerFile int    `json:"max_keywords_per_file"`
	ReloadAfterImport  bool   `json:"reload_after_import"`
	RecordHistory      bool   `json:"record_history"`
}

func RegisterImports(r gin.IRouter, cfg config.Config, batches *rulehistory.BatchStore) {
	toOpt := func(req importRequest, dry bool) importer.Options {
		in := req.InputPath
		if in == "" {
			in = cfg.Importer.DefaultInputDir
		}
		out := req.OutputPath
		if out == "" {
			out = cfg.Importer.DefaultOutputDir
		}
		src := req.Source
		if src == "" {
			src = cfg.Importer.DefaultSource
		}
		max := req.MaxKeywordsPerFile
		if max <= 0 {
			max = cfg.Importer.MaxKeywordsPerFile
		}
		return importer.Options{Input: in, Output: out, Source: src, Type: req.Type, Category: req.Category, Risk: req.RiskLevel, Action: req.Action, Strict: req.Strict, MaxKeywordsPerFile: max, DryRun: dry, ReloadAfterImport: req.ReloadAfterImport}
	}
	r.POST("/imports/preview", func(c *gin.Context) {
		var req importRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error()})
			return
		}
		o := toOpt(req, true)
		rep, err := importer.Run(o)
		if err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error(), "preview": rep})
			return
		}
		c.JSON(200, gin.H{"ok": true, "preview": rep})
	})
	r.POST("/imports/run", func(c *gin.Context) {
		var req importRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error()})
			return
		}
		o := toOpt(req, false)
		rep, err := importer.Run(o)
		if rep != nil {
			_ = importer.WriteReport(rep, filepath.Join(cfg.Importer.ReportDir, "import_"+rep.BatchID+".json"), "json")
		}
		if req.RecordHistory && batches != nil && rep != nil {
			_ = batches.AppendBatch(rulehistory.ImportBatch{BatchID: rep.BatchID, Timestamp: rep.Timestamp, Source: o.Source, InputPath: o.Input, OutputPath: o.Output, Category: o.Category, RiskLevel: o.Risk, Action: o.Action, FilesScanned: rep.FilesScanned, KeywordsRead: rep.KeywordsRead + rep.DomainsRead + rep.RegexRead, KeywordsDeduplicated: rep.DuplicatesRemoved, RulesWritten: len(rep.OutputFiles), DryRun: false, ReloadAfterImport: o.ReloadAfterImport, Status: rep.Status, GeneratedFiles: rep.OutputFiles})
		}
		if err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error(), "report": rep})
			return
		}
		c.JSON(200, gin.H{"ok": true, "batch_id": rep.BatchID, "report": rep, "reload": rep.Reload})
	})
}
