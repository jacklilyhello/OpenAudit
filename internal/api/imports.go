package api

import (
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openaudit/openaudit/internal/config"
	"github.com/openaudit/openaudit/internal/importer"
	"github.com/openaudit/openaudit/internal/rulehistory"
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
	toOpt := func(req importRequest, dry bool) (importer.ValidatedOptions, error) {
		rawInputPath := strings.TrimSpace(req.InputPath)
		rawOutputPath := strings.TrimSpace(req.OutputPath)
		src := req.Source
		if src == "" {
			src = cfg.Importer.DefaultSource
		}
		max := req.MaxKeywordsPerFile
		if max <= 0 {
			max = cfg.Importer.MaxKeywordsPerFile
		}
		opts := importer.Options{Source: src, Type: req.Type, Category: req.Category, Risk: req.RiskLevel, Action: req.Action, Strict: req.Strict, MaxKeywordsPerFile: max, DryRun: dry, ReloadAfterImport: req.ReloadAfterImport}
		return importer.NewValidatedOptionsWithDefaults(rawInputPath, rawOutputPath, cfg.Importer.DefaultInputDir, cfg.Importer.DefaultOutputDir, opts)
	}
	r.POST("/imports/preview", func(c *gin.Context) {
		var req importRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error()})
			return
		}
		o, err := toOpt(req, true)
		if err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error()})
			return
		}
		rep, err := importer.RunValidated(o)
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
		o, err := toOpt(req, false)
		if err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error()})
			return
		}
		rep, err := importer.RunValidated(o)
		if rep != nil {
			reportPath := filepath.Join(cfg.Importer.ReportDir, importer.ReportFileName(rep.BatchID))
			if reportErr := importer.WriteReportUnder(rep, cfg.Importer.ReportDir, reportPath, "json"); reportErr != nil && err == nil {
				err = reportErr
			}
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
