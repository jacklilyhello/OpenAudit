package api

import (
	"fmt"
	"os"
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
	toOpt := func(req importRequest, dry bool) (importer.Options, error) {
		in, err := resolveImportAPIPath(req.InputPath, cfg.Importer.DefaultInputDir, "input_path")
		if err != nil {
			return importer.Options{}, err
		}
		out, err := resolveImportAPIPath(req.OutputPath, cfg.Importer.DefaultOutputDir, "output_path")
		if err != nil {
			return importer.Options{}, err
		}
		src := req.Source
		if src == "" {
			src = cfg.Importer.DefaultSource
		}
		max := req.MaxKeywordsPerFile
		if max <= 0 {
			max = cfg.Importer.MaxKeywordsPerFile
		}
		return importer.Options{Input: in, Output: out, Source: src, Type: req.Type, Category: req.Category, Risk: req.RiskLevel, Action: req.Action, Strict: req.Strict, MaxKeywordsPerFile: max, DryRun: dry, ReloadAfterImport: req.ReloadAfterImport}, nil
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
		o, err := toOpt(req, false)
		if err != nil {
			c.JSON(400, gin.H{"ok": false, "error": err.Error()})
			return
		}
		rep, err := importer.Run(o)
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

func resolveImportAPIPath(requestPath, defaultRoot, field string) (string, error) {
	rootAbs, err := safeAPIAbsPath(defaultRoot)
	if err != nil {
		return "", fmt.Errorf("%s default root: %w", field, err)
	}
	if info, err := os.Lstat(rootAbs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s default root symlink rejected", field)
	}
	provided := strings.TrimSpace(requestPath)
	if provided == "" {
		return rootAbs, nil
	}
	if strings.ContainsRune(provided, 0) {
		return "", fmt.Errorf("%s contains NUL", field)
	}
	if hasParentTraversal(provided) {
		return "", fmt.Errorf("%s contains parent traversal", field)
	}
	var candidateAbs string
	if filepath.IsAbs(provided) {
		candidateAbs, err = safeAPIAbsPath(provided)
		if err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
	} else {
		candidateAbs, err = safeAPIAbsPath(provided)
		if err == nil && ensureAPIPathUnder(rootAbs, candidateAbs) == nil {
			return candidateAbs, nil
		}
		candidateAbs, err = safeAPIAbsPath(filepath.Join(rootAbs, provided))
		if err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
	}
	if err := ensureAPIPathUnder(rootAbs, candidateAbs); err != nil {
		return "", fmt.Errorf("%s outside configured root: %w", field, err)
	}
	if info, err := os.Lstat(candidateAbs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s symlink rejected", field)
	}
	return candidateAbs, nil
}

func safeAPIAbsPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("path contains NUL")
	}
	if hasParentTraversal(p) {
		return "", fmt.Errorf("path contains parent traversal")
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func hasParentTraversal(p string) bool {
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func ensureAPIPathUnder(baseAbs, candidateAbs string) error {
	rel, err := filepath.Rel(filepath.Clean(baseAbs), filepath.Clean(candidateAbs))
	if err != nil {
		return err
	}
	if apiRelEscapesBase(rel) || filepath.IsAbs(rel) {
		return fmt.Errorf("%q escapes %q", candidateAbs, baseAbs)
	}
	return nil
}

func apiRelEscapesBase(rel string) bool {
	return rel == ".." || len(rel) > 3 && rel[:3] == ".."+string(os.PathSeparator)
}
