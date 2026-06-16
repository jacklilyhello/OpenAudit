package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/openaudit/openaudit/internal/importer"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"log"
	"net/http"
)

func main() {
	var o importer.Options
	flag.StringVar(&o.Input, "input", "", "input directory")
	flag.StringVar(&o.Output, "output", "./data/imported", "output directory")
	flag.StringVar(&o.Category, "category", "", "category override")
	flag.StringVar(&o.Risk, "risk", "medium", "risk level")
	flag.StringVar(&o.Action, "action", "review", "action")
	flag.StringVar(&o.Source, "source", "sensitive-lexicon", "source")
	flag.IntVar(&o.MaxKeywordsPerFile, "max-keywords-per-file", 10000, "max keywords per output file")
	flag.BoolVar(&o.DryRun, "dry-run", false, "scan without writing files")
	recordHistory := flag.Bool("record-history", false, "record import batch history")
	historyPath := flag.String("history-path", "./storage/rule-history/import-batches.jsonl", "import batch history JSONL path")
	reloadURL := flag.String("reload-url", "", "optional /rules/reload URL to call after import")
	apiKey := flag.String("api-key", "", "API key for optional reload request")
	flag.Parse()
	if o.Input == "" {
		log.Fatal("--input is required")
	}
	res, err := importer.ImportSensitiveLexicon(o)
	if err != nil {
		log.Fatal(err)
	}
	reloadOK := false
	if *reloadURL != "" && !o.DryRun {
		req, _ := http.NewRequest(http.MethodPost, *reloadURL, bytes.NewReader(nil))
		if *apiKey != "" {
			req.Header.Set("X-API-Key", *apiKey)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			reloadOK = resp.StatusCode >= 200 && resp.StatusCode < 300
			resp.Body.Close()
		}
	}
	if *recordHistory {
		status := "success"
		if o.DryRun {
			status = "dry_run"
		}
		_ = rulehistory.NewBatchStore(*historyPath).AppendBatch(rulehistory.ImportBatch{Source: o.Source, InputPath: o.Input, OutputPath: o.Output, Category: o.Category, RiskLevel: o.Risk, Action: o.Action, FilesScanned: res.FilesScanned, KeywordsRead: res.KeywordsRead, KeywordsDeduplicated: res.KeywordsDeduplicated, RulesWritten: res.FilesWritten, DryRun: o.DryRun, ReloadAfterImport: reloadOK, Status: status, GeneratedFiles: res.Files})
	}
	fmt.Printf("files scanned: %d\nkeywords read: %d\nkeywords deduplicated: %d\nfiles written: %d\n", res.FilesScanned, res.KeywordsRead, res.KeywordsDeduplicated, res.FilesWritten)
}
