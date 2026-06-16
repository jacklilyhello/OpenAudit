package main

import (
	"flag"
	"fmt"
	"github.com/openaudit/openaudit/internal/importer"
	"github.com/openaudit/openaudit/internal/rulehistory"
	"log"
	"path/filepath"
)

func main() {
	var o importer.Options
	flag.StringVar(&o.Input, "input", "", "input directory")
	flag.StringVar(&o.Output, "output", "./data/imported", "output directory")
	flag.StringVar(&o.Category, "category", "", "category override")
	flag.StringVar(&o.Risk, "risk", "medium", "risk level")
	flag.StringVar(&o.Action, "action", "review", "action")
	flag.StringVar(&o.Source, "source", "sensitive-lexicon", "source")
	flag.StringVar(&o.Type, "type", "auto", "rule type: auto|keyword|domain|regex")
	flag.StringVar(&o.DedupeScope, "dedupe-scope", "batch", "dedupe scope: batch|file")
	flag.IntVar(&o.MaxKeywordsPerFile, "max-keywords-per-file", 10000, "max entries per output file")
	flag.IntVar(&o.MaxLineRunes, "max-line-runes", 4096, "max line length in runes")
	flag.BoolVar(&o.Strict, "strict", false, "fail on invalid lines")
	flag.BoolVar(&o.DryRun, "dry-run", false, "scan without writing files")
	flag.BoolVar(&o.ReloadAfterImport, "reload-after-import", false, "call reload after successful import")
	flag.StringVar(&o.ReloadURL, "reload-url", "", "optional /rules/reload URL")
	flag.StringVar(&o.APIKey, "api-key", "", "API key for optional reload request")
	flag.StringVar(&o.ReportPath, "report", "", "report output path")
	flag.StringVar(&o.ReportFormat, "report-format", "json", "json|markdown")
	recordHistory := flag.Bool("record-history", false, "record import batch history")
	historyPath := flag.String("history-path", "./storage/rule-history/import-batches.jsonl", "import batch history JSONL path")
	reportDir := flag.String("report-dir", "./storage/imports/reports", "default report directory")
	flag.Parse()
	if o.Input == "" {
		log.Fatal("--input is required")
	}
	rep, err := importer.Run(o)
	if rep == nil {
		log.Fatal(err)
	}
	if o.ReportPath == "" && !o.DryRun {
		o.ReportPath = filepath.Join(*reportDir, importer.ReportFileName(rep.BatchID))
	}
	if o.ReportPath != "" {
		if e := importer.WriteReportUnder(rep, *reportDir, o.ReportPath, o.ReportFormat); e != nil {
			log.Printf("write report failed: %v", e)
		}
	}
	if *recordHistory {
		if e := rulehistory.NewBatchStore(*historyPath).AppendBatch(rulehistory.ImportBatch{BatchID: rep.BatchID, Timestamp: rep.Timestamp, Source: o.Source, InputPath: o.Input, OutputPath: o.Output, Category: o.Category, RiskLevel: o.Risk, Action: o.Action, FilesScanned: rep.FilesScanned, KeywordsRead: rep.KeywordsRead + rep.DomainsRead + rep.RegexRead, KeywordsDeduplicated: rep.DuplicatesRemoved, RulesWritten: len(rep.OutputFiles), DryRun: o.DryRun, ReloadAfterImport: o.ReloadAfterImport, Status: rep.Status, GeneratedFiles: rep.OutputFiles}); e != nil {
			log.Printf("record import batch history failed: %v", e)
		}
	}
	fmt.Printf("status: %s\nfiles scanned: %d\nlines read: %d\nduplicates removed: %d\noutput files: %d\n", rep.Status, rep.FilesScanned, rep.LinesRead, rep.DuplicatesRemoved, len(rep.OutputFiles))
	if err != nil {
		log.Fatal(err)
	}
}
