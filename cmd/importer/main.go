package main

import (
	"flag"
	"fmt"
	"github.com/openaudit/openaudit/internal/importer"
	"log"
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
	flag.Parse()
	if o.Input == "" {
		log.Fatal("--input is required")
	}
	res, err := importer.ImportSensitiveLexicon(o)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("files scanned: %d\nkeywords read: %d\nkeywords deduplicated: %d\nfiles written: %d\n", res.FilesScanned, res.KeywordsRead, res.KeywordsDeduplicated, res.FilesWritten)
}
