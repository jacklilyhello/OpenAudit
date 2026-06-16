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
	flag.StringVar(&o.Category, "category", "general", "category")
	flag.StringVar(&o.Risk, "risk", "medium", "risk level")
	flag.StringVar(&o.Action, "action", "review", "action")
	flag.StringVar(&o.Source, "source", "sensitive-lexicon", "source")
	flag.Parse()
	if o.Input == "" {
		log.Fatal("--input is required")
	}
	res, err := importer.ImportSensitiveLexicon(o)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("imported %d keywords into %d files\n", res.Keywords, len(res.Files))
}
