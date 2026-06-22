package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/openaudit/openaudit/internal/bundled"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: bundled-rules convert|validate")
	}
	switch os.Args[1] {
	case "convert":
		convert(os.Args[2:])
	case "validate":
		validate(os.Args[2:])
	default:
		log.Fatal("unknown command")
	}
}
func convert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	var input, output, dataset, repo, commit, src, tstamp, license string
	dry := fs.Bool("dry-run", false, "do not write output")
	fs.StringVar(&input, "input", "", "input JSON path")
	fs.StringVar(&output, "output", "", "output .json.gz path")
	fs.StringVar(&dataset, "dataset", "", "g79 or x19")
	fs.StringVar(&repo, "source-repository", "", "upstream repository")
	fs.StringVar(&commit, "source-commit", "", "full source commit SHA")
	fs.StringVar(&src, "source-file-path", "", "upstream source file path")
	fs.StringVar(&tstamp, "timestamp", "", "RFC3339 reproducible timestamp")
	fs.StringVar(&license, "license", "NOASSERTION", "license identifier")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
	if input == "" || output == "" || dataset == "" || repo == "" || commit == "" || src == "" {
		log.Fatal("--input, --output, --dataset, --source-repository, --source-commit, and --source-file-path are required")
	}
	ts := time.Time{}
	if tstamp != "" {
		var err error
		ts, err = time.Parse(time.RFC3339, tstamp)
		if err != nil {
			log.Fatal(err)
		}
	}
	rep, err := bundled.ConvertFile(input, bundled.Options{Dataset: dataset, SourceRepository: repo, SourceCommit: commit, SourceFilePath: src, OutputPath: output, Timestamp: ts, LicenseIdentifier: license}, *dry)
	printReport(rep)
	if err != nil {
		log.Fatal(err)
	}
}
func validate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	var input string
	fs.StringVar(&input, "input", "", "pack .json.gz path")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
	if input == "" {
		log.Fatal("--input is required")
	}
	// #nosec G304 -- local operator-supplied validation path for offline pack validation.
	b, err := os.ReadFile(input)
	if err != nil {
		log.Fatal(err)
	}
	p, err := bundled.ReadPackGzip(b, bundled.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("valid pack: provider=%s dataset=%s rules=%s\n", p.Provider, p.Dataset, strconv.Itoa(len(p.Rules)))
}
func printReport(r bundled.Report) {
	b, _ := json.Marshal(r)
	fmt.Printf("summary: dataset=%s imported=%d re2_ok=%d re2_bad=%d pack_sha256=%s\n", r.Dataset, r.ImportedRecords, r.RE2CompatibleRules, r.RE2IncompatibleRules, r.GeneratedPackSHA256)
	_ = b
}
