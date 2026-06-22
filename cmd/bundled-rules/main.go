package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/openaudit/openaudit/internal/bundled"
)

func main() {
	log.SetFlags(0)
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
	var input, output, reportPath, dataset, repo, commit, src, tstamp, license string
	dry := fs.Bool("dry-run", false, "do not write output")
	jsonOut := fs.Bool("json", false, "print machine-readable report JSON to stdout in dry-run mode")
	fs.StringVar(&input, "input", "", "input JSON path")
	fs.StringVar(&output, "output", "", "output .json.gz path")
	fs.StringVar(&reportPath, "report", "", "report JSON path")
	fs.StringVar(&dataset, "dataset", "", "g79 or x19")
	fs.StringVar(&repo, "source-repository", "", "upstream repository")
	fs.StringVar(&commit, "source-commit", "", "full source commit SHA")
	fs.StringVar(&src, "source-file-path", "", "upstream source file path")
	fs.StringVar(&tstamp, "timestamp", "", "RFC3339 reproducible timestamp")
	fs.StringVar(&license, "license", "NOASSERTION", "license identifier")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
	if input == "" || dataset == "" || repo == "" || commit == "" || src == "" {
		log.Fatal("--input, --dataset, --source-repository, --source-commit, and --source-file-path are required")
	}
	if !*dry && (output == "" || reportPath == "") {
		log.Fatal("--output and --report are required unless --dry-run is set")
	}
	ts := time.Time{}
	if tstamp != "" {
		var err error
		ts, err = time.Parse(time.RFC3339, tstamp)
		if err != nil {
			log.Fatal(err)
		}
	}
	rep, err := bundled.ConvertFile(input, bundled.Options{Dataset: dataset, SourceRepository: repo, SourceCommit: commit, SourceFilePath: src, OutputPath: output, ReportPath: reportPath, Timestamp: ts, LicenseIdentifier: license}, *dry)
	if err != nil {
		log.Fatal(err)
	}
	printSummary(rep)
	if *dry && *jsonOut {
		b, err := bundled.MarshalReport(rep)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(string(b))
	}
}
func validate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	var input, reportPath string
	fs.StringVar(&input, "input", "", "pack .json.gz path")
	fs.StringVar(&reportPath, "report", "", "optional report JSON path")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
	if input == "" {
		log.Fatal("--input is required")
	}
	b, err := bundled.ReadLimitedLocalFile(input, bundled.DefaultLimits().CompressedPackBytes)
	if err != nil {
		log.Fatal(err)
	}
	p, err := bundled.ReadPackGzip(b, bundled.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}
	if err := bundled.ValidatePack(p, bundled.DefaultLimits()); err != nil {
		log.Fatal(err)
	}
	if reportPath != "" {
		rb, err := bundled.ReadLimitedLocalFile(reportPath, bundled.DefaultLimits().ReportBytes)
		if err != nil {
			log.Fatal(err)
		}
		r, err := bundled.DecodeReportJSON(rb, bundled.DefaultLimits())
		if err != nil {
			log.Fatal(err)
		}
		if err := bundled.ValidateReportForPack(r, p, b); err != nil {
			log.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if r.GeneratedPackSHA256 != hex.EncodeToString(sum[:]) {
			log.Fatal("report sha mismatch")
		}
	}
	fmt.Printf("valid pack: provider=%s dataset=%s rules=%d\n", p.Provider, p.Dataset, len(p.Rules))
}
func printSummary(r bundled.Report) {
	fmt.Printf("summary: dataset=%s imported=%d empty=%d malformed=%d re2_ok=%d re2_bad=%d pack_sha256=%s\n", r.Dataset, r.ImportedRecords, r.EmptyRecords, r.MalformedRecords, r.RE2CompatibleRules, r.RE2IncompatibleRules, r.GeneratedPackSHA256)
}
