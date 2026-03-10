package analyzer

import (
	"flag"
	"fmt"
	"os"

	"github.com/wanaware/GCP-Sec/internal/utils"
	"github.com/wanaware/GCP-Sec/pkg/compliance"
	"github.com/wanaware/GCP-Sec/pkg/parser"
	"github.com/wanaware/GCP-Sec/pkg/report"
	"github.com/wanaware/GCP-Sec/pkg/scoring"
)

var filterValueFlags = map[string]bool{
	"-p": true, "--priority": true,
	"-c": true, "--category": true,
	"--project":        true,
	"--min-risk-score": true,
	"--max-risk-score": true,
	"-o": true, "--output": true,
}

func runFilter(args []string) int {
	inputFile, flagArgs := utils.ExtractPositional(args, filterValueFlags)

	fs := flag.NewFlagSet("filter", flag.ContinueOnError)

	priorities := fs.String("priority", "", "Filter by priority (comma-separated)")
	fs.String("p", "", "Filter by priority (shorthand)")
	categories := fs.String("category", "", "Filter by category (comma-separated)")
	fs.String("c", "", "Filter by category (shorthand)")
	projects := fs.String("project", "", "Filter by project (comma-separated)")
	output := fs.String("output", "", "Output CSV file path (default: stdout)")
	fs.String("o", "", "Output file path (shorthand)")
	minScore := fs.Float64("min-risk-score", 0, "Minimum risk score")
	maxScore := fs.Float64("max-risk-score", 100, "Maximum risk score")

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if inputFile == "" {
		fmt.Fprintf(os.Stderr, "Error: input CSV file is required\n\nUsage: GCP-Sec filter <input.csv> [options]\n")
		return 1
	}

	logger := GlobalConfig.Logger

	// Parse
	p := parser.NewParser(logger)
	findings, parseErrors, err := p.ParseFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	logger.Info("Parsed %d findings (%d errors)", len(findings), parseErrors)

	// Score
	engine := scoring.NewEngine(scoring.DefaultConfig(), logger)
	engine.ScoreAll(findings)

	// Compliance
	detector := compliance.NewDetector()
	for _, f := range findings {
		detector.DetectViolations(f)
	}

	// Resolve shorthand flags
	pri := *priorities
	if pri == "" {
		pri = fs.Lookup("p").Value.String()
	}
	cat := *categories
	if cat == "" {
		cat = fs.Lookup("c").Value.String()
	}
	outPath := *output
	if outPath == "" {
		outPath = fs.Lookup("o").Value.String()
	}

	// Apply filters
	af := &AnalyzeFlags{
		Priorities:   pri,
		Categories:   cat,
		Projects:     *projects,
		MinRiskScore: *minScore,
		MaxRiskScore: *maxScore,
	}
	filtered := applyFilters(findings, af)
	logger.Info("Filtered to %d findings", len(filtered))

	// Build minimal report
	builder := report.NewBuilder()
	r := builder.Build(filtered, inputFile, 0)

	// Write CSV
	gen := report.NewCSVGenerator()
	var outFile *os.File

	if outPath == "" {
		outFile = os.Stdout
	} else {
		outFile, err = os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			return 1
		}
		defer outFile.Close()
	}

	if err := gen.Generate(r, outFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
		return 1
	}

	if outPath != "" {
		fmt.Fprintf(os.Stderr, "Wrote %d findings to %s\n", len(filtered), outPath)
	}
	return 0
}

// Ensure utils is used (for the import to be valid when ExtractPositional is the only use).
var _ = utils.ParseBool
