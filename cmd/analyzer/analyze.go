package analyzer

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
	"github.com/wanaware/GCP-Sec/pkg/parser"
)

// analyzeValueFlags lists flags for the analyze command that take a value argument.
// Used by ExtractPositional to correctly separate the CSV filename from flag values.
var analyzeValueFlags = map[string]bool{
	"-o": true, "--output": true,
	"-f": true, "--format": true,
	"-d": true, "--output-dir": true,
	"--formats":        true,
	"-p": true, "--priority": true,
	"-c": true, "--category": true,
	"--project":        true,
	"--scoring-config": true,
	"--min-risk-score": true,
	"--max-risk-score": true,
}

// AnalyzeFlags holds parsed CLI flags for the analyze command.
type AnalyzeFlags struct {
	Output             string
	Format             string
	OutputDir          string
	Formats            string
	Priorities         string
	Categories         string
	Projects           string
	SplitByPriority    bool
	IncludeRemediation bool
	IncludeCompliance  bool
	AIEnhance          bool
	MinRiskScore       float64
	MaxRiskScore       float64
	Verbose            bool
	Debug              bool
}

func runAnalyze(args []string) int {
	// Separate the positional CSV file argument from flag arguments so that Go's
	// standard flag package works correctly regardless of argument ordering.
	inputFile, flagArgs := utils.ExtractPositional(args, analyzeValueFlags)

	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	af := &AnalyzeFlags{}

	fs.StringVar(&af.Output, "output", "", "Output file path (e.g. report.md); stem is used for multi-format output")
	fs.StringVar(&af.Output, "o", "", "Output file path (shorthand)")
	fs.StringVar(&af.Format, "format", "", "Single output format: markdown, html, json, csv (default: generates markdown+html)")
	fs.StringVar(&af.Format, "f", "", "Output format (shorthand)")
	fs.StringVar(&af.OutputDir, "output-dir", "", "Output directory")
	fs.StringVar(&af.OutputDir, "d", "", "Output directory (shorthand)")
	fs.StringVar(&af.Formats, "formats", "", "Comma-separated output formats")
	fs.StringVar(&af.Priorities, "priority", "", "Filter by priority (comma-separated)")
	fs.StringVar(&af.Priorities, "p", "", "Filter by priority (shorthand)")
	fs.StringVar(&af.Categories, "category", "", "Filter by category (comma-separated)")
	fs.StringVar(&af.Categories, "c", "", "Filter by category (shorthand)")
	fs.StringVar(&af.Projects, "project", "", "Filter by project (comma-separated)")
	fs.BoolVar(&af.SplitByPriority, "split-by-priority", false, "Split output by priority")
	fs.BoolVar(&af.IncludeRemediation, "include-remediation", true, "Include remediation steps and scripts (default: enabled)")
	fs.BoolVar(&af.IncludeCompliance, "include-compliance", false, "Include compliance details")
	fs.BoolVar(&af.AIEnhance, "ai-enhance", false, "Enrich CRITICAL findings via Claude AI (requires ANTHROPIC_API_KEY)")
	fs.Float64Var(&af.MinRiskScore, "min-risk-score", 0, "Minimum risk score")
	fs.Float64Var(&af.MaxRiskScore, "max-risk-score", 100, "Maximum risk score")
	fs.BoolVar(&af.Verbose, "verbose", false, "Verbose logging")
	fs.BoolVar(&af.Verbose, "v", false, "Verbose logging (shorthand)")
	fs.BoolVar(&af.Debug, "debug", false, "Debug logging")

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		return 1
	}

	if inputFile == "" {
		fmt.Fprintf(os.Stderr, "Error: input CSV file is required\n\nUsage: GCP-Sec analyze <input.csv> [options]\n")
		return 1
	}

	logger := GlobalConfig.Logger

	// ── Parse CSV ──────────────────────────────────────────────────────────────
	logger.Info("Parsing CSV file: %s", inputFile)
	p := parser.NewParser(logger)
	findings, parseErrors, err := p.ParseFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	logger.Info("Parsed %d findings (%d parse errors)", len(findings), parseErrors)

	// ── Run analysis pipeline ──────────────────────────────────────────────────
	baseName := strings.TrimSuffix(filepath.Base(inputFile), filepath.Ext(inputFile)) + "-report"
	return runPipeline(PipelineInput{
		Findings:    findings,
		SourceLabel: inputFile,
		BaseName:    baseName,
		ParseErrors: parseErrors,
		Flags:       af,
		Logger:      logger,
	})
}

// applyFilters applies all active filters to the findings slice.
func applyFilters(findings []*models.Finding, af *AnalyzeFlags) []*models.Finding {
	result := findings

	if af.Priorities != "" {
		priorities := splitUpper(af.Priorities)
		set := make(map[string]bool, len(priorities))
		for _, p := range priorities {
			set[p] = true
		}
		var out []*models.Finding
		for _, f := range result {
			if set[f.Priority] {
				out = append(out, f)
			}
		}
		result = out
	}

	if af.Categories != "" {
		categories := splitUpper(af.Categories)
		set := make(map[string]bool, len(categories))
		for _, c := range categories {
			set[c] = true
		}
		var out []*models.Finding
		for _, f := range result {
			if set[f.Category] {
				out = append(out, f)
			}
		}
		result = out
	}

	if af.Projects != "" {
		projects := splitFields(af.Projects)
		set := make(map[string]bool, len(projects))
		for _, p := range projects {
			set[p] = true
		}
		var out []*models.Finding
		for _, f := range result {
			if set[f.ProjectID] || set[f.ProjectDisplayName] {
				out = append(out, f)
			}
		}
		result = out
	}

	if af.MinRiskScore > 0 || af.MaxRiskScore < 100 {
		var out []*models.Finding
		for _, f := range result {
			if f.RiskScore == nil {
				continue
			}
			if f.RiskScore.Total >= af.MinRiskScore && f.RiskScore.Total <= af.MaxRiskScore {
				out = append(out, f)
			}
		}
		result = out
	}

	return result
}

// resolveFormats returns the list of output formats to generate.
// Priority: --formats > --format > default (markdown + html).
func resolveFormats(af *AnalyzeFlags) []string {
	if af.Formats != "" {
		return splitFields(af.Formats)
	}
	if af.Format != "" {
		return []string{af.Format}
	}
	return []string{"markdown", "html"}
}

// printSummary prints a quick stats summary to stdout.
func printSummary(r *models.Report) {
	fmt.Printf("\n── Analysis Complete ──────────────────────────────────────\n")
	fmt.Printf("  Total findings:  %d\n", r.Stats.Total)
	fmt.Printf("  Critical:        %d\n", r.Stats.Critical)
	fmt.Printf("  High:            %d\n", r.Stats.High)
	fmt.Printf("  Medium:          %d\n", r.Stats.Medium)
	fmt.Printf("  Low:             %d\n", r.Stats.Low)
	fmt.Printf("  Mean risk score: %.2f\n", r.Stats.RiskStats.Mean)
	fmt.Printf("  Risk range:      %.2f - %.2f\n", r.Stats.RiskStats.Min, r.Stats.RiskStats.Max)
	fmt.Printf("──────────────────────────────────────────────────────────\n")
}

func splitUpper(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitFields(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
