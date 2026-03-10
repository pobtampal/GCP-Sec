package analyzer

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/wanaware/GCP-Sec/internal/utils"
	"github.com/wanaware/GCP-Sec/pkg/compliance"
	"github.com/wanaware/GCP-Sec/pkg/parser"
	"github.com/wanaware/GCP-Sec/pkg/report"
	"github.com/wanaware/GCP-Sec/pkg/scoring"
)

var statsValueFlags = map[string]bool{} // stats has no value-taking flags

func runStats(args []string) int {
	inputFile, flagArgs := utils.ExtractPositional(args, statsValueFlags)

	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	verbose := fs.Bool("verbose", false, "Verbose output")
	fs.Bool("v", false, "Verbose (shorthand)")

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if inputFile == "" {
		fmt.Fprintf(os.Stderr, "Error: input CSV file is required\n\nUsage: GCP-Sec stats <input.csv>\n")
		return 1
	}

	logger := GlobalConfig.Logger
	if *verbose {
		logger.SetLevel(utils.LevelDebug)
	}

	// Parse
	p := parser.NewParser(logger)
	findings, parseErrors, err := p.ParseFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Score
	engine := scoring.NewEngine(scoring.DefaultConfig(), logger)
	engine.ScoreAll(findings)

	// Compliance
	detector := compliance.NewDetector()
	for _, f := range findings {
		detector.DetectViolations(f)
	}

	// Build report
	builder := report.NewBuilder()
	r := builder.Build(findings, inputFile, parseErrors)
	r.ComplianceSummary = detector.Aggregate(findings)

	// Print stats to stdout
	fmt.Printf("\n══════════════════════════════════════════════════\n")
	fmt.Printf("  GCP Security Findings Statistics\n")
	fmt.Printf("══════════════════════════════════════════════════\n")
	fmt.Printf("  Input file:      %s\n", inputFile)
	fmt.Printf("  Total rows:      %d\n", r.TotalRows)
	fmt.Printf("  Parse errors:    %d\n", r.ParseErrors)
	fmt.Printf("  Active findings: %d\n\n", r.Stats.Total)

	fmt.Printf("  Priority Distribution:\n")
	fmt.Printf("  %-12s %6d  (%5.1f%%)\n", "CRITICAL", r.Stats.Critical, utils.SafePercentage(r.Stats.Critical, r.Stats.Total))
	fmt.Printf("  %-12s %6d  (%5.1f%%)\n", "HIGH", r.Stats.High, utils.SafePercentage(r.Stats.High, r.Stats.Total))
	fmt.Printf("  %-12s %6d  (%5.1f%%)\n", "MEDIUM", r.Stats.Medium, utils.SafePercentage(r.Stats.Medium, r.Stats.Total))
	fmt.Printf("  %-12s %6d  (%5.1f%%)\n\n", "LOW", r.Stats.Low, utils.SafePercentage(r.Stats.Low, r.Stats.Total))

	fmt.Printf("  Risk Score Statistics:\n")
	fmt.Printf("  %-16s %.2f\n", "Mean:", r.Stats.RiskStats.Mean)
	fmt.Printf("  %-16s %.2f\n", "Median:", r.Stats.RiskStats.Median)
	fmt.Printf("  %-16s %.2f\n", "Std Dev:", r.Stats.RiskStats.StdDev)
	fmt.Printf("  %-16s %.2f - %.2f\n\n", "Range:", r.Stats.RiskStats.Min, r.Stats.RiskStats.Max)

	fmt.Printf("  Top 10 Categories:\n")
	top := r.Stats.TopCategories
	if len(top) > 10 {
		top = top[:10]
	}
	for i, c := range top {
		fmt.Printf("  %2d. %-45s %5d\n", i+1, c.Category, c.Count)
	}

	if len(r.ComplianceSummary) > 0 {
		fmt.Printf("\n  Compliance Frameworks Detected:\n")
		fws := make([]string, 0, len(r.ComplianceSummary))
		for fw := range r.ComplianceSummary {
			fws = append(fws, fw)
		}
		sort.Strings(fws)
		for _, fw := range fws {
			fmt.Printf("  %-20s %d violations\n", fw+":", len(r.ComplianceSummary[fw]))
		}
	}

	if len(r.ProjectBreakdown) > 0 {
		fmt.Printf("\n  Top Projects:\n")
		projs := make([]struct {
			Name  string
			Count int
		}, 0, len(r.ProjectBreakdown))
		for _, ps := range r.ProjectBreakdown {
			projs = append(projs, struct {
				Name  string
				Count int
			}{ps.ProjectName, ps.Count})
		}
		sort.Slice(projs, func(i, j int) bool { return projs[i].Count > projs[j].Count })
		limit := 5
		if len(projs) < limit {
			limit = len(projs)
		}
		for i, proj := range projs[:limit] {
			fmt.Printf("  %2d. %-45s %5d\n", i+1, proj.Name, proj.Count)
		}
	}

	fmt.Printf("\n══════════════════════════════════════════════════\n\n")
	return 0
}
