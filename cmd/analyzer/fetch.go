package analyzer

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/wanaware/GCP-Sec/pkg/fetcher"
)

// FetchFlags holds parsed CLI flags for the fetch command.
type FetchFlags struct {
	OrgID   string
	Days    int
	SaveCSV string
	AnalyzeFlags
}

func runFetch(args []string) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	ff := &FetchFlags{}

	// Fetch-specific flags
	fs.StringVar(&ff.OrgID, "org-id", "", "GCP organization ID (required)")
	fs.IntVar(&ff.Days, "days", 7, "Lookback window in days")
	fs.StringVar(&ff.SaveCSV, "save-csv", "", "Save raw fetched findings as CSV")

	// Shared analysis flags (same as analyze command)
	fs.StringVar(&ff.Output, "output", "", "Output file path; stem is used for multi-format output")
	fs.StringVar(&ff.Output, "o", "", "Output file path (shorthand)")
	fs.StringVar(&ff.Format, "format", "", "Single output format: markdown, html, json, csv (default: generates markdown+html)")
	fs.StringVar(&ff.Format, "f", "", "Output format (shorthand)")
	fs.StringVar(&ff.OutputDir, "output-dir", "", "Output directory")
	fs.StringVar(&ff.OutputDir, "d", "", "Output directory (shorthand)")
	fs.StringVar(&ff.Formats, "formats", "", "Comma-separated output formats")
	fs.StringVar(&ff.Priorities, "priority", "", "Filter by priority (comma-separated)")
	fs.StringVar(&ff.Priorities, "p", "", "Filter by priority (shorthand)")
	fs.StringVar(&ff.Categories, "category", "", "Filter by category (comma-separated)")
	fs.StringVar(&ff.Categories, "c", "", "Filter by category (shorthand)")
	fs.StringVar(&ff.Projects, "project", "", "Filter by project (comma-separated)")
	fs.BoolVar(&ff.SplitByPriority, "split-by-priority", false, "Split output by priority")
	fs.BoolVar(&ff.IncludeRemediation, "include-remediation", true, "Include remediation steps and scripts (default: enabled)")
	fs.BoolVar(&ff.IncludeCompliance, "include-compliance", false, "Include compliance details")
	fs.BoolVar(&ff.AIEnhance, "ai-enhance", false, "Enrich CRITICAL findings via Claude AI (requires ANTHROPIC_API_KEY)")
	fs.Float64Var(&ff.MinRiskScore, "min-risk-score", 0, "Minimum risk score")
	fs.Float64Var(&ff.MaxRiskScore, "max-risk-score", 100, "Maximum risk score")
	fs.BoolVar(&ff.Verbose, "verbose", false, "Verbose logging")
	fs.BoolVar(&ff.Verbose, "v", false, "Verbose logging (shorthand)")
	fs.BoolVar(&ff.Debug, "debug", false, "Debug logging")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		return 1
	}

	if ff.OrgID == "" {
		fmt.Fprintf(os.Stderr, "Error: --org-id is required\n\nUsage: GCP-Sec fetch --org-id <ORG_ID> [options]\n")
		return 1
	}

	if ff.Days < 1 {
		fmt.Fprintf(os.Stderr, "Error: --days must be at least 1\n")
		return 1
	}

	logger := GlobalConfig.Logger

	// Create a context that is cancelled on interrupt (Ctrl+C).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// ── Fetch findings from GCP SCC API ───────────────────────────────────
	f := fetcher.NewFetcher(ff.OrgID, logger)
	findings, err := f.FetchFindings(ctx, ff.Days)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if len(findings) == 0 {
		fmt.Println("No active findings found in the specified time window.")
		return 0
	}

	// ── Run the shared analysis pipeline ──────────────────────────────────
	sourceLabel := fmt.Sprintf("GCP SCC org:%s (last %d days)", ff.OrgID, ff.Days)
	baseName := fmt.Sprintf("scc-org-%s-report", ff.OrgID)

	return runPipeline(PipelineInput{
		Findings:    findings,
		SourceLabel: sourceLabel,
		BaseName:    baseName,
		ParseErrors: 0,
		Flags:       &ff.AnalyzeFlags,
		Logger:      logger,
		SaveCSVPath: ff.SaveCSV,
	})
}
