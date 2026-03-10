// Package analyzer implements the CLI commands for GCP-Sec.
package analyzer

import (
	"fmt"
	"os"
	"strings"

	"github.com/wanaware/GCP-Sec/internal/utils"
)

// Config holds global CLI configuration shared between subcommands.
type Config struct {
	Verbose bool
	Debug   bool
	Logger  *utils.Logger
}

// GlobalConfig is the shared configuration populated by persistent flags.
var GlobalConfig Config

// Execute is the entry point for the CLI. It dispatches to subcommands.
func Execute(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}

	cmd := strings.ToLower(args[0])
	remaining := args[1:]

	// Setup logger based on flags present in remaining args
	level := utils.LevelInfo
	for _, a := range remaining {
		if a == "--debug" {
			level = utils.LevelDebug
		} else if a == "-v" || a == "--verbose" {
			level = utils.LevelDebug
		}
	}
	GlobalConfig.Logger = utils.NewLogger(level, os.Stderr)

	switch cmd {
	case "analyze":
		return runAnalyze(remaining)
	case "fetch":
		return runFetch(remaining)
	case "stats":
		return runStats(remaining)
	case "filter":
		return runFilter(remaining)
	case "help", "--help", "-h":
		printUsage()
		return 0
	case "version", "--version":
		fmt.Println("GCP-Sec v1.0.0")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", cmd)
		printUsage()
		return 1
	}
}

func printUsage() {
	fmt.Print(`GCP-Sec - GCP Security Command Center findings analyzer

USAGE:
  GCP-Sec <command> [options] [input.csv]

COMMANDS:
  analyze     Analyze findings from a CSV file and generate a report
  fetch       Fetch findings live from GCP SCC API and analyze
  stats       Show statistics summary
  filter      Filter findings and export to CSV
  help        Show this help
  version     Show version

FETCH OPTIONS:
      --org-id <id>            GCP organization ID (required)
      --days <n>               Lookback window in days (default: 7)
      --save-csv <path>        Save raw fetched findings as CSV
  (All analyze options below also apply to fetch)

ANALYZE OPTIONS:
  -o, --output <path>         Output file path; stem sets the base name for multi-format output
  -f, --format <fmt>          Single output format: markdown, html, json, csv
                              (omit to use default: both markdown + html)
  -d, --output-dir <dir>      Output directory (overrides directory derived from -o)
      --formats <fmt,...>      Comma-separated formats (e.g. markdown,html,json)
  -p, --priority <p,...>      Filter: critical,high,medium,low
  -c, --category <c,...>      Filter by category
      --project <p,...>        Filter by GCP project ID
      --split-by-priority      Write separate files per priority level
      --include-remediation    Include remediation steps and scripts (default: true)
      --include-compliance     Include compliance violation details
      --ai-enhance             AI-enrich CRITICAL findings via Claude API (requires ANTHROPIC_API_KEY)
      --min-risk-score <f>     Minimum risk score filter (default: 0)
      --max-risk-score <f>     Maximum risk score filter (default: 100)
  -v, --verbose               Verbose logging
      --debug                 Debug logging

STATS OPTIONS:
  -v, --verbose               Verbose logging

FILTER OPTIONS:
  -p, --priority <p,...>      Filter by priority
  -c, --category <c,...>      Filter by category
      --project <p,...>        Filter by project
      --min-risk-score <f>     Minimum risk score
  -o, --output <path>         Output CSV file

EXAMPLES:
  GCP-Sec analyze findings.csv
      # writes findings-report.md + findings-report.html (default)
  GCP-Sec analyze findings.csv -o security-report.md --include-remediation
      # writes security-report.md + security-report.html
  GCP-Sec analyze findings.csv --format json -o report.json
      # single format override
  GCP-Sec analyze findings.csv --formats markdown,json,html -d ./reports
      # explicit multi-format into a directory
  GCP-Sec fetch --org-id 123456789 --days 7 -o report.md
      # writes report.md + report.html
  GCP-Sec fetch --org-id 123456789 --days 30 --save-csv raw.csv --include-remediation
  GCP-Sec stats findings.csv
  GCP-Sec filter findings.csv --priority high,critical -o high-findings.csv
`)
}
