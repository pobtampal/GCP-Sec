package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
	"github.com/wanaware/GCP-Sec/pkg/compliance"
	"github.com/wanaware/GCP-Sec/pkg/llm"
	"github.com/wanaware/GCP-Sec/pkg/remediation"
	"github.com/wanaware/GCP-Sec/pkg/report"
	"github.com/wanaware/GCP-Sec/pkg/scoring"
)

// PipelineInput holds all inputs to the shared analysis pipeline.
type PipelineInput struct {
	Findings    []*models.Finding
	SourceLabel string // e.g. "findings.csv" or "GCP SCC org:123456"
	BaseName    string // base name for output files (without extension)
	ParseErrors int
	Flags       *AnalyzeFlags
	Logger      *utils.Logger
	SaveCSVPath string // optional: save scored findings as CSV before filtering
}

// runPipeline executes the full analysis pipeline: scoring, compliance
// detection, remediation, AI enrichment, filtering, report building,
// and output writing. Returns the exit code (0 = success).
func runPipeline(input PipelineInput) int {
	findings := input.Findings
	af := input.Flags
	logger := input.Logger

	// ── Score findings ─────────────────────────────────────────────────────
	logger.Info("Scoring %d findings...", len(findings))
	engine := scoring.NewEngine(scoring.DefaultConfig(), logger)
	engine.ScoreAll(findings)

	// ── Compliance detection ───────────────────────────────────────────────
	detector := compliance.NewDetector()
	for _, f := range findings {
		detector.DetectViolations(f)
	}

	// ── Remediation guidance ───────────────────────────────────────────────
	if af.IncludeRemediation {
		logger.Info("Generating remediation guidance...")
		gen := remediation.NewGenerator()
		gen.GenerateAll(findings)
	}

	// ── AI enrichment (optional) ───────────────────────────────────────────
	if af.AIEnhance {
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			fmt.Fprintln(os.Stderr, "Warning: --ai-enhance set but ANTHROPIC_API_KEY is not set; skipping AI enrichment")
		} else {
			logger.Info("AI-enhancing CRITICAL findings via Claude API...")
			enricher := llm.NewEnricher(apiKey, logger)
			enricher.EnrichAll(findings)
		}
	}

	// ── Save raw scored findings as CSV (optional) ─────────────────────────
	if input.SaveCSVPath != "" {
		logger.Info("Saving scored findings to CSV: %s", input.SaveCSVPath)
		saveReport := &models.Report{Findings: findings}
		if err := report.WriteReport(saveReport, "csv", input.SaveCSVPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: error saving CSV: %v\n", err)
		} else {
			fmt.Printf("  Saved findings CSV: %s\n", input.SaveCSVPath)
		}
	}

	// ── Apply filters ──────────────────────────────────────────────────────
	filtered := applyFilters(findings, af)
	logger.Info("Findings after filtering: %d", len(filtered))

	// ── Build report ───────────────────────────────────────────────────────
	builder := report.NewBuilder()
	r := builder.Build(filtered, input.SourceLabel, input.ParseErrors)

	if af.IncludeCompliance {
		r.ComplianceSummary = detector.Aggregate(filtered)
	}

	// ── Print summary to stdout ────────────────────────────────────────────
	printSummary(r)

	// ── Write report(s) ────────────────────────────────────────────────────
	formats := resolveFormats(af)
	// Append a timestamp to the default base name so every run produces unique files.
	baseName := input.BaseName + "-" + time.Now().Format("20060102-150405")

	// When -o is provided, its stem and directory take precedence over the
	// input-file-derived baseName (e.g. -o security-report.md → stem "security-report").
	outDir := af.OutputDir
	if af.Output != "" && outDir == "" {
		if dir := filepath.Dir(af.Output); dir != "" && dir != "." {
			outDir = dir
		}
		if stem := strings.TrimSuffix(filepath.Base(af.Output), filepath.Ext(af.Output)); stem != "" {
			baseName = stem
		}
	}

	if outDir != "" || len(formats) > 1 {
		if outDir == "" {
			outDir = "."
		}
		if af.SplitByPriority {
			for _, fmtName := range formats {
				written, err := report.WriteSplitByPriority(r, fmtName, outDir, baseName)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error writing split reports: %v\n", err)
					return 1
				}
				for _, path := range written {
					fmt.Printf("  Wrote: %s\n", path)
				}
			}
		} else {
			written, err := report.WriteReports(r, formats, outDir, baseName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error writing reports: %v\n", err)
				return 1
			}
			for _, path := range written {
				fmt.Printf("  Wrote: %s\n", path)
			}
		}
	} else {
		// Single format explicitly requested via --format or --formats with one entry.
		outPath := af.Output
		fmtName := formats[0]
		if outPath == "" {
			outPath = baseName + "." + report.FormatExtension(fmtName)
		}
		if err := report.WriteReport(r, fmtName, outPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
			return 1
		}
		fmt.Printf("\nReport written to: %s\n", outPath)
		outDir = filepath.Dir(outPath)
		if outDir == "" {
			outDir = "."
		}
	}

	// ── Write per-finding remediation scripts ──────────────────────────────
	if af.IncludeRemediation {
		scriptFiles, err := report.WriteRemediationScripts(r, outDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: error writing remediation scripts: %v\n", err)
		}
		for _, path := range scriptFiles {
			fmt.Printf("  Script: %s\n", path)
		}
		if len(scriptFiles) > 0 {
			fmt.Printf("  [%d remediation script(s) in %s/remediation-scripts/]\n",
				len(scriptFiles), outDir)
		}
	}

	return 0
}
