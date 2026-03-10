package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
)

// Builder assembles a complete Report from scored findings.
type Builder struct{}

// NewBuilder creates a new Builder.
func NewBuilder() *Builder { return &Builder{} }

// Build constructs a Report from the given findings slice.
func (b *Builder) Build(findings []*models.Finding, inputFile string, parseErrors int) *models.Report {
	r := &models.Report{
		GeneratedAt: time.Now().UTC(),
		InputFile:   inputFile,
		TotalRows:   len(findings) + parseErrors,
		ParseErrors: parseErrors,
		Findings:    findings,
	}

	r.Stats = b.computeStats(findings)
	r.CategoryBreakdown = b.buildCategoryBreakdown(findings)
	r.ProjectBreakdown = b.buildProjectBreakdown(findings)

	return r
}

// computeStats builds the ReportStats from findings.
func (b *Builder) computeStats(findings []*models.Finding) models.ReportStats {
	stats := models.ReportStats{Total: len(findings)}

	scores := make([]float64, 0, len(findings))
	catCount := map[string]int{}
	projCount := map[string]int{}

	for _, f := range findings {
		switch f.Priority {
		case models.PriorityCritical:
			stats.Critical++
		case models.PriorityHigh:
			stats.High++
		case models.PriorityMedium:
			stats.Medium++
		default:
			stats.Low++
		}

		if f.RiskScore != nil {
			scores = append(scores, f.RiskScore.Total)
		}

		catCount[f.Category]++
		proj := f.ProjectDisplayName
		if proj == "" {
			proj = f.ProjectID
		}
		if proj != "" {
			projCount[proj]++
		}
	}

	// Risk stats
	sort.Float64s(scores)
	if len(scores) > 0 {
		stats.RiskStats = models.RiskScoreStats{
			Count:  len(scores),
			Mean:   utils.Round(utils.Mean(scores), 2),
			Median: utils.Round(utils.Median(scores), 2),
			Min:    scores[0],
			Max:    scores[len(scores)-1],
			StdDev: utils.Round(utils.StdDev(scores), 2),
		}
	}

	// Top categories
	for cat, cnt := range catCount {
		stats.TopCategories = append(stats.TopCategories, models.CategoryCount{
			Category: cat, Count: cnt,
		})
	}
	sort.Slice(stats.TopCategories, func(i, j int) bool {
		return stats.TopCategories[i].Count > stats.TopCategories[j].Count
	})

	// Top projects
	for proj, cnt := range projCount {
		stats.TopProjects = append(stats.TopProjects, models.ProjectCount{
			Project: proj, Count: cnt,
		})
	}
	sort.Slice(stats.TopProjects, func(i, j int) bool {
		return stats.TopProjects[i].Count > stats.TopProjects[j].Count
	})

	return stats
}

// buildCategoryBreakdown aggregates findings by category.
func (b *Builder) buildCategoryBreakdown(findings []*models.Finding) map[string]models.CategoryStats {
	m := map[string]models.CategoryStats{}
	scoreSum := map[string]float64{}
	count := map[string]int{}

	for _, f := range findings {
		cat := f.Category
		cs := m[cat]
		cs.Category = cat
		cs.Count++
		count[cat]++
		if f.RiskScore != nil {
			scoreSum[cat] += f.RiskScore.Total
		}
		switch f.Priority {
		case models.PriorityCritical:
			cs.Critical++
		case models.PriorityHigh:
			cs.High++
		case models.PriorityMedium:
			cs.Medium++
		default:
			cs.Low++
		}
		m[cat] = cs
	}

	for cat, cs := range m {
		if count[cat] > 0 {
			cs.AvgRiskScore = utils.Round(scoreSum[cat]/float64(count[cat]), 2)
		}
		m[cat] = cs
	}
	return m
}

// buildProjectBreakdown aggregates findings by GCP project.
func (b *Builder) buildProjectBreakdown(findings []*models.Finding) map[string]models.ProjectStats {
	m := map[string]models.ProjectStats{}
	scoreSum := map[string]float64{}
	count := map[string]int{}

	for _, f := range findings {
		projID := f.ProjectID
		if projID == "" {
			projID = f.ProjectDisplayName
		}
		if projID == "" {
			continue
		}

		ps := m[projID]
		ps.ProjectID = projID
		if ps.ProjectName == "" {
			ps.ProjectName = f.ProjectDisplayName
			if ps.ProjectName == "" {
				ps.ProjectName = projID
			}
		}
		ps.Count++
		count[projID]++
		if f.RiskScore != nil {
			scoreSum[projID] += f.RiskScore.Total
		}
		switch f.Priority {
		case models.PriorityCritical:
			ps.Critical++
		case models.PriorityHigh:
			ps.High++
		case models.PriorityMedium:
			ps.Medium++
		default:
			ps.Low++
		}
		m[projID] = ps
	}

	for projID, ps := range m {
		if count[projID] > 0 {
			ps.AvgRiskScore = utils.Round(scoreSum[projID]/float64(count[projID]), 2)
		}
		m[projID] = ps
	}
	return m
}

// WriteReport writes a report in the given format to the given output path.
// format may be "markdown", "json", "html", or "csv".
func WriteReport(r *models.Report, format, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file %s: %w", outputPath, err)
	}
	defer f.Close()

	switch strings.ToLower(format) {
	case "markdown", "md":
		return NewMarkdownGenerator().Generate(r, f)
	case "json":
		return NewJSONGenerator(true).Generate(r, f)
	case "html":
		return NewHTMLGenerator().Generate(r, f)
	case "csv":
		return NewCSVGenerator().Generate(r, f)
	default:
		return fmt.Errorf("unknown format: %s (supported: markdown, json, html, csv)", format)
	}
}

// WriteReports writes reports in multiple formats to outputDir.
func WriteReports(r *models.Report, formats []string, outputDir, baseName string) ([]string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	var written []string
	for _, fmt := range formats {
		ext := FormatExtension(fmt)
		path := filepath.Join(outputDir, baseName+"."+ext)
		if err := WriteReport(r, fmt, path); err != nil {
			return written, fmt2Errorf("writing %s report: %w", fmt, err)
		}
		written = append(written, path)
	}
	return written, nil
}

// WriteSplitByPriority writes separate files for each priority level.
func WriteSplitByPriority(r *models.Report, format, outputDir, baseName string) ([]string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	priorities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	var written []string

	for _, priority := range priorities {
		var pFindings []*models.Finding
		for _, f := range r.Findings {
			if f.Priority == priority {
				pFindings = append(pFindings, f)
			}
		}
		if len(pFindings) == 0 {
			continue
		}

		pReport := *r
		pReport.Findings = pFindings
		stats := models.ReportStats{Total: len(pFindings)}
		for _, f := range pFindings {
			switch f.Priority {
			case "CRITICAL":
				stats.Critical++
			case "HIGH":
				stats.High++
			case "MEDIUM":
				stats.Medium++
			default:
				stats.Low++
			}
		}
		pReport.Stats = stats

		ext := FormatExtension(format)
		path := filepath.Join(outputDir, baseName+"-"+strings.ToLower(priority)+"."+ext)
		if err := WriteReport(&pReport, format, path); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// FormatExtension returns the file extension for a given format name.
func FormatExtension(format string) string {
	switch strings.ToLower(format) {
	case "markdown", "md":
		return "md"
	case "html":
		return "html"
	case "json":
		return "json"
	case "csv":
		return "csv"
	default:
		return format
	}
}

// WriteRemediationScripts writes individual runnable script files to
// <outDir>/remediation-scripts/ for every CRITICAL finding that has a script.
// Returns the list of file paths written and any fatal error.
func WriteRemediationScripts(r *models.Report, outDir string) ([]string, error) {
	scriptsDir := filepath.Join(outDir, "remediation-scripts")
	if err := os.MkdirAll(scriptsDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating remediation-scripts dir: %w", err)
	}

	var written []string
	for _, f := range r.Findings {
		if f.Remediation == nil || f.Remediation.RemediationScript == "" {
			continue
		}

		ext := "sh"
		if f.Remediation.RemediationScriptLang == "python3" {
			ext = "py"
		}

		// Derive a filesystem-safe base name from the finding's short name.
		shortName := f.ShortName()
		if shortName == "" {
			shortName = strings.NewReplacer(" ", "-", "_", "-").Replace(f.Category)
		}
		fileName := shortName + "-remediate." + ext
		filePath := filepath.Join(scriptsDir, fileName)

		file, err := os.Create(filePath)
		if err != nil {
			return written, fmt.Errorf("creating script file %s: %w", filePath, err)
		}

		_, writeErr := file.WriteString(f.Remediation.RemediationScript)
		closeErr := file.Close()

		if writeErr != nil {
			return written, fmt.Errorf("writing script %s: %w", filePath, writeErr)
		}
		if closeErr != nil {
			return written, fmt.Errorf("closing script %s: %w", filePath, closeErr)
		}

		// Make scripts directly executable.
		if err := os.Chmod(filePath, 0o755); err != nil {
			return written, fmt.Errorf("chmod %s: %w", filePath, err)
		}

		written = append(written, filePath)
	}
	return written, nil
}

// fmt2Errorf is a local alias to avoid shadowing the fmt package import.
func fmt2Errorf(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}
