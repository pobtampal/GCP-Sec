// Package parser provides CSV parsing for GCP Security Command Center findings.
package parser

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
)

// fieldIndex maps CSV column names to their index in the header row.
type fieldIndex map[string]int

// columnAliases maps known GCP SCC CSV column name variants to the canonical
// column names used by parseRow(). This allows the parser to handle both the
// simplified column names (used in sample/test data) and the dotted API paths
// produced by "gcloud scc findings list --format=csv".
var columnAliases = map[string]string{
	// Core finding fields
	"finding.name":          "name",
	"finding.finding_class": "finding_class",
	"finding.findingClass":  "finding_class",
	"finding.finding_type":  "finding_type",
	"finding.findingType":   "finding_type",
	"finding.category":      "category",
	"finding.state":         "state",
	"finding.severity":      "severity",

	// Resource fields
	"resource.name":                 "resource_name",
	"resource.display_name":         "resource_display_name",
	"resource.displayName":          "resource_display_name",
	"resource.type":                 "resource_type",
	"resource.resourceType":         "resource_type",
	"resource.resource_type":        "resource_type",
	"resource.project_id":           "project_id",
	"resource.projectId":            "project_id",
	"resource.project_display_name": "project_display_name",
	"resource.projectDisplayName":   "project_display_name",

	// Timestamps
	"finding.event_time":  "event_time",
	"finding.eventTime":   "event_time",
	"finding.create_time": "create_time",
	"finding.createTime":  "create_time",

	// Text fields
	"finding.description":  "description",
	"finding.external_uri": "external_uri",
	"finding.externalUri":  "external_uri",
	"finding.nextSteps":    "finding.next_steps",
}

// Parser parses GCP Security Command Center CSV exports into Finding structs.
type Parser struct {
	logger *utils.Logger
}

// NewParser creates a new CSV Parser with the provided logger.
func NewParser(logger *utils.Logger) *Parser {
	if logger == nil {
		logger = utils.DefaultLogger
	}
	return &Parser{logger: logger}
}

// ParseFile opens a CSV file and parses all findings from it.
// It returns the slice of findings and any non-fatal parse errors encountered.
func (p *Parser) ParseFile(path string) ([]*models.Finding, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("opening CSV file: %w", err)
	}
	defer f.Close()
	return p.Parse(f)
}

// Parse reads CSV data from r and returns the parsed findings.
// parseErrors counts rows that were skipped due to errors.
func (p *Parser) Parse(r io.Reader) ([]*models.Finding, int, error) {
	reader := csv.NewReader(r)
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1 // variable number of fields

	// Read header row
	header, err := reader.Read()
	if err != nil {
		return nil, 0, fmt.Errorf("reading CSV header: %w", err)
	}

	idx := buildIndex(header)
	p.logger.Debug("Parsed CSV header with %d columns", len(header))

	var findings []*models.Finding
	parseErrors := 0
	rowNum := 1

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		rowNum++
		if err != nil {
			p.logger.Warn("Row %d: skipping malformed row: %v", rowNum, err)
			parseErrors++
			continue
		}

		finding, err := p.parseRow(idx, row, rowNum)
		if err != nil {
			p.logger.Warn("Row %d: %v", rowNum, err)
			parseErrors++
			continue
		}
		findings = append(findings, finding)
	}

	p.logger.Info("Parsed %d findings (%d errors) from CSV", len(findings), parseErrors)
	return findings, parseErrors, nil
}

// buildIndex creates a column-name → index map from the header row.
// It performs two passes: first it indexes every column by its exact header
// name, then it registers canonical aliases from columnAliases so that
// parseRow() works regardless of whether the CSV uses bare names or dotted
// GCP SCC API paths. Existing bare-name entries are never overwritten
// ("first column wins"), ensuring backward compatibility.
func buildIndex(header []string) fieldIndex {
	idx := make(fieldIndex, len(header))

	// First pass: index every column by its exact header name.
	for i, col := range header {
		idx[strings.TrimSpace(col)] = i
	}

	// Second pass: for each column that has a known canonical alias,
	// add the canonical name to the index only if it is not already present.
	for i, col := range header {
		col = strings.TrimSpace(col)
		if canonical, ok := columnAliases[col]; ok {
			if _, exists := idx[canonical]; !exists {
				idx[canonical] = i
			}
		}
	}

	return idx
}

// get safely retrieves a trimmed value from a row by column name.
func get(idx fieldIndex, row []string, col string) string {
	i, ok := idx[col]
	if !ok || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}

// parseRow converts a single CSV row into a Finding.
func (p *Parser) parseRow(idx fieldIndex, row []string, rowNum int) (*models.Finding, error) {
	f := &models.Finding{}

	// Core fields
	f.Name = get(idx, row, "name")
	f.FindingClass = strings.ToUpper(get(idx, row, "finding_class"))
	f.FindingType = get(idx, row, "finding_type")
	f.Category = strings.ToUpper(get(idx, row, "category"))
	f.State = strings.ToUpper(get(idx, row, "state"))
	f.Severity = strings.ToUpper(get(idx, row, "severity"))

	// Apply defaults for missing required fields
	if f.Severity == "" {
		p.logger.Debug("Row %d: missing severity, defaulting to LOW", rowNum)
		f.Severity = "LOW"
	}
	if f.State == "" {
		f.State = "ACTIVE"
	}

	// Resource fields
	f.ResourceName = get(idx, row, "resource_name")
	f.ResourceDisplayName = get(idx, row, "resource_display_name")
	f.ResourceType = get(idx, row, "resource_type")
	f.ProjectDisplayName = get(idx, row, "project_display_name")
	f.ProjectID = get(idx, row, "project_id")

	// Timestamps
	f.EventTimeRaw = get(idx, row, "event_time")
	f.CreateTimeRaw = get(idx, row, "create_time")
	f.EventTime = parseTime(f.EventTimeRaw)
	f.CreateTime = parseTime(f.CreateTimeRaw)

	// Text fields
	f.Description = get(idx, row, "description")
	f.NextSteps = get(idx, row, "finding.next_steps")
	f.ExternalURI = get(idx, row, "external_uri")

	// Raw vulnerability fields
	f.CVSSv3Raw = get(idx, row, "finding.vulnerability.cve.cvssv3")
	f.CVEIDRaw = get(idx, row, "finding.vulnerability.cve.id")
	f.ObservedInWildRaw = get(idx, row, "finding.vulnerability.cve.observed_in_the_wild")
	f.ZeroDayRaw = get(idx, row, "finding.vulnerability.cve.zero_day")
	f.ExploitabilityRaw = get(idx, row, "finding.vulnerability.cve.exploitation_activity")

	// Parse CVE fields
	f.CVEID = parseCVEID(f.CVEIDRaw)
	f.CVSSScore = parseCVSSScore(f.CVSSv3Raw, p.logger, rowNum)
	f.ObservedInWild = utils.ParseBool(f.ObservedInWildRaw)
	f.ZeroDay = utils.ParseBool(f.ZeroDayRaw)
	f.ExploitActivity = strings.ToUpper(strings.TrimSpace(f.ExploitabilityRaw))

	// Exposure
	f.PublicIPAddressRaw = get(idx, row, "finding.external_exposure.public_ip_address")
	f.PublicIPAddress = utils.ParseBool(f.PublicIPAddressRaw)

	// Compliance raw fields
	f.CompliancesRaw = get(idx, row, "finding.compliances")
	f.ComplianceDetailsRaw = get(idx, row, "finding.compliance_details.frameworks")
	f.CloudControlRaw = get(idx, row, "finding.compliance_details.cloud_control")

	// Parse compliance frameworks
	f.ComplianceFrameworks = parseComplianceFrameworks(f.CompliancesRaw)

	// Labels
	f.ResourceLabelsRaw = get(idx, row, "resource.labels")
	f.FindingLabelsRaw = get(idx, row, "finding.source_properties")

	return f, nil
}

// parseCVSSScore extracts the numeric base score from the cvssv3 JSON field.
// Example JSON: {"base_score": 7.5, "attack_vector": "NETWORK", ...}
func parseCVSSScore(raw string, logger *utils.Logger, rowNum int) float64 {
	if raw == "" {
		return 0
	}
	// Try JSON object with base_score key
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &obj); err == nil {
		// Try common field names
		for _, key := range []string{"base_score", "baseScore", "score"} {
			if v, ok := obj[key]; ok {
				switch val := v.(type) {
				case float64:
					return val
				case string:
					if f, err := strconv.ParseFloat(val, 64); err == nil {
						return f
					}
				}
			}
		}
	}
	// Try plain number
	if f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err == nil {
		return f
	}
	if logger != nil {
		logger.Debug("Row %d: could not parse CVSS score from %q", rowNum, raw)
	}
	return 0
}

// parseCVEID extracts the CVE identifier from the raw field.
// The field may contain a bare ID ("CVE-2021-44228") or a JSON value.
func parseCVEID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Strip surrounding quotes or JSON string
	raw = strings.Trim(raw, "\"")
	if strings.HasPrefix(strings.ToUpper(raw), "CVE-") {
		return strings.ToUpper(raw)
	}
	// Try JSON string
	var s string
	if err := json.Unmarshal([]byte(raw), &s); err == nil {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(strings.ToUpper(s), "CVE-") {
			return strings.ToUpper(s)
		}
	}
	return raw
}

// parseComplianceFrameworks extracts framework names from the compliances JSON field.
// The field may be a JSON array like: [{"standard": "CIS", "version": "1.2", "ids": ["3.1"]}]
func parseComplianceFrameworks(raw string) []string {
	if raw == "" {
		return nil
	}
	var frameworks []string

	// Try JSON array of objects
	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &arr); err == nil {
		for _, item := range arr {
			for _, key := range []string{"standard", "framework", "name"} {
				if v, ok := item[key]; ok {
					if s, ok := v.(string); ok && s != "" {
						frameworks = append(frameworks, strings.ToUpper(s))
						break
					}
				}
			}
		}
		return utils.UniqueStrings(frameworks)
	}

	// Try JSON array of strings
	var sarr []string
	if err := json.Unmarshal([]byte(raw), &sarr); err == nil {
		for _, s := range sarr {
			frameworks = append(frameworks, strings.ToUpper(strings.TrimSpace(s)))
		}
		return utils.UniqueStrings(frameworks)
	}

	// Plain comma-separated
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			frameworks = append(frameworks, strings.ToUpper(p))
		}
	}
	return utils.UniqueStrings(frameworks)
}

// parseTime tries several common timestamp formats.
var timeFormats = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05Z",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, format := range timeFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
