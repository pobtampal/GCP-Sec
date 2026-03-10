// Package llm provides optional AI enrichment of findings via the Claude API.
// Enrichment is gated on --ai-enhance and ANTHROPIC_API_KEY; if either is absent
// the program falls back to template-based remediation with no degradation.
package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
)

const (
	claudeAPIURL = "https://api.anthropic.com/v1/messages"
	claudeModel  = "claude-haiku-4-5-20251001"
	apiVersion   = "2023-06-01"
	maxTokens    = 1024
	httpTimeout  = 30 * time.Second
)

// Enricher calls the Claude API to generate improved risk rationale and
// remediation scripts for CRITICAL findings.
type Enricher struct {
	apiKey     string
	httpClient *http.Client
	logger     *utils.Logger
}

// NewEnricher creates an Enricher backed by the given API key.
func NewEnricher(apiKey string, logger *utils.Logger) *Enricher {
	if logger == nil {
		logger = utils.DefaultLogger
	}
	return &Enricher{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		logger: logger,
	}
}

// EnrichAll enriches all CRITICAL findings in parallel (up to 4 concurrent calls).
// HIGH findings are also enriched when they have a RemediationScript already set.
// On any per-finding error the original values are preserved and a warning is logged.
func (e *Enricher) EnrichAll(findings []*models.Finding) {
	type job struct {
		f *models.Finding
	}

	jobs := make(chan job, len(findings))
	for _, f := range findings {
		if f.Priority == models.PriorityCritical {
			jobs <- job{f}
		}
	}
	close(jobs)

	if len(jobs) == 0 {
		return
	}

	workers := 4
	if len(jobs) < workers {
		workers = len(jobs)
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if err := e.Enrich(j.f); err != nil {
					e.logger.Warn("LLM enrichment failed for %s: %v", j.f.ShortName(), err)
				}
			}
		}()
	}
	wg.Wait()
}

// claudeRequest is the JSON body sent to the Claude Messages API.
type claudeRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// claudeResponse is the subset of the API response we care about.
type claudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// enrichResult is the JSON structure we ask Claude to return.
type enrichResult struct {
	RiskRationale    string `json:"risk_rationale"`
	RemediationScript string `json:"remediation_script"`
	RemediationLang  string `json:"remediation_lang"`
}

// Enrich calls the Claude API for a single finding and overwrites the finding's
// Rationale and RemediationScript fields with the LLM response.
// If the finding has no Remediation yet (--include-remediation not used) the
// RemediationScript is still populated so callers can write it to disk.
func (e *Enricher) Enrich(f *models.Finding) error {
	prompt := e.buildPrompt(f)

	reqBody, err := json.Marshal(claudeRequest{
		Model:     claudeModel,
		MaxTokens: maxTokens,
		Messages: []message{
			{Role: "user", Content: prompt},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, claudeAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", e.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http call: %w", err)
	}
	defer resp.Body.Close()

	var cr claudeResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return fmt.Errorf("decode response (status %d): %w", resp.StatusCode, err)
	}

	if cr.Error != nil {
		return fmt.Errorf("API error %s: %s", cr.Error.Type, cr.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if len(cr.Content) == 0 {
		return fmt.Errorf("empty response content")
	}

	result, err := e.parseResult(cr.Content[0].Text)
	if err != nil {
		return fmt.Errorf("parse LLM result: %w", err)
	}

	// Apply enriched values — only overwrite if LLM returned non-empty strings.
	if f.RiskScore != nil && result.RiskRationale != "" {
		f.RiskScore.Rationale = result.RiskRationale + " [AI-enhanced]"
	}
	if result.RemediationScript != "" {
		lang := result.RemediationLang
		if lang == "" {
			lang = "bash"
		}
		if f.Remediation != nil {
			f.Remediation.RemediationScript = result.RemediationScript
			f.Remediation.RemediationScriptLang = lang
		}
	}

	return nil
}

// buildPrompt constructs the full-context prompt sent to Claude.
// Includes all available finding data — category, severity, resource, description, CVE.
func (e *Enricher) buildPrompt(f *models.Finding) string {
	cveInfo := "N/A"
	if f.HasCVE() {
		cveInfo = f.CVEID
	}
	cvssInfo := "N/A"
	if f.CVSSScore > 0 {
		cvssInfo = fmt.Sprintf("%.1f", f.CVSSScore)
	}

	var sb strings.Builder
	sb.WriteString("You are a GCP security expert. Analyze the following GCP Security Command Center finding ")
	sb.WriteString("and return a JSON object with exactly these three fields:\n")
	sb.WriteString("  risk_rationale   — 2-3 sentence explanation of why this is a security risk\n")
	sb.WriteString("  remediation_script — a complete, runnable shell or Python script that fixes the issue\n")
	sb.WriteString("  remediation_lang — either \"bash\" or \"python3\"\n\n")
	sb.WriteString("Use the real resource names and project IDs from the finding when writing the script.\n")
	sb.WriteString("For bash scripts: include #!/bin/bash, set -euo pipefail, and a DRY_RUN guard.\n")
	sb.WriteString("For python3 scripts: include #!/usr/bin/env python3 and subprocess-based gcloud calls.\n\n")
	sb.WriteString("Return ONLY the JSON object — no markdown, no explanation outside the JSON.\n\n")
	sb.WriteString("Finding details:\n")
	fmt.Fprintf(&sb, "  Category:    %s\n", f.Category)
	fmt.Fprintf(&sb, "  Severity:    %s\n", f.Severity)
	fmt.Fprintf(&sb, "  Priority:    %s\n", f.Priority)
	fmt.Fprintf(&sb, "  Resource:    %s\n", f.ResourceName)
	fmt.Fprintf(&sb, "  Project:     %s\n", f.ProjectID)
	fmt.Fprintf(&sb, "  Description: %s\n", f.Description)
	fmt.Fprintf(&sb, "  CVE:         %s\n", cveInfo)
	fmt.Fprintf(&sb, "  CVSS:        %s\n", cvssInfo)
	if f.NextSteps != "" {
		fmt.Fprintf(&sb, "  Next steps:  %s\n", f.NextSteps)
	}
	return sb.String()
}

// parseResult extracts the enrichResult from Claude's text response.
// Claude is instructed to return raw JSON, but we strip any accidental markdown fences.
func (e *Enricher) parseResult(text string) (enrichResult, error) {
	text = strings.TrimSpace(text)
	// Strip optional ```json ... ``` or ``` ... ``` wrappers.
	if strings.HasPrefix(text, "```") {
		lines := strings.SplitN(text, "\n", 2)
		if len(lines) == 2 {
			text = lines[1]
		}
		if idx := strings.LastIndex(text, "```"); idx >= 0 {
			text = text[:idx]
		}
		text = strings.TrimSpace(text)
	}

	var result enrichResult
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		return enrichResult{}, fmt.Errorf("unmarshal JSON: %w (raw: %.200s)", err, text)
	}
	return result, nil
}
