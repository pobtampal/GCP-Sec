package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wanaware/GCP-Sec/internal/models"
)

// claudeOKResponse builds a minimal Claude API response wrapping the given JSON body.
func claudeOKResponse(body enrichResult) []byte {
	text, _ := json.Marshal(body)
	resp := map[string]interface{}{
		"content": []map[string]string{
			{"type": "text", "text": string(text)},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// criticalFinding builds a minimal CRITICAL finding for enricher tests.
func criticalFinding() *models.Finding {
	f := &models.Finding{
		Name:         "organizations/123/sources/1/findings/test001",
		Category:     "OPEN_FIREWALL_TO_PUBLIC",
		Severity:     "CRITICAL",
		Priority:     models.PriorityCritical,
		ProjectID:    "test-project",
		ResourceName: "//compute.googleapis.com/projects/test-project/global/firewalls/allow-all",
		Description:  "Firewall allows all inbound traffic.",
		RiskScore:    &models.RiskScore{Total: 80, Rationale: "original rationale"},
		Remediation: &models.RemediationStep{
			RemediationScript:     "#!/bin/bash\necho original",
			RemediationScriptLang: "bash",
		},
	}
	return f
}

// enricherWithServer creates an Enricher pointed at the test server URL.
func enricherWithServer(serverURL string) *Enricher {
	e := NewEnricher("test-api-key", nil)
	e.httpClient = &http.Client{}
	// Override the URL by monkey-patching via a custom RoundTripper.
	e.httpClient.Transport = &redirectTransport{base: serverURL}
	return e
}

// redirectTransport rewrites the host of every request to the test server.
type redirectTransport struct {
	base string
}

func (r *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Build new URL: take path/query from original, host from base.
	newURL := r.base + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequest(req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return http.DefaultTransport.RoundTrip(newReq)
}

// TestEnricher_ParsesResponse verifies that a valid Claude response overwrites
// the finding's Rationale and RemediationScript fields.
func TestEnricher_ParsesResponse(t *testing.T) {
	want := enrichResult{
		RiskRationale:     "This firewall rule is dangerous.",
		RemediationScript: "#!/bin/bash\ngcloud compute firewall-rules delete allow-all",
		RemediationLang:   "bash",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(claudeOKResponse(want))
	}))
	defer srv.Close()

	e := enricherWithServer(srv.URL)
	f := criticalFinding()

	if err := e.Enrich(f); err != nil {
		t.Fatalf("Enrich returned error: %v", err)
	}

	if !strings.Contains(f.RiskScore.Rationale, want.RiskRationale) {
		t.Errorf("Rationale not updated: got %q, want to contain %q", f.RiskScore.Rationale, want.RiskRationale)
	}
	if f.Remediation.RemediationScript != want.RemediationScript {
		t.Errorf("RemediationScript not updated: got %q, want %q", f.Remediation.RemediationScript, want.RemediationScript)
	}
	if f.Remediation.RemediationScriptLang != "bash" {
		t.Errorf("RemediationScriptLang: got %q, want %q", f.Remediation.RemediationScriptLang, "bash")
	}
}

// TestEnricher_FallsBackOnAPIError verifies that when the server returns 500,
// the original finding values are preserved.
func TestEnricher_FallsBackOnAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":{"type":"server_error","message":"internal"}}`))
	}))
	defer srv.Close()

	e := enricherWithServer(srv.URL)
	f := criticalFinding()
	originalRationale := f.RiskScore.Rationale
	originalScript := f.Remediation.RemediationScript

	err := e.Enrich(f)
	if err == nil {
		t.Fatal("expected an error from 500 response, got nil")
	}

	// Original values must be unchanged.
	if f.RiskScore.Rationale != originalRationale {
		t.Errorf("Rationale was mutated on error: got %q", f.RiskScore.Rationale)
	}
	if f.Remediation.RemediationScript != originalScript {
		t.Errorf("RemediationScript was mutated on error: got %q", f.Remediation.RemediationScript)
	}
}

// TestEnricher_MarkdownFencesStripped verifies that Claude's response wrapped
// in ```json...``` fences is parsed correctly.
func TestEnricher_MarkdownFencesStripped(t *testing.T) {
	inner := `{"risk_rationale":"Risky.","remediation_script":"#!/bin/bash\necho fix","remediation_lang":"bash"}`
	fenced := "```json\n" + inner + "\n```"

	resp := map[string]interface{}{
		"content": []map[string]string{
			{"type": "text", "text": fenced},
		},
	}
	respBytes, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	}))
	defer srv.Close()

	e := enricherWithServer(srv.URL)
	f := criticalFinding()

	if err := e.Enrich(f); err != nil {
		t.Fatalf("Enrich with markdown fences failed: %v", err)
	}
	if !strings.Contains(f.RiskScore.Rationale, "Risky.") {
		t.Errorf("expected rationale to contain 'Risky.', got %q", f.RiskScore.Rationale)
	}
}

// TestEnrichAll_SkipsNonCritical verifies that EnrichAll only calls the API for
// CRITICAL findings, not MEDIUM or LOW.
func TestEnrichAll_SkipsNonCritical(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(claudeOKResponse(enrichResult{
			RiskRationale:     "test",
			RemediationScript: "#!/bin/bash\necho ok",
			RemediationLang:   "bash",
		}))
	}))
	defer srv.Close()

	e := enricherWithServer(srv.URL)

	findings := []*models.Finding{
		{Priority: models.PriorityCritical, RiskScore: &models.RiskScore{}, Remediation: &models.RemediationStep{}},
		{Priority: models.PriorityHigh, RiskScore: &models.RiskScore{}, Remediation: &models.RemediationStep{}},
		{Priority: models.PriorityMedium, RiskScore: &models.RiskScore{}},
		{Priority: models.PriorityLow, RiskScore: &models.RiskScore{}},
	}

	e.EnrichAll(findings)

	// Only the CRITICAL finding should trigger an API call.
	if callCount != 1 {
		t.Errorf("EnrichAll: expected 1 API call (CRITICAL only), got %d", callCount)
	}
}

// TestEnricher_AITagAppended verifies the "[AI-enhanced]" suffix is appended to rationale.
func TestEnricher_AITagAppended(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(claudeOKResponse(enrichResult{
			RiskRationale:     "LLM rationale here.",
			RemediationScript: "#!/bin/bash\necho ok",
			RemediationLang:   "bash",
		}))
	}))
	defer srv.Close()

	e := enricherWithServer(srv.URL)
	f := criticalFinding()
	e.Enrich(f) //nolint:errcheck

	if !strings.HasSuffix(f.RiskScore.Rationale, "[AI-enhanced]") {
		t.Errorf("expected '[AI-enhanced]' suffix, got: %s", f.RiskScore.Rationale)
	}
}
