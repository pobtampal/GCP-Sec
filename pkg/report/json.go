package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
)

// JSONGenerator writes JSON-formatted reports.
type JSONGenerator struct {
	Pretty bool
}

// NewJSONGenerator creates a new JSONGenerator.
// When pretty is true, output is indented for human reading.
func NewJSONGenerator(pretty bool) *JSONGenerator {
	return &JSONGenerator{Pretty: pretty}
}

// Generate writes a JSON report for r to w.
func (g *JSONGenerator) Generate(r *models.Report, w io.Writer) error {
	if r.GeneratedAt.IsZero() {
		r.GeneratedAt = time.Now().UTC()
	}

	var (
		b   []byte
		err error
	)
	if g.Pretty {
		b, err = json.MarshalIndent(r, "", "  ")
	} else {
		b, err = json.Marshal(r)
	}
	if err != nil {
		return fmt.Errorf("marshalling report to JSON: %w", err)
	}

	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("writing JSON report: %w", err)
	}
	return nil
}
