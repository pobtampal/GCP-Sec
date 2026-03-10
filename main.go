// GCP-Sec analyzes GCP Security Command Center findings
// from CSV exports and generates comprehensive security reports with
// risk scoring, compliance violations, and remediation guidance.
package main

import (
	"os"

	"github.com/wanaware/GCP-Sec/cmd/analyzer"
)

func main() {
	os.Exit(analyzer.Execute(os.Args[1:]))
}
