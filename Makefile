BINARY    := gcp-security-analyzer
MAIN      := ./main.go
BUILD_DIR := ./dist
VERSION   := 1.0.0
LDFLAGS   := -ldflags="-X main.version=$(VERSION) -s -w"

.PHONY: all build test test-cover lint clean install run-sample run-fetch help setup-hooks sast govulncheck trivy-fs gitleaks semgrep

all: build

## build: Compile the binary
build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(MAIN)
	@echo "✓ Built $(BUILD_DIR)/$(BINARY)"

## install: Install the binary to GOPATH/bin
install:
	go install $(LDFLAGS) .
	@echo "✓ Installed $(BINARY)"

## test: Run all unit tests
test:
	go test ./... -v -count=1

## test-cover: Run tests with coverage report
test-cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | grep total
	@echo "✓ Coverage report written to coverage.html"

## bench: Run benchmark tests
bench:
	go test ./... -bench=. -benchmem -run='^$$'

## lint: Run go vet and staticcheck
lint:
	go vet ./...
	@which staticcheck > /dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

## fmt: Format all Go source files
fmt:
	gofmt -w .

## tidy: Tidy go.mod and go.sum
tidy:
	go mod tidy

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

## run-sample: Analyze the sample CSV and generate a report
run-sample: build
	$(BUILD_DIR)/$(BINARY) analyze testdata/sample-findings.csv \
		--output reports/sample-report.md \
		--include-remediation \
		--include-compliance \
		--verbose
	@echo "✓ Report written to reports/sample-report.md"

## run-all-formats: Generate reports in all formats from the sample CSV
run-all-formats: build
	@mkdir -p reports
	$(BUILD_DIR)/$(BINARY) analyze testdata/sample-findings.csv \
		--output-dir reports \
		--formats markdown,json,html,csv \
		--include-remediation \
		--include-compliance

## run-fetch: Fetch findings from GCP SCC and analyze (requires ORG_ID env var)
run-fetch: build
	@if [ -z "$(ORG_ID)" ]; then echo "Error: ORG_ID is required. Usage: make run-fetch ORG_ID=123456789"; exit 1; fi
	@mkdir -p reports
	$(BUILD_DIR)/$(BINARY) fetch --org-id $(ORG_ID) \
		--days $(or $(DAYS),7) \
		--output reports/scc-report.md \
		--include-remediation \
		--include-compliance \
		--verbose
	@echo "✓ Report written to reports/scc-report.md"

## stats-sample: Show statistics for the sample CSV
stats-sample: build
	$(BUILD_DIR)/$(BINARY) stats testdata/sample-findings.csv

## help: Show this help
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

## setup-hooks: Install pre-commit security hooks
setup-hooks:
	@cp .github/hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "✓ Pre-commit hook installed. Run 'make setup-hooks' on each clone."

## sast: Run all SAST checks locally (requires gitleaks, semgrep, govulncheck, trivy)
sast:
	@echo "=== Gitleaks ===" && gitleaks detect --config=.gitleaks.toml --verbose || true
	@echo "=== Semgrep ===" && semgrep --config=.semgrep.yml --error . || true
	@echo "=== govulncheck ===" && govulncheck ./... || true
	@echo "=== Trivy (filesystem) ===" && trivy fs --severity HIGH,CRITICAL . || true

## govulncheck: Scan Go dependencies for known CVEs
govulncheck:
	@which govulncheck > /dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

## trivy-fs: Scan the filesystem for vulnerabilities (requires trivy)
trivy-fs:
	@which trivy > /dev/null 2>&1 || (echo "Install trivy: https://aquasecurity.github.io/trivy/"; exit 1)
	trivy fs --severity HIGH,CRITICAL .

## gitleaks: Scan the full repo history for leaked secrets
gitleaks:
	@which gitleaks > /dev/null 2>&1 || (echo "Install gitleaks: https://github.com/gitleaks/gitleaks"; exit 1)
	gitleaks detect --config=.gitleaks.toml --verbose

## semgrep: Run Semgrep static analysis
semgrep:
	@which semgrep > /dev/null 2>&1 || (echo "Install semgrep: pip install semgrep"; exit 1)
	semgrep --config=.semgrep.yml --config=p/golang --severity=ERROR --error .
