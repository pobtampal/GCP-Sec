package fetcher

import (
	"context"
	"fmt"
	"time"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/api/iterator"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
)

// Fetcher retrieves findings from the GCP Security Command Center API.
type Fetcher struct {
	orgID  string
	logger *utils.Logger
}

// NewFetcher creates a new Fetcher for the given organization ID.
func NewFetcher(orgID string, logger *utils.Logger) *Fetcher {
	if logger == nil {
		logger = utils.DefaultLogger
	}
	return &Fetcher{orgID: orgID, logger: logger}
}

// FetchFindings retrieves ACTIVE findings from the last `days` days.
// It handles pagination automatically via the iterator.
func (f *Fetcher) FetchFindings(ctx context.Context, days int) ([]*models.Finding, error) {
	f.logger.Info("Connecting to GCP Security Command Center API...")

	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create SCC client (run 'gcloud auth application-default login' if not authenticated): %w", err)
	}
	defer client.Close()

	// Build the time filter for the lookback window.
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	filter := fmt.Sprintf("state=\"ACTIVE\" AND event_time >= \"%s\"", cutoff)

	parent := fmt.Sprintf("organizations/%s/sources/-", f.orgID)
	f.logger.Info("Fetching ACTIVE findings from last %d days (org: %s)...", days, f.orgID)
	f.logger.Debug("Parent: %s", parent)
	f.logger.Debug("Filter: %s", filter)

	req := &securitycenterpb.ListFindingsRequest{
		Parent:   parent,
		Filter:   filter,
		PageSize: 1000,
	}

	it := client.ListFindings(ctx, req)

	var findings []*models.Finding
	count := 0

	for {
		result, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return findings, fmt.Errorf("error fetching findings (fetched %d so far): %w", count, err)
		}

		finding := ConvertFinding(result)
		findings = append(findings, finding)
		count++

		if count%500 == 0 {
			f.logger.Info("Fetched %d findings so far...", count)
		}
	}

	f.logger.Info("Fetch complete: %d findings retrieved", count)
	return findings, nil
}
