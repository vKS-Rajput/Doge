package researcher

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// DifferentialResearcher performs synchronized multi-principal matrix experiments
// (Anonymous vs User A vs User B vs Admin) across endpoints to uncover state,
// authorization, and response discrepancies.
type DifferentialResearcher struct {
	httpClient HTTPClient
}

// NewDifferentialResearcher creates a new differential researcher.
func NewDifferentialResearcher(httpClient HTTPClient) *DifferentialResearcher {
	return &DifferentialResearcher{httpClient: httpClient}
}

// Type returns domain.ResearcherDifferential.
func (r *DifferentialResearcher) Type() domain.ResearcherType {
	return domain.ResearcherDifferential
}

// PrincipalExecution records one probe under a specific identity.
type PrincipalExecution struct {
	PrincipalName  string
	StatusCode     int
	BodyLength     int
	ParsedJSONKeys []string
	Evidence       domain.ExperimentEvidence
}

// Execute runs differential testing across all identities and target endpoints.
func (r *DifferentialResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherDifferential,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	// Build principal set: Anonymous + all provided credentials
	principals := make(map[string]map[string]string)
	principals["anonymous"] = nil
	for credName, token := range brief.Credentials {
		principals[credName] = map[string]string{"Authorization": "Bearer " + token}
	}

	for _, ep := range brief.KnownEndpoints {
		if requestCount >= brief.MaxRequests {
			break
		}

		matrix := make(map[string]PrincipalExecution)

		for pName, headers := range principals {
			if requestCount >= brief.MaxRequests {
				break
			}
			ev, err := r.httpClient.Do(ctx, "GET", ep, headers, "")
			if err != nil {
				continue
			}
			requestCount++
			ev.Description = fmt.Sprintf("Differential probe [%s] on %s", pName, ep)
			result.Evidence = append(result.Evidence, *ev)

			pe := PrincipalExecution{
				PrincipalName: pName,
				StatusCode:    ev.ResponseStatus,
				BodyLength:    len(ev.ResponseBody),
				Evidence:      *ev,
			}

			var data map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &data); err == nil {
				for k := range data {
					pe.ParsedJSONKeys = append(pe.ParsedJSONKeys, k)
				}
			}
			matrix[pName] = pe
		}

		// Analyze matrix for anomalies
		r.analyzeDiscrepancies(ep, matrix, result)
	}

	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.Status = domain.MissionCompleted
	result.Summary = fmt.Sprintf("Differential Research: %d requests made across %d endpoints and %d principals, %d candidate findings discovered",
		requestCount, len(brief.KnownEndpoints), len(principals), len(result.CandidateFindings))

	return result, nil
}

func (r *DifferentialResearcher) analyzeDiscrepancies(endpoint string, matrix map[string]PrincipalExecution, result *domain.MissionResult) {
	anon, hasAnon := matrix["anonymous"]

	// Check 1: Sensitive data leaked to Anonymous identical to Authenticated User
	for pName, authExec := range matrix {
		if pName == "anonymous" {
			continue
		}
		if hasAnon && anon.StatusCode == 200 && authExec.StatusCode == 200 {
			if anon.BodyLength > 100 && abs(anon.BodyLength-authExec.BodyLength) < 10 {
				cand := domain.CandidateVulnerability{
					ID:          uuid.New(),
					Type:        "DIFFERENTIAL_UNAUTHENTICATED_DATA_EXPOSURE",
					Title:       fmt.Sprintf("Differential Exposure: Anonymous Access Matches Authenticated Response on %s", endpoint),
					Description: fmt.Sprintf("Endpoint %s returns identical status (200) and payload length for anonymous as authenticated principal %s.", endpoint, pName),
					Severity:    string(domain.SeverityMedium),
					Endpoint:    endpoint,
					DiscoveredAt: time.Now().UTC(),
				}
				result.CandidateFindings = append(result.CandidateFindings, cand)
			}
		}

		// Check 2: Cross-Principal Horizontal Variance (User A vs User B)
		for otherName, otherExec := range matrix {
			if otherName == "anonymous" || otherName == pName {
				continue
			}
			// Both 200 OK but different keys leaked or identical sensitive data
			if authExec.StatusCode == 200 && otherExec.StatusCode == 200 {
				if len(authExec.ParsedJSONKeys) > 0 && len(otherExec.ParsedJSONKeys) > 0 {
					if !reflect.DeepEqual(authExec.ParsedJSONKeys, otherExec.ParsedJSONKeys) {
						result.Observations = append(result.Observations, domain.MissionObservation{
							Type:        "differential_schema_variance",
							Description: fmt.Sprintf("Schema variance between %s and %s on %s", pName, otherName, endpoint),
							Endpoint:    endpoint,
							Details:     map[string]any{"keys_a": authExec.ParsedJSONKeys, "keys_b": otherExec.ParsedJSONKeys},
							ObservedAt:  time.Now().UTC(),
						})
					}
				}
			}
		}
	}
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
