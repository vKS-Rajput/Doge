package researcher

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// CacheResearcher investigates cache key normalization discrepancies, unkeyed headers,
// and reverse-proxy cache poisoning / context bleed vulnerabilities.
type CacheResearcher struct {
	httpClient HTTPClient
}

// NewCacheResearcher creates a new cache researcher.
func NewCacheResearcher(httpClient HTTPClient) *CacheResearcher {
	return &CacheResearcher{httpClient: httpClient}
}

// Type returns domain.ResearcherCache.
func (r *CacheResearcher) Type() domain.ResearcherType {
	return domain.ResearcherCache
}

// Execute performs cache-key normalization and unkeyed header experiments.
func (r *CacheResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherCache,
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

		// Probe 1: Baseline Request
		evBase, err := r.httpClient.Do(ctx, "GET", ep, authHeaders, "")
		if err != nil {
			continue
		}
		requestCount++
		evBase.Description = fmt.Sprintf("Cache baseline probe on %s", ep)
		result.Evidence = append(result.Evidence, *evBase)

		// Probe 2: Unkeyed Header Injection
		unkeyedHeaders := []struct {
			name  string
			value string
		}{
			{"X-Forwarded-Host", "attacker-canary.doge.local"},
			{"X-Original-URL", "/admin/unauthorized_cache_probe"},
			{"X-Rewrite-URL", "/internal/metrics"},
		}

		for _, uh := range unkeyedHeaders {
			if requestCount >= brief.MaxRequests {
				break
			}
			h := make(map[string]string)
			for k, v := range authHeaders {
				h[k] = v
			}
			h[uh.name] = uh.value

			evH, err := r.httpClient.Do(ctx, "GET", ep, h, "")
			if err != nil {
				continue
			}
			requestCount++
			evH.Description = fmt.Sprintf("Cache unkeyed header [%s: %s] on %s", uh.name, uh.value, ep)
			result.Evidence = append(result.Evidence, *evH)

			// If canary reflected or redirect altered
			if strings.Contains(evH.ResponseBody, uh.value) {
				cand := domain.CandidateVulnerability{
					ID:          uuid.New(),
					Type:        "CACHE_POISONING_UNKEYED_HEADER_REFLECTION",
					Title:       fmt.Sprintf("Cache Poisoning via Unkeyed Header %s on %s", uh.name, ep),
					Description: fmt.Sprintf("Endpoint %s reflects unkeyed header %s into response body. If response is cached, all users receive poisoned payload.", ep, uh.name),
					Severity:    string(domain.SeverityHigh),
					Endpoint:    ep,
					DiscoveredAt: time.Now().UTC(),
				}
				result.CandidateFindings = append(result.CandidateFindings, cand)
			}
		}

		// Probe 3: Path Normalization / Canonicalization Collision
		if strings.Contains(ep, "/") {
			mutatedPath := ep + "/%2e%2e/" + ep[strings.LastIndex(ep, "/")+1:]
			evNorm, err := r.httpClient.Do(ctx, "GET", mutatedPath, authHeaders, "")
			if err == nil {
				requestCount++
				evNorm.Description = fmt.Sprintf("Cache normalization collision probe on %s", mutatedPath)
				result.Evidence = append(result.Evidence, *evNorm)

				if evNorm.ResponseStatus == 200 && strings.Contains(evNorm.ResponseBody, "cache") {
					result.Observations = append(result.Observations, domain.MissionObservation{
						Type:        "cache_normalization_divergence",
						Description: fmt.Sprintf("Path normalization collision on %s returned 200 OK", mutatedPath),
						Endpoint:    mutatedPath,
						Details:     map[string]any{"response": evNorm.ResponseBody},
						ObservedAt:  time.Now().UTC(),
					})
				}
			}
		}
	}

	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.Status = domain.MissionCompleted
	result.Summary = fmt.Sprintf("Cache Research: %d requests made across %d endpoints, %d candidate findings discovered",
		requestCount, len(brief.KnownEndpoints), len(result.CandidateFindings))

	return result, nil
}
