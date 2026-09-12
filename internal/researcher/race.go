package researcher

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// RaceResearcher executes concurrent burst requests to detect latent race windows,
// TOCTOU (Time-of-Check to Time-of-Use) discrepancies, and limit overdraw vulnerabilities.
type RaceResearcher struct {
	httpClient HTTPClient
}

// NewRaceResearcher creates a new race researcher.
func NewRaceResearcher(httpClient HTTPClient) *RaceResearcher {
	return &RaceResearcher{httpClient: httpClient}
}

// Type returns domain.ResearcherRace.
func (r *RaceResearcher) Type() domain.ResearcherType {
	return domain.ResearcherRace
}

// Execute performs high-concurrency burst testing against candidate transactional endpoints.
func (r *RaceResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherRace,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	authHeaders := make(map[string]string)
	for _, token := range brief.Credentials {
		authHeaders["Authorization"] = "Bearer " + token
		authHeaders["Content-Type"] = "application/json"
		break
	}

	// Identify transactional / state-changing endpoints
	candidateEndpoints := make([]string, 0)
	for _, ep := range brief.KnownEndpoints {
		low := strings.ToLower(ep)
		if strings.Contains(low, "transfer") || strings.Contains(low, "wallet") ||
			strings.Contains(low, "redeem") || strings.Contains(low, "coupon") ||
			strings.Contains(low, "checkout") || strings.Contains(low, "vote") ||
			strings.Contains(low, "calibrate") || strings.Contains(low, "order") {
			candidateEndpoints = append(candidateEndpoints, ep)
		}
	}

	if len(candidateEndpoints) == 0 {
		candidateEndpoints = brief.KnownEndpoints
	}

	burstSize := 5
	for _, ep := range candidateEndpoints {
		if requestCount+burstSize > brief.MaxRequests {
			break
		}

		// Execute synchronized concurrent burst
		var wg sync.WaitGroup
		evidenceChan := make(chan *domain.ExperimentEvidence, burstSize)
		startBarrier := make(chan struct{})

		for i := 0; i < burstSize; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-startBarrier // Synchronize release
				body := `{"amount": 10, "units": 5, "action": "transfer"}`
				ev, err := r.httpClient.Do(ctx, "POST", ep, authHeaders, body)
				if err == nil {
					ev.Description = fmt.Sprintf("Concurrent race burst request %d on %s", idx+1, ep)
					evidenceChan <- ev
				}
			}(i)
		}

		close(startBarrier) // Release all concurrent requests simultaneously
		wg.Wait()
		close(evidenceChan)

		successCount := 0
		var burstResponses []int
		for ev := range evidenceChan {
			requestCount++
			result.Evidence = append(result.Evidence, *ev)
			burstResponses = append(burstResponses, ev.ResponseStatus)
			if ev.ResponseStatus >= 200 && ev.ResponseStatus < 300 {
				successCount++
			}
		}

		// If multiple concurrent requests succeeded where only one should have been permitted
		if successCount > 1 {
			cand := domain.CandidateVulnerability{
				ID:          uuid.New(),
				Type:        "LATENT_CONCURRENCY_RACE_WINDOW",
				Title:       fmt.Sprintf("Latent Race Condition Window on %s", ep),
				Description: fmt.Sprintf("Synchronized concurrent burst of %d requests produced %d successful responses (Codes: %v), indicating lack of transaction isolation or atomic locking.", burstSize, successCount, burstResponses),
				Severity:    string(domain.SeverityHigh),
				Endpoint:    ep,
				DiscoveredAt: time.Now().UTC(),
			}
			result.CandidateFindings = append(result.CandidateFindings, cand)
		}
	}

	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.Status = domain.MissionCompleted
	result.Summary = fmt.Sprintf("Race Condition Research: %d concurrent requests made across %d target endpoints, %d candidate findings discovered",
		requestCount, len(candidateEndpoints), len(result.CandidateFindings))

	return result, nil
}
