package researcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// AuthenticationResearcher tests identity and session mechanisms including
// token tampering (JWT alg none / signature stripping), session invalidation,
// and authentication boundary enforcement.
type AuthenticationResearcher struct {
	httpClient HTTPClient
}

// NewAuthenticationResearcher creates a new authentication researcher.
func NewAuthenticationResearcher(httpClient HTTPClient) *AuthenticationResearcher {
	return &AuthenticationResearcher{httpClient: httpClient}
}

// Type returns domain.ResearcherAuthentication.
func (r *AuthenticationResearcher) Type() domain.ResearcherType {
	return domain.ResearcherAuthentication
}

// Execute tests authentication boundaries and token integrity.
func (r *AuthenticationResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherAuthentication,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	// 1. Analyze provided credentials / tokens
	for credName, token := range brief.Credentials {
		if strings.Count(token, ".") == 2 {
			// JWT Token detected
			r.analyzeAndTestJWT(ctx, credName, token, brief, result, &requestCount)
		}
	}

	// 2. Test unauthenticated access to known protected endpoints
	for _, ep := range brief.KnownEndpoints {
		if requestCount >= brief.MaxRequests {
			break
		}
		// Try unauthenticated request
		ev, err := r.httpClient.Do(ctx, "GET", ep, nil, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Unauthenticated access check on %s", ep)
		result.Evidence = append(result.Evidence, *ev)

		// If endpoint contains sensitive route names and responds with 200 OK without auth
		lower := strings.ToLower(ep)
		if ev.ResponseStatus == 200 && (strings.Contains(lower, "admin") || strings.Contains(lower, "user") || strings.Contains(lower, "account") || strings.Contains(lower, "profile") || strings.Contains(lower, "wallet")) {
			cand := domain.CandidateVulnerability{
				ID:          uuid.New(),
				Type:        "AUTHENTICATION_MISSING_ON_SENSITIVE_ENDPOINT",
				Title:       fmt.Sprintf("Missing Authentication on %s", ep),
				Description: fmt.Sprintf("Endpoint %s returns HTTP 200 OK without requiring authentication credentials.", ep),
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
	result.Summary = fmt.Sprintf("Authentication Research: %d requests made, %d candidate findings discovered",
		requestCount, len(result.CandidateFindings))

	return result, nil
}

func (r *AuthenticationResearcher) analyzeAndTestJWT(ctx context.Context, credName, token string, brief *domain.MissionBrief, result *domain.MissionResult, reqCount *int) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return
	}

	result.Observations = append(result.Observations, domain.MissionObservation{
		Type:        "jwt_token_analyzed",
		Description: fmt.Sprintf("JWT Token [%s] parsed: alg=%v, typ=%v", credName, header["alg"], header["typ"]),
		Details:     map[string]any{"alg": header["alg"], "typ": header["typ"], "cred": credName},
		ObservedAt:  time.Now().UTC(),
	})

	// Test 1: Alg None Attack
	header["alg"] = "none"
	mutatedHeaderJSON, _ := json.Marshal(header)
	tamperedHeader := base64.RawURLEncoding.EncodeToString(mutatedHeaderJSON)
	tamperedNoneToken := tamperedHeader + "." + parts[1] + "."

	// Test against first known endpoint
	if len(brief.KnownEndpoints) > 0 && *reqCount < brief.MaxRequests {
		testEP := brief.KnownEndpoints[0]
		h := map[string]string{"Authorization": "Bearer " + tamperedNoneToken}
		ev, err := r.httpClient.Do(ctx, "GET", testEP, h, "")
		if err == nil {
			*reqCount++
			ev.Description = fmt.Sprintf("JWT Alg None test on %s with %s", testEP, credName)
			result.Evidence = append(result.Evidence, *ev)

			if ev.ResponseStatus == 200 {
				result.CandidateFindings = append(result.CandidateFindings, domain.CandidateVulnerability{
					ID:          uuid.New(),
					Type:        "JWT_ALGORITHM_NONE_ACCEPTED",
					Title:       fmt.Sprintf("JWT Alg None Vulnerability on %s", testEP),
					Description: "Server accepted unsigned JWT token with alg: none header, allowing complete token forgery.",
					Severity:    string(domain.SeverityCritical),
					Endpoint:    testEP,
					DiscoveredAt: time.Now().UTC(),
				})
			}
		}
	}
}
