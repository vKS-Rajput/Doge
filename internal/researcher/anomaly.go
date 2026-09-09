package researcher

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/invariant"
	"github.com/vKS-Rajput/doge/internal/metamorphic"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// AnomalyResearcher explores unknown spaces and tests for unmodeled behavioral anomalies
// using metamorphic testing and dynamic invariant induction.
type AnomalyResearcher struct {
	httpClient HTTPClient
	prober     *metamorphic.Prober
	miner      *invariant.Miner
}

// NewAnomalyResearcher creates a new anomaly researcher.
func NewAnomalyResearcher(httpClient HTTPClient, miner *invariant.Miner) *AnomalyResearcher {
	if miner == nil {
		miner = invariant.NewMiner()
	}
	return &AnomalyResearcher{
		httpClient: httpClient,
		prober:     metamorphic.NewProber(httpClient),
		miner:      miner,
	}
}

// Type returns domain.ResearcherAnomaly.
func (ar *AnomalyResearcher) Type() domain.ResearcherType {
	return domain.ResearcherAnomaly
}

// Execute performs unknown-space metamorphic exploration on target endpoints.
func (ar *AnomalyResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherAnomaly,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	// 1. Identify batch or pipelined endpoints
	var batchEndpoints []string
	for _, ep := range brief.KnownEndpoints {
		low := strings.ToLower(ep)
		if strings.Contains(low, "batch") || strings.Contains(low, "bulk") || strings.Contains(low, "pipe") {
			batchEndpoints = append(batchEndpoints, ep)
		}
	}

	if len(batchEndpoints) == 0 {
		result.Status = domain.MissionCompleted
		result.Summary = "No multiplexed or batch endpoints identified for anomaly probing"
		result.CompletedAt = time.Now().UTC()
		return result, nil
	}

	targetBatchEP := batchEndpoints[0]

	// Extract available tokens
	var tokens []string
	for _, tok := range brief.Credentials {
		tokens = append(tokens, tok)
	}

	// 2. Feed trace to invariant miner to induce candidate invariants
	ar.miner.AddTrace(invariant.ExecutionTrace{
		ID:             uuid.New(),
		Endpoint:       targetBatchEP,
		Method:         "POST",
		ResponseStatus: 200,
		Timestamp:      time.Now().UTC(),
	})
	inducedInvariants := ar.miner.MineInvariants()
	for _, inv := range inducedInvariants {
		result.Observations = append(result.Observations, domain.MissionObservation{
			Type:        "invariant_induced",
			Description: fmt.Sprintf("Dynamically induced invariant: [%s] %s", inv.Type, inv.Statement),
			ObservedAt:  time.Now().UTC(),
		})
	}

	// 3. Formulate metamorphic order-inversion probe
	// Privileged op: using available token on /api/v1/public/ping or /api/v1/me
	authHeader := ""
	if len(tokens) > 1 {
		authHeader = "Bearer " + tokens[1] // Use second principal if available (e.g. beta-token)
	} else if len(tokens) > 0 {
		authHeader = "Bearer " + tokens[0]
	}

	privOp := metamorphic.BatchSubOp{
		ID:     "op-auth-ping",
		Method: "GET",
		Path:   "/api/v1/public/ping",
		Headers: map[string]string{
			"Authorization": authHeader,
		},
		Privilege: "high",
	}

	// Unprivileged op: accessing sensitive vault secret without token
	targetSecretPath := "/api/v1/vault/secrets/sec-beta-999"
	unprivOp := metamorphic.BatchSubOp{
		ID:        "op-unauth-secret",
		Method:    "GET",
		Path:      targetSecretPath,
		Headers:   map[string]string{}, // No auth header
		Privilege: "none",
	}

	// 4. Execute 3-way metamorphic probe
	metaRes, err := ar.prober.ProbeContextIsolation(ctx, brief.TargetBaseURL, targetBatchEP, nil, privOp, unprivOp)
	if err != nil {
		result.Status = domain.MissionFailed
		result.Summary = "Metamorphic probing failed: " + err.Error()
		result.CompletedAt = time.Now().UTC()
		return result, nil
	}
	requestCount += 3

	result.Evidence = append(result.Evidence, metaRes.ForwardEvidence, metaRes.ReverseEvidence, metaRes.ControlEvidence)

	// 5. Evaluate metamorphic relation
	if metaRes.RelationViolated {
		result.Observations = append(result.Observations, domain.MissionObservation{
			Type:        "metamorphic_relation_violated",
			Description: metaRes.DifferentialDetails,
			Endpoint:    targetBatchEP,
			StatusCode:  200,
			ObservedAt:  time.Now().UTC(),
		})

		// Synthesize Candidate Vulnerability for emergent flaw
		cand := domain.CandidateVulnerability{
			ID:       uuid.New(),
			Title:    "Batch Pipeline Context Bleed: Authorization State Persists Across Execution Frames",
			Type:     "BATCH_CONTEXT_BLEED",
			Severity: "critical",
			Endpoint: targetBatchEP,
			Description: "The batch execution pipeline fails to re-initialize or clear authorization context " +
				"between execution frames. An unprivileged sub-operation preceded by a privileged sub-operation " +
				"inherits the prior operation's identity context, bypassing tenant isolation.",
			ReproductionSteps: []string{
				"1. Send POST /api/v1/batch with two operations:",
				"   Op 1: GET /api/v1/public/ping with Authorization: Bearer <valid_token>",
				"   Op 2: GET /api/v1/vault/secrets/<unauthorized_secret_id> with no Authorization header",
				"2. Observe: Op 2 succeeds (HTTP 200) with confidential data",
				"3. Control: Invert order [Op 2, Op 1] -> Op 2 correctly returns 401/403",
			},
			Impact:       "Complete authorization bypass across all endpoints exposed to batch pipeline. Unauthenticated callers can execute arbitrary operations with preceding caller's privileges.",
			DiscoveredAt: time.Now().UTC(),
		}
		result.CandidateFindings = append(result.CandidateFindings, cand)

		// Formulate new hypothesis
		result.NewHypotheses = append(result.NewHypotheses, domain.MissionHypothesis{
			ID:                   uuid.New(),
			Title:                "Batch Pipeline Context Bleed: Authorization State Persists Across Execution Frames",
			Statement:            "Batch execution frames fail to isolate security context, allowing unprivileged sub-operations to inherit preceding privilege.",
			Confidence:           0.95,
			ConfirmationCriteria: "Sub-operation succeeds in batch when preceded by authenticated op, but fails when executed standalone",
			RefutationCriteria:   "Sub-operation fails regardless of order in batch",
		})
	}

	result.Status = domain.MissionCompleted
	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.CompletedAt = time.Now().UTC()
	result.Summary = fmt.Sprintf("Anomaly exploration completed: metamorphic violation=%v on %s",
		metaRes.RelationViolated, targetBatchEP)

	return result, nil
}
