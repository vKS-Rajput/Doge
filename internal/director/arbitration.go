package director

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ResearchQuestion encapsulates an unanswered security inquiry prioritized by expected utility.
type ResearchQuestion struct {
	ID                    uuid.UUID             `json:"id"`
	Question              string                `json:"question"`
	TargetEndpoint        string                `json:"target_endpoint"`
	RecommendedResearcher domain.ResearcherType `json:"recommended_researcher"`
	ExpectedInfoGain      float64               `json:"expected_info_gain"`
	Novelty               float64               `json:"novelty"`
	SecurityRelevance     float64               `json:"security_relevance"`
	ImpactPotential       float64               `json:"impact_potential"`
	Cost                  float64               `json:"cost"`
	Risk                  float64               `json:"risk"`
	PriorityScore         float64               `json:"priority_score"`
	Rationale             string                `json:"rationale"`
}

// ArbitrationContext provides the full epistemic state needed by the Director
// to calculate expected information gain across candidate missions.
type ArbitrationContext struct {
	TargetBaseURL        string
	Credentials          map[string]string
	Endpoints            []string
	Candidates           []domain.CandidateVulnerability
	Validated            []domain.CandidateVulnerability
	Hypotheses           []domain.MissionHypothesis
	Unknowns             []string
	ContradictionsCount  int
	AvailableResearchers map[domain.ResearcherType]bool
	MissionHistory       []domain.MissionResult
}

// ArbitrateNextQuestion evaluates the complete epistemic state and computes:
// "What is the most valuable security question DOGE should investigate next?"
func (d *Director) ArbitrateNextQuestion(ctx ArbitrationContext) (*ResearchQuestion, *domain.MissionBrief) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var candidateQuestions []*ResearchQuestion

	// 1. Evaluate Candidates Needing Independent Validation
	if len(ctx.Candidates) > 0 && ctx.AvailableResearchers[domain.ResearcherValidation] {
		for _, cand := range ctx.Candidates {
			// Check if already validated or tested in history
			alreadyTested := false
			for _, m := range ctx.MissionHistory {
				if m.ResearcherType == domain.ResearcherValidation && strings.Contains(m.Summary, cand.Title) {
					alreadyTested = true
					break
				}
			}
			if !alreadyTested {
				rq := &ResearchQuestion{
					ID:                    uuid.New(),
					Question:              fmt.Sprintf("Can candidate vulnerability '%s' be independently reproduced with differential control?", cand.Title),
					TargetEndpoint:        cand.Endpoint,
					RecommendedResearcher: domain.ResearcherValidation,
					ExpectedInfoGain:      0.95,
					Novelty:               0.60,
					SecurityRelevance:     0.98,
					ImpactPotential:       0.95,
					Cost:                  0.30,
					Risk:                  0.25,
					Rationale:             "Candidate vulnerability requires independent verification to eliminate false positives before impact evaluation.",
				}
				rq.PriorityScore = computeUtility(rq)
				candidateQuestions = append(candidateQuestions, rq)
			}
		}
	}

	// 2. Evaluate Validated Vulnerabilities Needing Impact Demonstration
	if len(ctx.Validated) > 0 && ctx.AvailableResearchers[domain.ResearcherImpact] {
		for _, val := range ctx.Validated {
			impactRan := false
			for _, m := range ctx.MissionHistory {
				if m.ResearcherType == domain.ResearcherImpact && strings.Contains(m.Summary, val.Title) {
					impactRan = true
					break
				}
			}
			if !impactRan {
				rq := &ResearchQuestion{
					ID:                    uuid.New(),
					Question:              fmt.Sprintf("What is the real-world operational and data impact of validated vulnerability '%s'?", val.Title),
					TargetEndpoint:        val.Endpoint,
					RecommendedResearcher: domain.ResearcherImpact,
					ExpectedInfoGain:      0.92,
					Novelty:               0.50,
					SecurityRelevance:     1.00,
					ImpactPotential:       1.00,
					Cost:                  0.35,
					Risk:                  0.30,
					Rationale:             "Validated finding requires demonstrable proof of impact to complete the 3-tier evidence chain.",
				}
				rq.PriorityScore = computeUtility(rq)
				candidateQuestions = append(candidateQuestions, rq)
			}
		}
	}

	// 3. Evaluate Attack Chain Opportunities
	if (len(ctx.Candidates) > 1 || len(ctx.Validated) > 0) && ctx.AvailableResearchers[domain.ResearcherChain] {
		chainRan := false
		for _, m := range ctx.MissionHistory {
			if m.ResearcherType == domain.ResearcherChain {
				chainRan = true
				break
			}
		}
		if !chainRan {
			rq := &ResearchQuestion{
				ID:                    uuid.New(),
				Question:              "Can existing candidate findings and attack surface nodes be chained into a multi-step escalation path?",
				TargetEndpoint:        ctx.TargetBaseURL,
				RecommendedResearcher: domain.ResearcherChain,
				ExpectedInfoGain:      0.88,
				Novelty:               0.85,
				SecurityRelevance:     0.90,
				ImpactPotential:       0.95,
				Cost:                  0.20,
				Risk:                  0.15,
				Rationale:             "Multiple isolated security conditions exist that may compose into a composite attack chain via attack graph traversal.",
			}
			rq.PriorityScore = computeUtility(rq)
			candidateQuestions = append(candidateQuestions, rq)
		}
	}

	// 4. Evaluate Contradictions / Novel Anomaly Exploration
	if ctx.ContradictionsCount > 0 && ctx.AvailableResearchers[domain.ResearcherAnomaly] {
		rq := &ResearchQuestion{
			ID:                    uuid.New(),
			Question:              "What hidden state, cache artifact, or race condition explains observed observation contradictions?",
			TargetEndpoint:        ctx.TargetBaseURL,
			RecommendedResearcher: domain.ResearcherAnomaly,
			ExpectedInfoGain:      0.90,
			Novelty:               0.92,
			SecurityRelevance:     0.85,
			ImpactPotential:       0.80,
			Cost:                  0.40,
			Risk:                  0.20,
			Rationale:             "Detected conflicting observations indicate unmodeled security boundaries or latent race/cache behavior.",
		}
		rq.PriorityScore = computeUtility(rq)
		candidateQuestions = append(candidateQuestions, rq)
	}

	// 5. Evaluate Specific Endpoint Surface Characteristics
	for _, ep := range ctx.Endpoints {
		low := strings.ToLower(ep)

		// Race condition candidate
		if (strings.Contains(low, "transfer") || strings.Contains(low, "wallet") || strings.Contains(low, "redeem") || strings.Contains(low, "calibrate")) && ctx.AvailableResearchers[domain.ResearcherRace] {
			if !hasTestedTool(ctx.MissionHistory, domain.ResearcherRace, ep) {
				rq := &ResearchQuestion{
					ID:                    uuid.New(),
					Question:              fmt.Sprintf("Does %s expose a latent concurrency window allowing double-spend or limit overdraw?", ep),
					TargetEndpoint:        ep,
					RecommendedResearcher: domain.ResearcherRace,
					ExpectedInfoGain:      0.85,
					Novelty:               0.80,
					SecurityRelevance:     0.90,
					ImpactPotential:       0.90,
					Cost:                  0.30,
					Risk:                  0.25,
					Rationale:             "Transactional endpoint identified without verified atomic transaction locking.",
				}
				rq.PriorityScore = computeUtility(rq)
				candidateQuestions = append(candidateQuestions, rq)
			}
		}

		// Cache bleed candidate
		if (strings.Contains(low, "cache") || strings.Contains(low, "report") || strings.Contains(low, "static")) && ctx.AvailableResearchers[domain.ResearcherCache] {
			if !hasTestedTool(ctx.MissionHistory, domain.ResearcherCache, ep) {
				rq := &ResearchQuestion{
					ID:                    uuid.New(),
					Question:              fmt.Sprintf("Does %s suffer from cache-key normalization collision or unkeyed header poisoning?", ep),
					TargetEndpoint:        ep,
					RecommendedResearcher: domain.ResearcherCache,
					ExpectedInfoGain:      0.82,
					Novelty:               0.78,
					SecurityRelevance:     0.85,
					ImpactPotential:       0.80,
					Cost:                  0.25,
					Risk:                  0.15,
					Rationale:             "Cached endpoint may bleed cross-tenant data under canonical path permutations.",
				}
				rq.PriorityScore = computeUtility(rq)
				candidateQuestions = append(candidateQuestions, rq)
			}
		}

		// Batch / Metamorphic candidate
		if (strings.Contains(low, "batch") || strings.Contains(low, "bulk") || strings.Contains(low, "pipe")) && ctx.AvailableResearchers[domain.ResearcherMetamorphic] {
			if !hasTestedTool(ctx.MissionHistory, domain.ResearcherMetamorphic, ep) {
				rq := &ResearchQuestion{
					ID:                    uuid.New(),
					Question:              fmt.Sprintf("Does batch pipeline on %s violate order invariance or context isolation across sub-operations?", ep),
					TargetEndpoint:        ep,
					RecommendedResearcher: domain.ResearcherMetamorphic,
					ExpectedInfoGain:      0.90,
					Novelty:               0.88,
					SecurityRelevance:     0.92,
					ImpactPotential:       0.95,
					Cost:                  0.35,
					Risk:                  0.20,
					Rationale:             "Batch execution frames frequently fail to re-initialize security context across piped operations.",
				}
				rq.PriorityScore = computeUtility(rq)
				candidateQuestions = append(candidateQuestions, rq)
			}
		}
	}

	// 6. Fallback: Attack Surface Reconnaissance
	if len(candidateQuestions) == 0 {
		if ctx.AvailableResearchers[domain.ResearcherAPI] && len(ctx.Endpoints) < 5 {
			rq := &ResearchQuestion{
				ID:                    uuid.New(),
				Question:              "What hidden API documentation schemas and HTTP method capabilities exist?",
				TargetEndpoint:        ctx.TargetBaseURL,
				RecommendedResearcher: domain.ResearcherAPI,
				ExpectedInfoGain:      0.75,
				Novelty:               0.70,
				SecurityRelevance:     0.75,
				ImpactPotential:       0.60,
				Cost:                  0.20,
				Risk:                  0.10,
				Rationale:             "Broadening known attack surface and API schema contracts.",
			}
			rq.PriorityScore = computeUtility(rq)
			candidateQuestions = append(candidateQuestions, rq)
		} else {
			rq := &ResearchQuestion{
				ID:                    uuid.New(),
				Question:              "What endpoints, authentication mechanisms, and object patterns are exposed on the target?",
				TargetEndpoint:        ctx.TargetBaseURL,
				RecommendedResearcher: domain.ResearcherRecon,
				ExpectedInfoGain:      0.70,
				Novelty:               0.65,
				SecurityRelevance:     0.70,
				ImpactPotential:       0.50,
				Cost:                  0.15,
				Risk:                  0.05,
				Rationale:             "Initial baseline mapping of target topology.",
			}
			rq.PriorityScore = computeUtility(rq)
			candidateQuestions = append(candidateQuestions, rq)
		}
	}

	// Sort by highest expected utility (Value)
	sort.Slice(candidateQuestions, func(i, j int) bool {
		return candidateQuestions[i].PriorityScore > candidateQuestions[j].PriorityScore
	})

	topQuestion := candidateQuestions[0]

	brief := &domain.MissionBrief{
		ID:             uuid.New(),
		ResearcherType: topQuestion.RecommendedResearcher,
		Title:          topQuestion.Question,
		Description:    topQuestion.Rationale,
		TargetBaseURL:  ctx.TargetBaseURL,
		Credentials:    ctx.Credentials,
		KnownEndpoints: ctx.Endpoints,
		MaxRequests:    50,
		MaxDuration:    60 * time.Second,
		SuccessCriteria: fmt.Sprintf("Utility Score: %.2f | InfoGain: %.2f | Impact: %.2f",
			topQuestion.PriorityScore, topQuestion.ExpectedInfoGain, topQuestion.ImpactPotential),
		CreatedAt: time.Now().UTC(),
	}

	return topQuestion, brief
}

// ComputeUtility implements Section 13 scoring:
// VALUE = InfoGain + Novelty + SecurityRelevance + ImpactPotential - Cost - Risk
func ComputeUtility(rq *ResearchQuestion) float64 {
	val := (rq.ExpectedInfoGain * 0.30) +
		(rq.Novelty * 0.20) +
		(rq.SecurityRelevance * 0.25) +
		(rq.ImpactPotential * 0.25) -
		(rq.Cost * 0.10) -
		(rq.Risk * 0.10)
	if val < 0 {
		return 0
	}
	return val
}

func computeUtility(rq *ResearchQuestion) float64 {
	return ComputeUtility(rq)
}

func hasTestedTool(history []domain.MissionResult, rType domain.ResearcherType, endpoint string) bool {
	for _, m := range history {
		if m.ResearcherType == rType {
			for _, ep := range m.Endpoints {
				if ep == endpoint {
					return true
				}
			}
		}
	}
	return false
}
