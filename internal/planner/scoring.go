package planner

import (
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
)

// LearningFeedbackProvider defines an interface for querying learned pattern weights and penalties.
type LearningFeedbackProvider interface {
	GetPatternPriorityBoost(patternName string) float64
	GetToolEffectiveness(tool string) float64
}

// ActionScoreBreakdown details the quantitative factors contributing to an action's priority.
type ActionScoreBreakdown struct {
	Confidence             float64 `json:"confidence"`
	PotentialImpact        float64 `json:"potential_impact"`
	EvidenceRelevance      float64 `json:"evidence_relevance"`
	ExpectedInfoGain       float64 `json:"expected_info_gain"`
	Novelty                float64 `json:"novelty"`
	Cost                   float64 `json:"cost"`
	RiskFactor             float64 `json:"risk_factor"`
	LearningBoost          float64 `json:"learning_boost"`
	CompositePriorityScore float64 `json:"composite_priority_score"`
}

// CalculateActionPriority computes the multi-factor Information Gain score for a candidate action.
// Formula:
// Priority = (Confidence * Impact * Relevance * ExpectedInfoGain * Novelty) / (Cost * Risk) * Multiplier + LearningBoost
func CalculateActionPriority(
	action *ResearchAction,
	hyp *hypothesis.ResearchHypothesis,
	feedback LearningFeedbackProvider,
) (float64, ActionScoreBreakdown) {
	breakdown := ActionScoreBreakdown{
		Confidence:        0.50, // baseline exploration confidence
		PotentialImpact:   0.50,
		EvidenceRelevance: 0.50,
		ExpectedInfoGain:  0.60,
		Novelty:           0.50,
		Cost:              1.0,
		RiskFactor:        1.0,
		LearningBoost:     0.0,
	}

	hypothesisMultiplier := 1.0

	// 1. Cost & Risk Factors
	switch action.Risk {
	case RiskPassive:
		breakdown.Cost = 1.0
		breakdown.RiskFactor = 1.0
	case RiskLow:
		breakdown.Cost = 1.1
		breakdown.RiskFactor = 1.1
	case RiskMedium:
		breakdown.Cost = 1.2
		breakdown.RiskFactor = 1.2
	case RiskHigh:
		breakdown.Cost = 1.5
		breakdown.RiskFactor = 1.5
	case RiskCritical:
		breakdown.Cost = 2.5
		breakdown.RiskFactor = 2.0
	}

	// 2. Hypothesis-Linked Scoring
	if hyp != nil {
		hypothesisMultiplier = 3.5 // Concrete hypothesis validation has high priority over generic recon
		breakdown.Confidence = hyp.Confidence
		breakdown.EvidenceRelevance = 0.6 + float64(len(hyp.SupportingEvidence))*0.1
		if breakdown.EvidenceRelevance > 1.0 {
			breakdown.EvidenceRelevance = 1.0
		}

		// Impact based on hypothesis category
		switch hyp.Category {
		case hypothesis.CatBOLA, hypothesis.CatAuthBoundary, hypothesis.CatPrivilegeEsc, hypothesis.CatSSRF:
			breakdown.PotentialImpact = 0.95
		case hypothesis.CatInjection, hypothesis.CatNovelAnomaly:
			breakdown.PotentialImpact = 0.80
		case hypothesis.CatCORS, hypothesis.CatMassAssignment:
			breakdown.PotentialImpact = 0.65
		case hypothesis.CatInformationLeak, hypothesis.CatRateLimitAnomaly:
			breakdown.PotentialImpact = 0.45
		default:
			breakdown.PotentialImpact = 0.50
		}

		// Expected Information Gain: High if unvalidated / plausible, lower if already evaluated multiple times
		switch hyp.Status {
		case hypothesis.StatusUnvalidated:
			breakdown.ExpectedInfoGain = 0.95
		case hypothesis.StatusPlausible:
			breakdown.ExpectedInfoGain = 0.85
		case hypothesis.StatusSupported:
			breakdown.ExpectedInfoGain = 0.75 // Verification still valuable
		case hypothesis.StatusContradicted:
			breakdown.ExpectedInfoGain = 0.20 // Penalized
		case hypothesis.StatusRejected:
			breakdown.ExpectedInfoGain = 0.01 // Severe penalty for refuted theories
		case hypothesis.StatusConfirmed:
			breakdown.ExpectedInfoGain = 0.05 // Already proven, move on to new surfaces
		default:
			breakdown.ExpectedInfoGain = 0.50
		}

		if hyp.EvaluationCount > 3 && hyp.Status != hypothesis.StatusConfirmed {
			breakdown.ExpectedInfoGain *= 0.5 // Diminishing returns on repeated probing
		}
	} else {
		// Tool-specific exploration heuristics
		switch action.Tool {
		case "subfinder", "assetfinder", "amass":
			breakdown.PotentialImpact = 0.40
			breakdown.ExpectedInfoGain = 0.50
			breakdown.Novelty = 0.50
		case "httpx", "whatweb":
			breakdown.PotentialImpact = 0.45
			breakdown.ExpectedInfoGain = 0.60
		case "katana", "hakrawler", "gau":
			breakdown.PotentialImpact = 0.55
			breakdown.ExpectedInfoGain = 0.65
		case "ffuf", "feroxbuster":
			breakdown.PotentialImpact = 0.50
			breakdown.ExpectedInfoGain = 0.55
		default:
			breakdown.ExpectedInfoGain = 0.40
		}
	}

	// 3. Learning Feedback Boost / Penalty
	if feedback != nil {
		// Check tool effectiveness
		toolEff := feedback.GetToolEffectiveness(action.Tool)
		breakdown.LearningBoost += toolEff

		// If linked to hypothesis or target pattern, check pattern boost
		if hyp != nil {
			patName := strings.ToLower(string(hyp.Category))
			patBoost := feedback.GetPatternPriorityBoost(patName)
			breakdown.LearningBoost += patBoost
		}
	}

	// Numerator: expected epistemic reward
	numerator := breakdown.Confidence * breakdown.PotentialImpact * breakdown.EvidenceRelevance * breakdown.ExpectedInfoGain * breakdown.Novelty

	// Denominator: resource cost and risk
	denominator := breakdown.Cost * breakdown.RiskFactor
	if denominator <= 0 {
		denominator = 1.0
	}

	rawScore := (numerator / denominator) * 10.0 * hypothesisMultiplier
	composite := rawScore + breakdown.LearningBoost

	if composite < 0 {
		composite = 0.0
	}

	breakdown.CompositePriorityScore = composite
	return composite, breakdown
}

// RankActions sorts candidate actions in descending order of their Information Gain priority.
func RankActions(
	actions []*ResearchAction,
	hyps []*hypothesis.ResearchHypothesis,
	feedback LearningFeedbackProvider,
) []*ResearchAction {
	hypMap := make(map[uuid.UUID]*hypothesis.ResearchHypothesis)
	for _, h := range hyps {
		hypMap[h.ID] = h
	}

	type scoredAction struct {
		action *ResearchAction
		score  float64
	}

	scored := make([]scoredAction, len(actions))
	for i, a := range actions {
		var h *hypothesis.ResearchHypothesis
		if a.HypothesisID != nil {
			h = hypMap[*a.HypothesisID]
		}
		score, breakdown := CalculateActionPriority(a, h, feedback)
		a.PriorityScore = score
		a.ScoreBreakdown = &breakdown
		scored[i] = scoredAction{action: a, score: score}
	}

	// Sort descending by score
	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	result := make([]*ResearchAction, len(actions))
	for i, s := range scored {
		result[i] = s.action
	}

	return result
}
