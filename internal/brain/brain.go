// Package brain implements the DOGE Research Brain — the intelligence
// layer that decides where investigation attention is most valuable.
//
// The Brain is a PRIORITIZATION ENGINE, not an executor.
//
// It consumes:
//   - Observations (what the tools found)
//   - Correlations (what connects)
//   - Attack surface (what's exposed)
//   - Novelty signals (what's unusual)
//   - Opportunities (what could be investigated)
//   - Investigation history (what's already been done)
//
// It produces:
//   - ResearchRecommendation objects, ranked by score
//
// The Brain NEVER:
//   - Executes tools
//   - Constructs shell commands
//   - Bypasses scheduler policy
//   - Approves validation
//   - Creates findings
//   - Calls any executor, runner, or process function
//
// Architecture:
//
//	Evidence → Brain.Prioritize() → []ResearchRecommendation
//	                                       │
//	                                       ↓
//	                                  Scheduler
//	                                       │
//	                                       ↓
//	                                  Deterministic job
//
// The Brain has two layers:
//
//	Layer 1: Deterministic scoring (always works, no LLM)
//	Layer 2: Optional LLM explanation (enriches, never decides)
package brain

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/novelty"
	"github.com/vKS-Rajput/doge/internal/opportunity"
	"github.com/vKS-Rajput/doge/internal/surface"
)

// ResearchRecommendation is the Brain's output — a prioritized,
// explained recommendation of where investigation attention
// should be focused next.
type ResearchRecommendation struct {
	// ID uniquely identifies this recommendation.
	ID uuid.UUID `json:"id"`

	// Target identifies the primary subject.
	Target string `json:"target"`

	// Title is a concise description.
	Title string `json:"title"`

	// Score is the composite priority score (0.0 - 1.0).
	// Higher = more attention-worthy.
	Score float64 `json:"score"`

	// Rank is the position in the priority list (1 = highest).
	Rank int `json:"rank"`

	// ScoreBreakdown explains how the score was computed.
	ScoreBreakdown ScoreBreakdown `json:"score_breakdown"`

	// Reasons explain WHY this is worth investigating.
	Reasons []string `json:"reasons"`

	// SurfaceType classifies the attack surface involved.
	SurfaceType surface.Category `json:"surface_type"`

	// RelatedOpportunityID links to the opportunity that spawned this.
	RelatedOpportunityID *uuid.UUID `json:"related_opportunity_id,omitempty"`

	// RelatedSignals lists the novelty signals supporting this.
	RelatedSignals []uuid.UUID `json:"related_signals,omitempty"`

	// Status tracks whether this recommendation has been acted on.
	Status RecommendationStatus `json:"status"`

	// CreatedAt is when this recommendation was generated.
	CreatedAt time.Time `json:"created_at"`
}

// RecommendationStatus tracks lifecycle.
type RecommendationStatus string

const (
	StatusPending      RecommendationStatus = "pending"
	StatusInvestigated RecommendationStatus = "investigated"
	StatusDismissed    RecommendationStatus = "dismissed"
	StatusStale        RecommendationStatus = "stale"
)

// ScoreBreakdown shows how each factor contributed to the score.
type ScoreBreakdown struct {
	NoveltyScore      float64 `json:"novelty_score"`
	SurfaceImportance float64 `json:"surface_importance"`
	CorrelationDensity float64 `json:"correlation_density"`
	MultiToolEvidence float64 `json:"multi_tool_evidence"`
	UnexploredBonus   float64 `json:"unexplored_bonus"`
	RecencyBonus      float64 `json:"recency_bonus"`
	InvestigatedPenalty float64 `json:"investigated_penalty"`
	ContradictionBonus float64 `json:"contradiction_bonus"`
}

// --- Scoring Weights ---

// Weights control how much each factor contributes to the final score.
// These are tunable but the defaults reflect security research priorities.
type Weights struct {
	Novelty       float64
	Surface       float64
	Correlation   float64
	MultiTool     float64
	Unexplored    float64
	Recency       float64
	Investigated  float64
	Contradiction float64
}

// DefaultWeights returns the standard scoring weights.
func DefaultWeights() Weights {
	return Weights{
		Novelty:       0.25,
		Surface:       0.20,
		Correlation:   0.15,
		MultiTool:     0.10,
		Unexplored:    0.10,
		Recency:       0.05,
		Investigated:  0.10,
		Contradiction: 0.05,
	}
}

// --- Evidence Input ---

// Evidence is the snapshot of investigation state the Brain consumes.
// The Brain does not query databases — callers build this snapshot.
type Evidence struct {
	// Opportunities are the current research opportunities.
	Opportunities []opportunity.Opportunity

	// NoveltySignals are the current novelty detections.
	NoveltySignals []novelty.Signal

	// ObservationCount is the total number of observations.
	ObservationCount int

	// CorrelationCount is the total number of correlations found.
	CorrelationCount int

	// ToolsUsed lists which tools have produced observations.
	ToolsUsed []string

	// InvestigatedTargets lists targets that have already been investigated.
	InvestigatedTargets map[string]bool

	// DismissedTargets lists targets explicitly dismissed by the researcher.
	DismissedTargets map[string]bool

	// ContradictedTargets lists targets with cross-tool contradictions.
	ContradictedTargets map[string]bool

	// SurfaceNodes is the current attack surface graph size.
	SurfaceNodes int

	// LastActivity is when the most recent observation was ingested.
	LastActivity time.Time
}

// --- Brain ---

// Brain is the research prioritization engine.
type Brain struct {
	weights Weights
	mu      sync.RWMutex

	// History of recommendations for dedup/staleness.
	history map[string]*RecommendationHistory
}

// RecommendationHistory tracks what was previously recommended.
type RecommendationHistory struct {
	Target          string
	TimesRecommended int
	LastRecommended  time.Time
	Status           RecommendationStatus
}

// New creates a new Brain with default weights.
func New() *Brain {
	return &Brain{
		weights: DefaultWeights(),
		history: make(map[string]*RecommendationHistory),
	}
}

// NewWithWeights creates a Brain with custom scoring weights.
func NewWithWeights(w Weights) *Brain {
	return &Brain{
		weights: w,
		history: make(map[string]*RecommendationHistory),
	}
}

// Prioritize takes the current investigation evidence and produces
// a ranked list of research recommendations.
//
// This is the main entry point. It is deterministic — same evidence
// always produces the same ranking (modulo time-based recency).
func (b *Brain) Prioritize(evidence Evidence) []ResearchRecommendation {
	b.mu.Lock()
	defer b.mu.Unlock()

	var recommendations []ResearchRecommendation

	// Score each opportunity.
	for _, opp := range evidence.Opportunities {
		rec := b.scoreOpportunity(opp, evidence)
		if rec != nil {
			recommendations = append(recommendations, *rec)
		}
	}

	// Score orphan novelty signals (signals without linked opportunities).
	orphanSignals := b.findOrphanSignals(evidence)
	for _, signal := range orphanSignals {
		rec := b.scoreSignal(signal, evidence)
		if rec != nil {
			recommendations = append(recommendations, *rec)
		}
	}

	// Sort by score descending.
	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].Score > recommendations[j].Score
	})

	// Assign ranks.
	for i := range recommendations {
		recommendations[i].Rank = i + 1
	}

	// Update history.
	for _, rec := range recommendations {
		b.updateHistory(rec)
	}

	return recommendations
}

// MarkInvestigated marks a target as already investigated.
func (b *Brain) MarkInvestigated(target string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	h, ok := b.history[target]
	if !ok {
		h = &RecommendationHistory{Target: target}
		b.history[target] = h
	}
	h.Status = StatusInvestigated
}

// MarkDismissed marks a target as dismissed by the researcher.
func (b *Brain) MarkDismissed(target string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	h, ok := b.history[target]
	if !ok {
		h = &RecommendationHistory{Target: target}
		b.history[target] = h
	}
	h.Status = StatusDismissed
}

// Recommendations returns the most recent prioritized list.
func (b *Brain) History() map[string]*RecommendationHistory {
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make(map[string]*RecommendationHistory, len(b.history))
	for k, v := range b.history {
		copy := *v
		out[k] = &copy
	}
	return out
}

// --- Scoring Functions ---

func (b *Brain) scoreOpportunity(opp opportunity.Opportunity, evidence Evidence) *ResearchRecommendation {
	target := opp.Target

	// Skip dismissed targets.
	if evidence.DismissedTargets[target] {
		return nil
	}

	breakdown := ScoreBreakdown{}

	// 1. Novelty score — average from linked signals.
	if len(opp.NoveltySignals) > 0 {
		totalNovelty := 0.0
		for _, sig := range opp.NoveltySignals {
			totalNovelty += sig.NoveltyScore
		}
		breakdown.NoveltyScore = totalNovelty / float64(len(opp.NoveltySignals))
	}

	// 2. Surface importance.
	breakdown.SurfaceImportance = surfaceImportance(opp.SurfaceType)

	// 3. Correlation density — more correlations = more interesting.
	if evidence.CorrelationCount > 0 && evidence.ObservationCount > 0 {
		density := float64(evidence.CorrelationCount) / float64(evidence.ObservationCount)
		breakdown.CorrelationDensity = clamp(density, 0, 1)
	}

	// 4. Multi-tool evidence — more tools corroborating = stronger signal.
	if len(evidence.ToolsUsed) > 1 {
		breakdown.MultiToolEvidence = clamp(float64(len(evidence.ToolsUsed))/7.0, 0, 1)
	}

	// 5. Unexplored bonus — never investigated = more interesting.
	if !evidence.InvestigatedTargets[target] {
		breakdown.UnexploredBonus = 1.0
	}

	// 6. Recency bonus — newer signals get a boost.
	recency := time.Since(opp.CreatedAt)
	if recency < 5*time.Minute {
		breakdown.RecencyBonus = 1.0
	} else if recency < 30*time.Minute {
		breakdown.RecencyBonus = 0.5
	} else if recency < 2*time.Hour {
		breakdown.RecencyBonus = 0.2
	}

	// 7. Investigated penalty — already investigated = lower priority.
	if evidence.InvestigatedTargets[target] {
		breakdown.InvestigatedPenalty = 1.0
	}
	// Also check brain's own history.
	if h, ok := b.history[target]; ok {
		if h.Status == StatusInvestigated {
			breakdown.InvestigatedPenalty = 1.0
		}
		// Repeated recommendations get diminishing returns.
		if h.TimesRecommended > 2 {
			breakdown.InvestigatedPenalty = math.Max(breakdown.InvestigatedPenalty, 0.5)
		}
	}

	// 8. Contradiction bonus — contradictions are always interesting.
	if evidence.ContradictedTargets[target] {
		breakdown.ContradictionBonus = 1.0
	}
	for _, sig := range opp.NoveltySignals {
		if sig.Category == novelty.CategoryContradiction {
			breakdown.ContradictionBonus = 1.0
		}
	}

	// Compute weighted score.
	score := b.weights.Novelty*breakdown.NoveltyScore +
		b.weights.Surface*breakdown.SurfaceImportance +
		b.weights.Correlation*breakdown.CorrelationDensity +
		b.weights.MultiTool*breakdown.MultiToolEvidence +
		b.weights.Unexplored*breakdown.UnexploredBonus +
		b.weights.Recency*breakdown.RecencyBonus -
		b.weights.Investigated*breakdown.InvestigatedPenalty +
		b.weights.Contradiction*breakdown.ContradictionBonus

	score = clamp(score, 0, 1)

	// Build reasons.
	reasons := buildReasons(opp, breakdown, evidence)

	oppID := opp.ID
	var signalIDs []uuid.UUID
	for _, sig := range opp.NoveltySignals {
		signalIDs = append(signalIDs, sig.ID)
	}

	return &ResearchRecommendation{
		ID:                   uuid.New(),
		Target:               target,
		Title:                opp.Title,
		Score:                score,
		ScoreBreakdown:       breakdown,
		Reasons:              reasons,
		SurfaceType:          opp.SurfaceType,
		RelatedOpportunityID: &oppID,
		RelatedSignals:       signalIDs,
		Status:               StatusPending,
		CreatedAt:            time.Now().UTC(),
	}
}

func (b *Brain) scoreSignal(signal novelty.Signal, evidence Evidence) *ResearchRecommendation {
	target := signal.Title // Use signal title as target identifier.

	// Skip dismissed.
	if evidence.DismissedTargets[target] {
		return nil
	}

	breakdown := ScoreBreakdown{
		NoveltyScore: signal.NoveltyScore,
	}

	if len(signal.SurfaceCategories) > 0 {
		breakdown.SurfaceImportance = surfaceImportance(signal.SurfaceCategories[0])
	}

	if !evidence.InvestigatedTargets[target] {
		breakdown.UnexploredBonus = 1.0
	}

	if signal.Category == novelty.CategoryContradiction {
		breakdown.ContradictionBonus = 1.0
	}

	score := b.weights.Novelty*breakdown.NoveltyScore +
		b.weights.Surface*breakdown.SurfaceImportance +
		b.weights.Unexplored*breakdown.UnexploredBonus +
		b.weights.Contradiction*breakdown.ContradictionBonus

	score = clamp(score, 0, 1)

	sigID := signal.ID
	return &ResearchRecommendation{
		ID:             uuid.New(),
		Target:         target,
		Title:          signal.Title,
		Score:          score,
		ScoreBreakdown: breakdown,
		Reasons: []string{
			fmt.Sprintf("Novelty signal: %s (score %.2f)", signal.Type, signal.NoveltyScore),
			signal.Description,
		},
		RelatedSignals: []uuid.UUID{sigID},
		Status:         StatusPending,
		CreatedAt:      time.Now().UTC(),
	}
}

// findOrphanSignals returns novelty signals not linked to any opportunity.
func (b *Brain) findOrphanSignals(evidence Evidence) []novelty.Signal {
	// Build set of signal IDs that are linked to opportunities.
	linked := make(map[uuid.UUID]bool)
	for _, opp := range evidence.Opportunities {
		for _, sig := range opp.NoveltySignals {
			linked[sig.ID] = true
		}
	}

	var orphans []novelty.Signal
	for _, sig := range evidence.NoveltySignals {
		if !linked[sig.ID] {
			orphans = append(orphans, sig)
		}
	}
	return orphans
}

func (b *Brain) updateHistory(rec ResearchRecommendation) {
	h, ok := b.history[rec.Target]
	if !ok {
		h = &RecommendationHistory{Target: rec.Target}
		b.history[rec.Target] = h
	}
	h.TimesRecommended++
	h.LastRecommended = time.Now()
	if h.Status == "" {
		h.Status = StatusPending
	}
}

// --- Surface Importance ---

// surfaceImportance returns a score (0-1) for how important a surface type is
// from a security research perspective.
func surfaceImportance(cat surface.Category) float64 {
	switch cat {
	case surface.CategoryAuthentication:
		return 1.0
	case surface.CategoryAuthorization:
		return 0.95
	case surface.CategoryUpload:
		return 0.95
	case surface.CategoryAPI:
		return 0.90
	case surface.CategoryExposure:
		return 0.85
	case surface.CategoryWeb:
		return 0.50
	case surface.CategoryDNS:
		return 0.40
	case surface.CategoryNetwork:
		return 0.35
	case surface.CategoryInfrastructure:
		return 0.30
	case surface.CategoryTechnology:
		return 0.25
	default:
		return 0.30
	}
}

// --- Reason Building ---

func buildReasons(opp opportunity.Opportunity, bd ScoreBreakdown, evidence Evidence) []string {
	var reasons []string

	if bd.NoveltyScore >= 0.8 {
		reasons = append(reasons, "Highly novel — unusual compared to known patterns")
	} else if bd.NoveltyScore >= 0.5 {
		reasons = append(reasons, "Moderately novel — some unusual characteristics")
	}

	if bd.SurfaceImportance >= 0.9 {
		reasons = append(reasons, fmt.Sprintf("High-value surface type: %s", opp.SurfaceType))
	}

	if bd.MultiToolEvidence >= 0.5 {
		reasons = append(reasons, fmt.Sprintf("Corroborated by %d tools", len(evidence.ToolsUsed)))
	}

	if bd.UnexploredBonus > 0 {
		reasons = append(reasons, "Never previously investigated")
	}

	if bd.ContradictionBonus > 0 {
		reasons = append(reasons, "Cross-tool contradiction detected — warrants investigation")
	}

	if bd.InvestigatedPenalty > 0 {
		reasons = append(reasons, "Previously investigated — lower priority unless new evidence")
	}

	if bd.RecencyBonus >= 0.8 {
		reasons = append(reasons, "Recently discovered — fresh intelligence")
	}

	if len(reasons) == 0 {
		reasons = append(reasons, opp.Description)
	}

	return reasons
}

// --- Utilities ---

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
