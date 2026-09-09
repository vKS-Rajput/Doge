// Package coordinator implements the central research brain of DOGE V2.
//
// The coordinator maintains global research state and orchestrates the complete
// research loop:
//
//	TARGET → LEARN → MAP → UNKNOWN → HYPOTHESIS → MISSION → RESEARCHER
//	→ EXPERIMENT → OBSERVATION → WORLD MODEL UPDATE → NEW HYPOTHESIS
//	→ EXPLOIT → INDEPENDENT VALIDATOR → IMPACT RESEARCHER → PROVEN FINDING
//
// The coordinator decides WHAT to investigate based on:
//   - What don't I know? (unknowns)
//   - Why does that matter? (information gain)
//   - What hypotheses explain it? (hypothesis engine)
//   - Which experiment best separates them? (experiment design)
//   - Which researcher should investigate? (researcher dispatch)
//   - What did we learn? (debrief)
//   - What should happen next? (loop)
//
// The tools are capabilities available to researchers.
// They are no longer DOGE's brain.
package coordinator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/researcher"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ResearchState holds the complete state of an ongoing research engagement.
type ResearchState struct {
	// Things we found
	Endpoints     []string               `json:"endpoints"`
	Users         []string               `json:"users"`
	Objects       []string               `json:"objects"`
	Technologies  []string               `json:"technologies"`

	// Things we tried
	Attempted     []AttemptRecord        `json:"attempted"`

	// Things that failed
	Failures      []FailureRecord        `json:"failures"`

	// Things we believe (hypotheses)
	Hypotheses    []domain.MissionHypothesis `json:"hypotheses"`

	// Things we disproved
	Disproved     []DisprovalRecord      `json:"disproved"`

	// Things we have not tested
	Untested      []string               `json:"untested"`

	// Things we cannot explain
	Unexplained   []string               `json:"unexplained"`

	// Things that changed
	Changes       []ChangeRecord         `json:"changes"`

	// Completed missions
	Missions      []domain.MissionResult `json:"missions"`

	// Candidate vulnerabilities (awaiting validation)
	Candidates    []domain.CandidateVulnerability `json:"candidates"`

	// Validated candidates (awaiting impact research)
	Validated     []domain.CandidateVulnerability `json:"validated"`

	// Proven findings (complete chain: discovery → validation → impact)
	ProvenFindings []domain.ProvenFinding          `json:"proven_findings"`

	// All evidence
	AllEvidence   []domain.ExperimentEvidence      `json:"all_evidence"`
}

// AttemptRecord records what was tried.
type AttemptRecord struct {
	Description string    `json:"description"`
	Endpoint    string    `json:"endpoint"`
	MissionID   uuid.UUID `json:"mission_id"`
	Timestamp   time.Time `json:"timestamp"`
}

// FailureRecord records what failed and why.
type FailureRecord struct {
	Description string    `json:"description"`
	Reason      string    `json:"reason"`
	MissionID   uuid.UUID `json:"mission_id"`
	Timestamp   time.Time `json:"timestamp"`
}

// DisprovalRecord records what hypotheses were disproved.
type DisprovalRecord struct {
	HypothesisTitle string    `json:"hypothesis_title"`
	Evidence        string    `json:"evidence"`
	Timestamp       time.Time `json:"timestamp"`
}

// ChangeRecord records behavioral changes observed in the target.
type ChangeRecord struct {
	Description string    `json:"description"`
	Before      string    `json:"before"`
	After       string    `json:"after"`
	Timestamp   time.Time `json:"timestamp"`
}

// ResearchCoordinator orchestrates the complete DOGE V2 research loop.
type ResearchCoordinator struct {
	state       *ResearchState
	researchers map[domain.ResearcherType]researcher.Researcher
	targetURL   string
	credentials map[string]string
	maxMissions int
}

// NewResearchCoordinator creates a new coordinator for a target engagement.
func NewResearchCoordinator(targetURL string, credentials map[string]string) *ResearchCoordinator {
	return &ResearchCoordinator{
		state: &ResearchState{
			Untested: []string{
				"API attack surface unknown",
				"Authentication model unknown",
				"Authorization boundaries unknown",
				"Multi-tenant isolation unknown",
			},
		},
		researchers: make(map[domain.ResearcherType]researcher.Researcher),
		targetURL:   targetURL,
		credentials: credentials,
		maxMissions: 10,
	}
}

// RegisterResearcher adds a specialized researcher to the coordinator's fleet.
func (c *ResearchCoordinator) RegisterResearcher(r researcher.Researcher) {
	c.researchers[r.Type()] = r
}

// SetMaxMissions configures the maximum number of missions to run.
func (c *ResearchCoordinator) SetMaxMissions(max int) {
	c.maxMissions = max
}

// GetState returns the current research state.
func (c *ResearchCoordinator) GetState() *ResearchState {
	return c.state
}

// Run executes the complete research loop until:
// 1. A proven finding is produced, OR
// 2. All research avenues are exhausted, OR
// 3. The mission budget is exceeded
func (c *ResearchCoordinator) Run(ctx context.Context) error {
	missionCount := 0

	// ──────────────────────────────────────
	// Phase 1: LEARN & MAP
	// ──────────────────────────────────────
	reconBrief := &domain.MissionBrief{
		ID:             uuid.New(),
		ResearcherType: domain.ResearcherRecon,
		Title:          "Initial Reconnaissance",
		Description:    "Map the target's attack surface, discover endpoints, authentication, tenants, and object patterns.",
		TargetBaseURL:  c.targetURL,
		Credentials:    c.credentials,
		MaxRequests:    50,
		MaxDuration:    60 * time.Second,
		SuccessCriteria: "At least one endpoint discovered, at least one user identified",
	}

	reconResult, err := c.dispatchMission(ctx, reconBrief)
	if err != nil {
		return fmt.Errorf("recon mission failed: %w", err)
	}
	c.debrief(reconResult)
	missionCount++

	// ──────────────────────────────────────
	// Phase 2: HYPOTHESIZE → MISSION → EXPERIMENT
	// ──────────────────────────────────────
	// Generate authorization testing mission if hypotheses warrant it
	if len(c.state.Hypotheses) > 0 && missionCount < c.maxMissions {
		authBrief := &domain.MissionBrief{
			ID:             uuid.New(),
			ResearcherType: domain.ResearcherAuthorization,
			Title:          "Authorization Boundary Testing",
			Description:    "Test object-level authorization through differential cross-principal experiments.",
			TargetBaseURL:  c.targetURL,
			Credentials:    c.credentials,
			Hypotheses:     c.state.Hypotheses,
			KnownEndpoints: c.state.Endpoints,
			KnownUsers:     c.state.Users,
			KnownObjects:   c.state.Objects,
			MaxRequests:    100,
			MaxDuration:    120 * time.Second,
			SuccessCriteria: "Hypothesis confirmed or refuted with evidence",
		}

		authResult, err := c.dispatchMission(ctx, authBrief)
		if err != nil {
			return fmt.Errorf("authorization mission failed: %w", err)
		}
		c.debrief(authResult)
		missionCount++
	}

	// ──────────────────────────────────────
	// Phase 3: INDEPENDENT VALIDATION
	// ──────────────────────────────────────
	if len(c.state.Candidates) > 0 && missionCount < c.maxMissions {
		// Pick the strongest candidate
		candidate := c.state.Candidates[0]

		validationBrief := &domain.MissionBrief{
			ID:             uuid.New(),
			ResearcherType: domain.ResearcherValidation,
			Title:          fmt.Sprintf("Independent Validation: %s", candidate.Title),
			Description:    "Independently reproduce and validate the candidate vulnerability using fresh context.",
			TargetBaseURL:  c.targetURL,
			Credentials:    c.credentials,
			Hypotheses: []domain.MissionHypothesis{
				{
					ID:                   candidate.ID,
					Title:                candidate.Title,
					Statement:            candidate.Description,
					Confidence:           0.80,
					ConfirmationCriteria: "Independent reproduction of cross-tenant access with evidence",
					RefutationCriteria:   "Cannot reproduce cross-tenant access",
				},
			},
			KnownEndpoints: c.state.Endpoints,
			KnownObjects:   c.state.Objects,
			MaxRequests:    80,
			MaxDuration:    90 * time.Second,
			SuccessCriteria: "Independent reproduction with evidence",
		}

		validationResult, err := c.dispatchMission(ctx, validationBrief)
		if err != nil {
			return fmt.Errorf("validation mission failed: %w", err)
		}
		c.debrief(validationResult)
		missionCount++
	}

	// ──────────────────────────────────────
	// Phase 4: IMPACT RESEARCH
	// ──────────────────────────────────────
	if len(c.state.Validated) > 0 && missionCount < c.maxMissions {
		validated := c.state.Validated[0]

		impactBrief := &domain.MissionBrief{
			ID:             uuid.New(),
			ResearcherType: domain.ResearcherImpact,
			Title:          fmt.Sprintf("Impact Demonstration: %s", validated.Title),
			Description:    "Demonstrate the real-world impact of the validated vulnerability within authorization constraints.",
			TargetBaseURL:  c.targetURL,
			Credentials:    c.credentials,
			KnownEndpoints: c.state.Endpoints,
			KnownObjects:   c.state.Objects,
			MaxRequests:    50,
			MaxDuration:    60 * time.Second,
			SuccessCriteria: "Impact demonstrated with evidence",
		}

		impactResult, err := c.dispatchMission(ctx, impactBrief)
		if err != nil {
			return fmt.Errorf("impact mission failed: %w", err)
		}
		c.debrief(impactResult)
		missionCount++
	}

	// ──────────────────────────────────────
	// Phase 5: PROVEN FINDING
	// ──────────────────────────────────────
	if len(c.state.Validated) > 0 {
		validated := c.state.Validated[0]

		// Collect all evidence across the research chain
		var discoveryEvidence, validationEvidence, impactEvidence []domain.ExperimentEvidence
		for _, m := range c.state.Missions {
			switch m.ResearcherType {
			case domain.ResearcherAuthorization:
				for _, ev := range m.Evidence {
					if ev.IsAnomalous {
						discoveryEvidence = append(discoveryEvidence, ev)
					}
				}
			case domain.ResearcherValidation:
				for _, ev := range m.Evidence {
					if ev.IsAnomalous {
						validationEvidence = append(validationEvidence, ev)
					}
				}
			case domain.ResearcherImpact:
				impactEvidence = append(impactEvidence, m.Evidence...)
			}
		}

		// Construct the proven finding
		proven := domain.ProvenFinding{
			ID:                  uuid.New(),
			CandidateID:         validated.ID,
			Title:               validated.Title,
			Type:                validated.Type,
			Severity:            validated.Severity,
			Endpoint:            validated.Endpoint,
			Description:         validated.Description,
			DiscoveryEvidence:   discoveryEvidence,
			ValidationEvidence:  validationEvidence,
			ImpactEvidence:      impactEvidence,
			ReproductionSteps:   validated.ReproductionSteps,
			ValidatedAt:         time.Now().UTC(),
		}

		// Find the mission IDs
		for _, m := range c.state.Missions {
			if m.ResearcherType == domain.ResearcherAuthorization {
				proven.DiscoveryMissionID = m.MissionID
			}
			if m.ResearcherType == domain.ResearcherValidation {
				proven.ValidationMissionID = m.MissionID
			}
			if m.ResearcherType == domain.ResearcherImpact {
				id := m.MissionID
				proven.ImpactMissionID = &id
			}
		}

		c.state.ProvenFindings = append(c.state.ProvenFindings, proven)
	}

	return nil
}

// dispatchMission sends a mission to the appropriate researcher and returns the result.
func (c *ResearchCoordinator) dispatchMission(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	r, ok := c.researchers[brief.ResearcherType]
	if !ok {
		return nil, fmt.Errorf("no researcher registered for type %s", brief.ResearcherType)
	}

	// Record the attempt
	c.state.Attempted = append(c.state.Attempted, AttemptRecord{
		Description: brief.Title,
		MissionID:   brief.ID,
		Timestamp:   time.Now().UTC(),
	})

	result, err := r.Execute(ctx, brief)
	if err != nil {
		c.state.Failures = append(c.state.Failures, FailureRecord{
			Description: brief.Title,
			Reason:      err.Error(),
			MissionID:   brief.ID,
			Timestamp:   time.Now().UTC(),
		})
		return nil, err
	}

	return result, nil
}

// debrief integrates a mission result into the global research state.
// This is where the World Model gets updated.
func (c *ResearchCoordinator) debrief(result *domain.MissionResult) {
	c.state.Missions = append(c.state.Missions, *result)

	// Merge discovered endpoints
	for _, ep := range result.Endpoints {
		if !contains(c.state.Endpoints, ep) {
			c.state.Endpoints = append(c.state.Endpoints, ep)
		}
	}

	// Merge discovered users
	for _, u := range result.Users {
		if !contains(c.state.Users, u) {
			c.state.Users = append(c.state.Users, u)
		}
	}

	// Merge discovered objects
	for _, o := range result.Objects {
		if !contains(c.state.Objects, o) {
			c.state.Objects = append(c.state.Objects, o)
		}
	}

	// Process new unknowns
	for _, u := range result.NewUnknowns {
		if !contains(c.state.Untested, u) {
			c.state.Untested = append(c.state.Untested, u)
		}
	}

	// Process new hypotheses
	c.state.Hypotheses = append(c.state.Hypotheses, result.NewHypotheses...)

	// Process hypothesis updates
	for _, update := range result.HypothesisUpdates {
		for i := range c.state.Hypotheses {
			if c.state.Hypotheses[i].ID == update.HypothesisID {
				c.state.Hypotheses[i].Confidence = update.NewConfidence
			}
		}
		if strings.Contains(update.NewStatus, "contradicted") || strings.Contains(update.NewStatus, "rejected") {
			c.state.Disproved = append(c.state.Disproved, DisprovalRecord{
				Evidence:  update.Reason,
				Timestamp: time.Now().UTC(),
			})
		}
	}

	// Process candidates
	c.state.Candidates = append(c.state.Candidates, result.CandidateFindings...)

	// If this was a validation mission with confirmed candidates, move to validated
	if result.ResearcherType == domain.ResearcherValidation {
		for _, candidate := range result.CandidateFindings {
			if strings.Contains(strings.ToLower(candidate.Title), "validated") {
				c.state.Validated = append(c.state.Validated, candidate)
			}
		}
	}

	// Collect all evidence
	c.state.AllEvidence = append(c.state.AllEvidence, result.Evidence...)

	// Remove resolved unknowns
	if result.ResearcherType == domain.ResearcherRecon {
		// Remove "API attack surface unknown" etc. when recon completes
		c.state.Untested = removeMatching(c.state.Untested, "API attack surface unknown")
		c.state.Untested = removeMatching(c.state.Untested, "Authentication model unknown")
		if len(result.Users) >= 2 {
			c.state.Untested = removeMatching(c.state.Untested, "Multi-tenant isolation unknown")
		}
	}
	if result.ResearcherType == domain.ResearcherAuthorization {
		c.state.Untested = removeMatching(c.state.Untested, "Authorization boundaries unknown")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func removeMatching(slice []string, target string) []string {
	var result []string
	for _, s := range slice {
		if s != target {
			result = append(result, s)
		}
	}
	return result
}
