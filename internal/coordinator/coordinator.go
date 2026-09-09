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
	"github.com/vKS-Rajput/doge/internal/attackgraph"
	"github.com/vKS-Rajput/doge/internal/property"
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

// ResearchCoordinator orchestrates the complete DOGE research loop.
type ResearchCoordinator struct {
	state             *ResearchState
	researchers       map[domain.ResearcherType]researcher.Researcher
	targetURL         string
	credentials       map[string]string
	maxMissions       int
	propertyEvaluator *property.Evaluator
	attackGraph       *attackgraph.Graph
	catalog           *property.Catalog
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
		researchers:       make(map[domain.ResearcherType]researcher.Researcher),
		targetURL:         targetURL,
		credentials:       credentials,
		maxMissions:       10,
		propertyEvaluator: property.NewEvaluator(),
		attackGraph:       attackgraph.NewGraph(),
		catalog:           property.NewCatalog(),
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

// PropertyEvaluator returns the coordinator's property evaluator.
func (c *ResearchCoordinator) PropertyEvaluator() *property.Evaluator {
	return c.propertyEvaluator
}

// AttackGraph returns the coordinator's attack graph.
func (c *ResearchCoordinator) AttackGraph() *attackgraph.Graph {
	return c.attackGraph
}

// Run executes the complete research loop dynamically until:
// 1. A proven finding is produced, OR
// 2. All research avenues are exhausted, OR
// 3. The mission budget is exceeded
func (c *ResearchCoordinator) Run(ctx context.Context) error {
	missionCount := 0

	for missionCount < c.maxMissions {
		brief := c.planNextMission()
		if brief == nil {
			break
		}

		result, err := c.dispatchMission(ctx, brief)
		if err != nil {
			return fmt.Errorf("mission %s (%s) failed: %w", brief.Title, brief.ResearcherType, err)
		}
		c.debrief(result)
		missionCount++

		// Check if we have achieved a complete proven finding
		if len(c.state.Validated) > 0 && c.hasImpactEvidence() {
			c.finalizeFindings()
			if len(c.state.ProvenFindings) > 0 {
				break
			}
		}
	}

	c.finalizeFindings()
	return nil
}

func (c *ResearchCoordinator) hasResearcher(rType domain.ResearcherType) bool {
	_, ok := c.researchers[rType]
	return ok
}

func (c *ResearchCoordinator) hasImpactEvidence() bool {
	for _, m := range c.state.Missions {
		if m.ResearcherType == domain.ResearcherImpact && len(m.Evidence) > 0 {
			return true
		}
	}
	return false
}

// planNextMission determines the next research step based on world model gaps and hypotheses.
func (c *ResearchCoordinator) planNextMission() *domain.MissionBrief {
	// 1. If no missions yet, always begin with Reconnaissance
	if len(c.state.Missions) == 0 {
		return &domain.MissionBrief{
			ID:              uuid.New(),
			ResearcherType:  domain.ResearcherRecon,
			Title:           "Initial Reconnaissance",
			Description:     "Map the target's attack surface, discover endpoints, authentication, tenants, and object patterns.",
			TargetBaseURL:   c.targetURL,
			Credentials:     c.credentials,
			MaxRequests:     50,
			MaxDuration:     60 * time.Second,
			SuccessCriteria: "At least one endpoint discovered, at least one user identified",
		}
	}

	// 2. If we have validated candidate(s) that need impact demonstration
	if len(c.state.Validated) > 0 && c.hasResearcher(domain.ResearcherImpact) {
		impactRan := false
		for _, m := range c.state.Missions {
			if m.ResearcherType == domain.ResearcherImpact {
				impactRan = true
				break
			}
		}
		if !impactRan {
			validated := c.state.Validated[0]
			return &domain.MissionBrief{
				ID:              uuid.New(),
				ResearcherType:  domain.ResearcherImpact,
				Title:           fmt.Sprintf("Impact Demonstration: %s", validated.Title),
				Description:     "Demonstrate the real-world impact of the validated vulnerability within authorization constraints.",
				TargetBaseURL:   c.targetURL,
				Credentials:     c.credentials,
				KnownEndpoints:  c.state.Endpoints,
				KnownObjects:    c.state.Objects,
				MaxRequests:     50,
				MaxDuration:     60 * time.Second,
				SuccessCriteria: "Impact demonstrated with evidence",
			}
		}
	}

	// 3. If we have unvalidated candidate(s), dispatch Independent Validation
	if len(c.state.Candidates) > 0 && len(c.state.Validated) == 0 && c.hasResearcher(domain.ResearcherValidation) {
		validationRan := false
		for _, m := range c.state.Missions {
			if m.ResearcherType == domain.ResearcherValidation {
				validationRan = true
				break
			}
		}
		if !validationRan {
			candidate := c.state.Candidates[0]
			var confCriteria, refutCriteria string
			if strings.Contains(strings.ToLower(candidate.Type), "workflow") {
				confCriteria = "Independent reproduction of workflow transition bypass with differential control"
				refutCriteria = "Cannot reproduce workflow transition bypass"
			} else {
				confCriteria = "Independent reproduction of cross-tenant access with evidence"
				refutCriteria = "Cannot reproduce cross-tenant access"
			}
			return &domain.MissionBrief{
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
						ConfirmationCriteria: confCriteria,
						RefutationCriteria:   refutCriteria,
					},
				},
				KnownEndpoints: c.state.Endpoints,
				KnownObjects:   c.state.Objects,
				MaxRequests:    80,
				MaxDuration:    90 * time.Second,
				SuccessCriteria: "Independent reproduction with evidence",
			}
		}
	}

	// 4. Hypothesis-driven research dispatch
	// Check for Workflow State Bypass hypothesis or workflow endpoints
	workflowRan := false
	for _, m := range c.state.Missions {
		if m.ResearcherType == domain.ResearcherWorkflow {
			workflowRan = true
			break
		}
	}
	hasWorkflowSignal := false
	for _, h := range c.state.Hypotheses {
		low := strings.ToLower(h.Title)
		if strings.Contains(low, "workflow") || strings.Contains(low, "state") {
			hasWorkflowSignal = true
			break
		}
	}
	for _, ep := range c.state.Endpoints {
		low := strings.ToLower(ep)
		if strings.Contains(low, "order") || strings.Contains(low, "cart") || strings.Contains(low, "checkout") {
			hasWorkflowSignal = true
			break
		}
	}
	if !workflowRan && hasWorkflowSignal && c.hasResearcher(domain.ResearcherWorkflow) {
		return &domain.MissionBrief{
			ID:              uuid.New(),
			ResearcherType:  domain.ResearcherWorkflow,
			Title:           "Workflow State Integrity Testing",
			Description:     "Discover state machines and test whether workflow transitions can be bypassed or skipped.",
			TargetBaseURL:   c.targetURL,
			Credentials:     c.credentials,
			Hypotheses:      c.state.Hypotheses,
			KnownEndpoints:  c.state.Endpoints,
			Unknowns:        c.state.Untested,
			MaxRequests:     100,
			MaxDuration:     120 * time.Second,
			SuccessCriteria: "State machine mapped and transition integrity tested",
		}
	}

	// Check for Authorization Testing hypothesis
	authRan := false
	for _, m := range c.state.Missions {
		if m.ResearcherType == domain.ResearcherAuthorization {
			authRan = true
			break
		}
	}
	if !authRan && len(c.state.Hypotheses) > 0 && c.hasResearcher(domain.ResearcherAuthorization) {
		return &domain.MissionBrief{
			ID:              uuid.New(),
			ResearcherType:  domain.ResearcherAuthorization,
			Title:           "Authorization Boundary Testing",
			Description:     "Test object-level authorization through differential cross-principal experiments.",
			TargetBaseURL:   c.targetURL,
			Credentials:     c.credentials,
			Hypotheses:      c.state.Hypotheses,
			KnownEndpoints:  c.state.Endpoints,
			KnownUsers:      c.state.Users,
			KnownObjects:    c.state.Objects,
			MaxRequests:     100,
			MaxDuration:     120 * time.Second,
			SuccessCriteria: "Hypothesis confirmed or refuted with evidence",
		}
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
		c.state.Untested = removeMatching(c.state.Untested, "API attack surface unknown")
		c.state.Untested = removeMatching(c.state.Untested, "Authentication model unknown")
		if len(result.Users) >= 2 {
			c.state.Untested = removeMatching(c.state.Untested, "Multi-tenant isolation unknown")
		}

		// Feed into property evaluator & attack graph
		for _, ep := range result.Endpoints {
			for _, p := range c.catalog.GenerateForEndpoint(ep) {
				c.propertyEvaluator.Register(p)
			}
			c.attackGraph.AddNode(attackgraph.NodeResource, ep, fmt.Sprintf("API endpoint: %s", ep), 0.9)
		}
		for _, u := range result.Users {
			c.attackGraph.AddNode(attackgraph.NodePrincipal, u, fmt.Sprintf("Identified principal: %s", u), 0.95)
		}
	}
	if result.ResearcherType == domain.ResearcherAuthorization {
		c.state.Untested = removeMatching(c.state.Untested, "Authorization boundaries unknown")
	}
	if result.ResearcherType == domain.ResearcherWorkflow {
		c.state.Untested = removeMatching(c.state.Untested, "Workflow state transition enforcement is untested")
		for _, p := range c.catalog.GenerateForWorkflow("order_flow", []string{"created", "checkout", "paid", "confirmed"}) {
			c.propertyEvaluator.Register(p)
		}
	}

	// Record weaknesses & impact in attack graph
	for _, cand := range result.CandidateFindings {
		wnode := c.attackGraph.AddNode(attackgraph.NodeWeakness, cand.Title, cand.Description, 0.9)
		if epNode, ok := c.attackGraph.GetNodeByLabel(cand.Endpoint); ok {
			c.attackGraph.AddEdge(epNode.ID, wnode.ID, attackgraph.EdgeLeadsTo, "hosts vulnerability", 0.9)
		}
	}
}

// finalizeFindings synthesizes validated candidates and evidence into proven findings.
func (c *ResearchCoordinator) finalizeFindings() {
	if len(c.state.Validated) == 0 || len(c.state.ProvenFindings) > 0 {
		return
	}

	for _, validated := range c.state.Validated {
		var discoveryEvidence, validationEvidence, impactEvidence []domain.ExperimentEvidence
		var discoveryMissionID, validationMissionID uuid.UUID
		var impactMissionID *uuid.UUID

		for _, m := range c.state.Missions {
			switch m.ResearcherType {
			case domain.ResearcherAuthorization, domain.ResearcherWorkflow:
				for _, ev := range m.Evidence {
					if ev.IsAnomalous {
						discoveryEvidence = append(discoveryEvidence, ev)
					}
				}
				discoveryMissionID = m.MissionID
			case domain.ResearcherValidation:
				for _, ev := range m.Evidence {
					if ev.IsAnomalous {
						validationEvidence = append(validationEvidence, ev)
					}
				}
				validationMissionID = m.MissionID
			case domain.ResearcherImpact:
				impactEvidence = append(impactEvidence, m.Evidence...)
				id := m.MissionID
				impactMissionID = &id
			}
		}

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
			DiscoveryMissionID:  discoveryMissionID,
			ValidationMissionID: validationMissionID,
			ImpactMissionID:     impactMissionID,
			ValidatedAt:         time.Now().UTC(),
		}

		c.state.ProvenFindings = append(c.state.ProvenFindings, proven)

		// Record impact in attack graph
		impNode := c.attackGraph.AddNode(attackgraph.NodeImpact, proven.Title+" Impact", proven.Description, 0.95)
		if valNode, ok := c.attackGraph.GetNodeByLabel(proven.Title); ok {
			c.attackGraph.AddEdge(valNode.ID, impNode.ID, attackgraph.EdgeLeadsTo, "demonstrates impact", 0.95)
		}
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
