package reasoning

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// SpecialistRole identifies one of the veteran domain expertise divisions.
type SpecialistRole string

const (
	RoleReconCartographer SpecialistRole = "Recon Cartographer (Attack Surface)"
	RoleAuthMatrix        SpecialistRole = "Auth & Identity Matrix (OAuth/JWT/State)"
	RoleLogicStateMachine SpecialistRole = "Logic & State Flaw Specialist (Invariants)"
	RoleCloudIAMMesh      SpecialistRole = "Cloud & IAM Mesh Specialist (Metadata/Escalation)"
	RoleAPISchemaContract SpecialistRole = "API & Schema Contract Specialist (BOLA/Smuggling)"
	RoleExploitDeveloper  SpecialistRole = "Exploit Developer & Prover (CEGAR Verification)"
)

// SpecialistProfile represents a veteran security researcher persona in the ensemble brain.
type SpecialistProfile struct {
	ID          string         `json:"id"`
	Role        SpecialistRole `json:"role"`
	Name        string         `json:"name"`
	Experience  string         `json:"experience"`
	FocusAreas  []string       `json:"focus_areas"`
	Status      string         `json:"status"` // "deliberating", "analyzing", "consensus_reached", "ready"
	Confidence  float64        `json:"confidence"`
	Invariant   string         `json:"invariant_hypothesis"`
	ActiveProbe string         `json:"active_probe,omitempty"`
}

// CouncilDeliberation represents an ensemble multi-perspective synthesis on an anomaly or target.
type CouncilDeliberation struct {
	Target             string              `json:"target"`
	Timestamp          time.Time           `json:"timestamp"`
	Specialists        []SpecialistProfile `json:"specialists"`
	ConsensusScore     float64             `json:"consensus_score"`
	AgreedHypotheses   []domain.Hypothesis `json:"agreed_hypotheses"`
	ContestedViews     []string            `json:"contested_views"`
	RecommendedAction  string              `json:"recommended_action"`
	RequiresHumanGate  bool                `json:"requires_human_gate"`
	ProposedRiskRating string              `json:"proposed_risk_rating"`
}

// EnsembleCouncil orchestrates the 50+ researcher collective intelligence brain.
type EnsembleCouncil struct {
	specialists []SpecialistProfile
}

// NewEnsembleCouncil initializes the 6 specialized veteran researcher divisions.
func NewEnsembleCouncil() *EnsembleCouncil {
	return &EnsembleCouncil{
		specialists: []SpecialistProfile{
			{
				ID:         "SPC-RECON",
				Role:       RoleReconCartographer,
				Name:       "Division 01: Recon & Edge Topology",
				Experience: "22 Years Edge Discovery & Network Topology",
				FocusAreas: []string{"Subdomain Takeover", "WAF Evasion", "Exposed Git/Kube", "Shadow Endpoints"},
				Status:     "ready",
				Confidence: 0.94,
				Invariant:  "Outer network boundaries must not expose administrative routes or default ingress certificates",
			},
			{
				ID:         "SPC-AUTH",
				Role:       RoleAuthMatrix,
				Name:       "Division 02: Auth & Identity Matrix",
				Experience: "24 Years Cryptographic Protocol & Token Security",
				FocusAreas: []string{"OAuth2 State Desync", "JWT Key Confusion", "Session Fixation", "SAML Signature Wrapping"},
				Status:     "ready",
				Confidence: 0.96,
				Invariant:  "Token signature verification must reject algorithm 'none' and unpinned JWKS URI keys",
			},
			{
				ID:         "SPC-LOGIC",
				Role:       RoleLogicStateMachine,
				Name:       "Division 03: Business Logic & State Invariants",
				Experience: "21 Years Concurrency, TOCTOU & Causal State Machines",
				FocusAreas: []string{"Negative Value Transfers", "Race Window Exploitation", "Step Skipping in Checkout/Workflows"},
				Status:     "ready",
				Confidence: 0.91,
				Invariant:  "Financial balance and workflow step transitions must execute under serializable atomicity constraints",
			},
			{
				ID:         "SPC-CLOUD",
				Role:       RoleCloudIAMMesh,
				Name:       "Division 04: Cloud Architecture & IAM Mesh",
				Experience: "20 Years Cloud Security Architecture & Container Boundaries",
				FocusAreas: []string{"SSRF to 169.254.169.254", "IAM Role Escalation", "K8s ServiceAccount Leaks", "S3 Bucket Policy Drift"},
				Status:     "ready",
				Confidence: 0.95,
				Invariant:  "Internal cloud instance metadata services must be unreachable from external user-supplied URLs",
			},
			{
				ID:         "SPC-API",
				Role:       RoleAPISchemaContract,
				Name:       "Division 05: API Contract & Protocol Invariants",
				Experience: "23 Years API Protocols, GraphQL, gRPC & HTTP Parser Differential",
				FocusAreas: []string{"BOLA / IDOR", "Mass Assignment", "HTTP/2 CL.TE Request Smuggling", "GraphQL Depth Attacks"},
				Status:     "ready",
				Confidence: 0.93,
				Invariant:  "Object access must enforce tenancy ownership predicates independently of client-supplied IDs",
			},
			{
				ID:         "SPC-EXPLOIT",
				Role:       RoleExploitDeveloper,
				Name:       "Division 06: Exploit Developer & Prover",
				Experience: "25 Years Binary/Web Exploit Engineering & CEGAR Proofs",
				FocusAreas: []string{"Minimal PoC Synthesis", "Zero-Day Invariant Falsification", "Cryptographic Attestation", "Safe Verification"},
				Status:     "ready",
				Confidence: 0.98,
				Invariant:  "Every candidate vulnerability must possess a deterministic, non-destructive reproducing proof bundle",
			},
		},
	}
}

// GetSpecialists returns the active profiles of all 6 veteran divisions.
func (c *EnsembleCouncil) GetSpecialists() []SpecialistProfile {
	res := make([]SpecialistProfile, len(c.specialists))
	copy(res, c.specialists)
	return res
}

// Deliberate analyzes an observation or target discrepancy across all 6 specialized perspectives.
func (c *EnsembleCouncil) Deliberate(ctx context.Context, target string, discrepancyDimension string, anomalyScore float64) *CouncilDeliberation {
	now := time.Now().UTC()
	specs := c.GetSpecialists()

	var hypotheses []domain.Hypothesis
	var contested []string
	requiresGate := false
	proposedRisk := "MEDIUM"

	// Simulate multi-perspective deliberation based on the anomaly dimension
	for i := range specs {
		specs[i].Status = "analyzing"
		switch specs[i].Role {
		case RoleAuthMatrix:
			if discrepancyDimension == "TokenAsymmetry" || discrepancyDimension == "StructuralInvariantDivergence" {
				specs[i].Confidence = 0.95
				specs[i].Status = "consensus_reached"
				hypotheses = append(hypotheses, domain.Hypothesis{
					ID:          uuid.New(),
					Title:       fmt.Sprintf("Auth Privilege Escalation at %s", target),
					Description: fmt.Sprintf("Target %s displays asymmetric authentication token validation allowing privilege escalation.", target),
					Type:        domain.HypothesisAccessControl,
					Confidence:  0.95,
					Status:      domain.HypothesisProposed,
					CreatedAt:   now,
					UpdatedAt:   now,
				})
				requiresGate = true
				proposedRisk = "HIGH"
			}
		case RoleAPISchemaContract:
			if discrepancyDimension == "RequestSmuggling" || discrepancyDimension == "StructuralInvariantDivergence" {
				specs[i].Confidence = 0.92
				specs[i].Status = "consensus_reached"
				hypotheses = append(hypotheses, domain.Hypothesis{
					ID:          uuid.New(),
					Title:       fmt.Sprintf("HTTP Parser Divergence at %s", target),
					Description: fmt.Sprintf("HTTP parser divergence detected at %s indicating potential request smuggling invariant violation.", target),
					Type:        domain.HypothesisVulnerability,
					Confidence:  0.92,
					Status:      domain.HypothesisProposed,
					CreatedAt:   now,
					UpdatedAt:   now,
				})
				requiresGate = true
				proposedRisk = "CRITICAL"
			}
		case RoleCloudIAMMesh:
			if discrepancyDimension == "CloudMetadataLeak" {
				specs[i].Confidence = 0.97
				specs[i].Status = "consensus_reached"
				hypotheses = append(hypotheses, domain.Hypothesis{
					ID:          uuid.New(),
					Title:       fmt.Sprintf("Cloud Metadata Reachable via SSRF at %s", target),
					Description: fmt.Sprintf("Cloud instance metadata service endpoint reachable via SSRF from %s.", target),
					Type:        domain.HypothesisVulnerability,
					Confidence:  0.97,
					Status:      domain.HypothesisProposed,
					CreatedAt:   now,
					UpdatedAt:   now,
				})
				requiresGate = true
				proposedRisk = "CRITICAL"
			}
		case RoleLogicStateMachine:
			specs[i].Status = "deliberating"
		case RoleReconCartographer:
			specs[i].Status = "ready"
		case RoleExploitDeveloper:
			if requiresGate {
				specs[i].Status = "awaiting_approval"
				specs[i].ActiveProbe = "Synthesizing minimal CEGAR falsification stimulus"
			} else {
				specs[i].Status = "ready"
			}
		}
	}

	consensus := 0.88
	if anomalyScore > 0.80 {
		consensus = 0.94
	}

	return &CouncilDeliberation{
		Target:             target,
		Timestamp:          now,
		Specialists:        specs,
		ConsensusScore:     consensus,
		AgreedHypotheses:   hypotheses,
		ContestedViews:     contested,
		RecommendedAction:  "Execute CEGAR verification test inside tactical sandbox with operator approval",
		RequiresHumanGate:  requiresGate,
		ProposedRiskRating: proposedRisk,
	}
}
