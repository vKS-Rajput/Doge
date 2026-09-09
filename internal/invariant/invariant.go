// Package invariant implements dynamic invariant induction for DOGE.
//
// Instead of relying purely on pre-compiled vulnerability checklists or static
// property templates, DOGE observes system behavior across execution traces,
// infers candidate invariants (algebraic, relational, and isolation properties),
// and actively designs experiments to test whether those invariants break.
//
// When an invariant is broken under anomalous conditions, the violation becomes
// an emergent security property without prior disclosure or template matching.
package invariant

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/property"
)

// InvariantType classifies the mathematical/behavioral domain of an invariant.
type InvariantType string

const (
	// InvariantContextIsolation: Execution context of operation A cannot leak to operation B.
	InvariantContextIsolation InvariantType = "context_isolation"

	// InvariantOrderCommutativity: Reordering independent operations preserves privilege boundaries.
	InvariantOrderCommutativity InvariantType = "order_commutativity"

	// InvariantIdempotency: Re-executing an operation does not escalate access.
	InvariantIdempotency InvariantType = "idempotency"

	// InvariantIdentityBinding: An operation executes strictly under its own identity claims.
	InvariantIdentityBinding InvariantType = "identity_binding"

	// InvariantStateConsistency: Successful status codes imply mandatory preconditions were met.
	InvariantStateConsistency InvariantType = "state_consistency"

	// InvariantScopeBoundary: Cross-domain or cross-tenant parameters cannot cross trust boundaries.
	InvariantScopeBoundary InvariantType = "scope_boundary"
)

// ExecutionTrace records an observed request/response interaction for invariant mining.
type ExecutionTrace struct {
	ID             uuid.UUID         `json:"id"`
	Endpoint       string            `json:"endpoint"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	ResponseStatus int               `json:"response_status"`
	ResponseBody   string            `json:"response_body,omitempty"`
	Principal      string            `json:"principal,omitempty"`
	SubOperations  []SubOpTrace      `json:"sub_operations,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
}

// SubOpTrace captures nested sub-operations in batched or pipelined requests.
type SubOpTrace struct {
	OpID           string            `json:"op_id"`
	Action         string            `json:"action"`
	Target         string            `json:"target"`
	Token          string            `json:"token,omitempty"`
	ResponseStatus int               `json:"response_status"`
	ResponseBody   string            `json:"response_body,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Invariant represents a dynamically inferred invariant about the target.
type Invariant struct {
	ID                    uuid.UUID               `json:"id"`
	Type                  InvariantType           `json:"type"`
	Statement             string                  `json:"statement"`
	Subject               string                  `json:"subject"`
	Precondition          string                  `json:"precondition"`
	ObservedSupportCount  int                     `json:"observed_support_count"`
	ContradictionCount    int                     `json:"contradiction_count"`
	Confidence            float64                 `json:"confidence"`
	State                 property.EpistemicState `json:"state"`
	EvidenceIDs           []uuid.UUID             `json:"evidence_ids,omitempty"`
	ViolationDescription  string                  `json:"violation_description,omitempty"`
	DiscoveredAt          time.Time               `json:"discovered_at"`
	UpdatedAt             time.Time               `json:"updated_at"`
}

// Validate checks that an invariant is well-formed.
func (inv *Invariant) Validate() error {
	if inv.Statement == "" {
		return fmt.Errorf("invariant statement cannot be empty")
	}
	if inv.Subject == "" {
		return fmt.Errorf("invariant subject cannot be empty")
	}
	return nil
}

// ToSecurityProperty converts an induced invariant into a testable SecurityProperty
// that DOGE's property evaluator and coordinator can reason about.
func (inv *Invariant) ToSecurityProperty() *property.SecurityProperty {
	class := property.ClassTrustBoundary
	switch inv.Type {
	case InvariantContextIsolation:
		class = property.ClassIsolation
	case InvariantIdentityBinding:
		class = property.ClassAuthorization
	case InvariantStateConsistency, InvariantOrderCommutativity:
		class = property.ClassWorkflowIntegrity
	case InvariantScopeBoundary:
		class = property.ClassTrustBoundary
	}

	return &property.SecurityProperty{
		ID:               inv.ID,
		Class:            class,
		Statement:        fmt.Sprintf("[Induced] %s", inv.Statement),
		Subject:          inv.Subject,
		SubjectType:      "induced_invariant",
		State:            inv.State,
		Confidence:       inv.Confidence,
		ViolationDetails: inv.ViolationDescription,
		Priority:         0.95, // High priority because it represents active behavioral discovery
		CreatedAt:        inv.DiscoveredAt,
		UpdatedAt:        inv.UpdatedAt,
	}
}
