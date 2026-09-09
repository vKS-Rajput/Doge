// Package property defines security properties as testable assertions
// about a target system. DOGE reasons about properties, not vulnerability
// classes. Vulnerabilities become: violations of security properties.
//
// This makes DOGE more general than a vulnerability scanner.
//
// A security property is a statement like:
//
//	"Only authorized users can access resource X"
//	"Tenant A cannot access Tenant B's resources"
//	"Workflow transitions cannot be skipped"
//
// DOGE tests whether these properties hold. When a property is violated,
// that violation IS the vulnerability — regardless of whether it matches
// a known CWE or vulnerability class.
package property

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PropertyClass categorizes the domain of a security property.
type PropertyClass string

const (
	// ClassAuthorization — access control properties.
	// "Only authorized principals can access resource X."
	ClassAuthorization PropertyClass = "authorization"

	// ClassIsolation — tenant/principal boundary properties.
	// "Tenant A cannot access Tenant B's resources."
	ClassIsolation PropertyClass = "isolation"

	// ClassWorkflowIntegrity — state machine and workflow properties.
	// "Workflow transitions cannot be skipped."
	ClassWorkflowIntegrity PropertyClass = "workflow_integrity"

	// ClassInputValidation — input handling properties.
	// "Untrusted input cannot influence privileged operations."
	ClassInputValidation PropertyClass = "input_validation"

	// ClassSecretContainment — secret handling properties.
	// "Secrets cannot escape their intended context."
	ClassSecretContainment PropertyClass = "secret_containment"

	// ClassTrustBoundary — trust boundary properties.
	// "Sensitive data cannot cross trust boundaries."
	ClassTrustBoundary PropertyClass = "trust_boundary"

	// ClassAuthentication — identity verification properties.
	// "Authentication state cannot be confused."
	ClassAuthentication PropertyClass = "authentication"

	// ClassSessionIntegrity — session handling properties.
	// "A session cannot be reused outside its intended boundary."
	ClassSessionIntegrity PropertyClass = "session_integrity"

	// ClassPrivilegeContainment — privilege escalation properties.
	// "A user cannot escalate privileges."
	ClassPrivilegeContainment PropertyClass = "privilege_containment"

	// ClassServerSideSafety — SSRF and server-side properties.
	// "External resources cannot be reached through unauthorized server-side primitives."
	ClassServerSideSafety PropertyClass = "server_side_safety"
)

// EpistemicState represents what DOGE knows about whether a property holds.
type EpistemicState string

const (
	// StateUnknown — DOGE has not yet tested this property.
	StateUnknown EpistemicState = "unknown"

	// StateAssumed — DOGE assumes this property holds (no evidence yet).
	StateAssumed EpistemicState = "assumed"

	// StateSupported — Evidence supports that this property holds.
	StateSupported EpistemicState = "supported"

	// StateContradicted — Evidence contradicts this property.
	StateContradicted EpistemicState = "contradicted"

	// StateUntested — DOGE knows this property is relevant but has not tested it.
	StateUntested EpistemicState = "untested"

	// StatePartiallyTested — Some experiments have been run, but coverage is incomplete.
	StatePartiallyTested EpistemicState = "partially_tested"

	// StateValidated — Independent validation confirmed the property status.
	StateValidated EpistemicState = "validated"

	// StateViolated — The property has been proven to NOT hold.
	StateViolated EpistemicState = "violated"
)

// SecurityProperty is a testable assertion about the security of a target system.
//
// Properties are NOT vulnerability descriptions. They are statements about
// what SHOULD be true. When DOGE proves a property is violated, the
// violation is the vulnerability.
type SecurityProperty struct {
	// ID uniquely identifies this property instance.
	ID uuid.UUID `json:"id"`

	// Class categorizes the security domain.
	Class PropertyClass `json:"class"`

	// Statement is the natural language assertion.
	// Example: "Only authenticated users can access /api/v1/items/{id}"
	Statement string `json:"statement"`

	// Subject is what entity/resource this property applies to.
	// Example: "/api/v1/items/{id}", "user-alice-001", "checkout workflow"
	Subject string `json:"subject"`

	// SubjectType classifies the subject.
	// Example: "endpoint", "principal", "workflow", "parameter"
	SubjectType string `json:"subject_type"`

	// State is the current epistemic state of this property.
	State EpistemicState `json:"state"`

	// Confidence in the current state (0.0 to 1.0).
	Confidence float64 `json:"confidence"`

	// TestedBy lists the experiment/mission IDs that have tested this property.
	TestedBy []uuid.UUID `json:"tested_by,omitempty"`

	// Evidence lists evidence IDs supporting the current state.
	Evidence []uuid.UUID `json:"evidence,omitempty"`

	// ViolationDetails describes how the property was violated, if applicable.
	ViolationDetails string `json:"violation_details,omitempty"`

	// Priority indicates how important this property is to test.
	// Higher = more important. Influenced by: security impact, information gain.
	Priority float64 `json:"priority"`

	// DependsOn lists property IDs that must be evaluated first.
	DependsOn []uuid.UUID `json:"depends_on,omitempty"`

	// CreatedAt is when this property was first identified.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the state was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// PropertyTestResult is the outcome of testing a security property.
type PropertyTestResult struct {
	// PropertyID identifies which property was tested.
	PropertyID uuid.UUID `json:"property_id"`

	// MissionID identifies which mission performed the test.
	MissionID uuid.UUID `json:"mission_id"`

	// Holds is true if the property was confirmed to hold.
	Holds bool `json:"holds"`

	// Confidence in this result.
	Confidence float64 `json:"confidence"`

	// Evidence supporting this result.
	Evidence []uuid.UUID `json:"evidence"`

	// Details describes what was observed.
	Details string `json:"details"`

	// TestedAt is when the test was performed.
	TestedAt time.Time `json:"tested_at"`
}

// Validate checks that a SecurityProperty is well-formed.
func (p *SecurityProperty) Validate() error {
	if p.Statement == "" {
		return fmt.Errorf("property statement is empty")
	}
	if p.Class == "" {
		return fmt.Errorf("property class is empty")
	}
	if p.Subject == "" {
		return fmt.Errorf("property subject is empty")
	}
	return nil
}

// IsTestable returns true if this property can be tested (not already validated/violated with high confidence).
func (p *SecurityProperty) IsTestable() bool {
	switch p.State {
	case StateValidated:
		return false // Already confirmed
	case StateViolated:
		return p.Confidence < 0.95 // Re-test if low confidence violation
	default:
		return true
	}
}

// InformationGain estimates how much testing this property would reduce uncertainty.
// Higher values mean more information would be gained.
func (p *SecurityProperty) InformationGain() float64 {
	switch p.State {
	case StateUnknown:
		return 1.0 * p.Priority // Maximum gain — we know nothing
	case StateAssumed:
		return 0.9 * p.Priority // High gain — assumption needs testing
	case StateUntested:
		return 0.85 * p.Priority // High gain — known untested
	case StatePartiallyTested:
		return 0.5 * (1.0 - p.Confidence) * p.Priority // Proportional to remaining uncertainty
	case StateSupported:
		return 0.3 * (1.0 - p.Confidence) * p.Priority // Low but nonzero — could be wrong
	case StateContradicted:
		return 0.7 * p.Priority // High — need to confirm or reject
	case StateViolated:
		return 0.1 * (1.0 - p.Confidence) * p.Priority // Very low — mostly known
	case StateValidated:
		return 0.0 // Zero — independently confirmed
	default:
		return 0.5 * p.Priority
	}
}

// ApplyTestResult updates the property state based on a test result.
func (p *SecurityProperty) ApplyTestResult(result PropertyTestResult) {
	p.TestedBy = append(p.TestedBy, result.MissionID)
	p.Evidence = append(p.Evidence, result.Evidence...)
	p.UpdatedAt = result.TestedAt

	if result.Holds {
		switch p.State {
		case StateUnknown, StateAssumed, StateUntested:
			p.State = StateSupported
			p.Confidence = result.Confidence
		case StatePartiallyTested:
			p.State = StateSupported
			p.Confidence = (p.Confidence + result.Confidence) / 2
		case StateSupported:
			// Increase confidence with corroborating evidence
			p.Confidence = 1.0 - (1.0-p.Confidence)*(1.0-result.Confidence)
		case StateContradicted:
			// Conflicting evidence — needs more research
			p.State = StatePartiallyTested
			p.Confidence = 0.5
		}
	} else {
		p.ViolationDetails = result.Details
		switch p.State {
		case StateUnknown, StateAssumed, StateUntested:
			p.State = StateContradicted
			p.Confidence = result.Confidence
		case StatePartiallyTested:
			p.State = StateContradicted
			p.Confidence = result.Confidence
		case StateSupported:
			// Previously supported, now contradicted
			p.State = StateContradicted
			p.Confidence = result.Confidence
		case StateContradicted:
			// Additional contradiction — increase confidence
			p.Confidence = 1.0 - (1.0-p.Confidence)*(1.0-result.Confidence)
			if p.Confidence >= 0.9 {
				p.State = StateViolated
			}
		case StateViolated:
			p.Confidence = 1.0 - (1.0-p.Confidence)*(1.0-result.Confidence)
		}
	}
}
