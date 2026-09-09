package property

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Catalog provides property templates and generators for common security properties.
// These are not vulnerability checks; they are formal security assertions that DOGE
// evaluates against the target system.
type Catalog struct{}

// NewCatalog creates a new property catalog instance.
func NewCatalog() *Catalog {
	return &Catalog{}
}

// GenerateForEndpoint generates core security properties for a discovered endpoint.
func (c *Catalog) GenerateForEndpoint(endpoint string) []*SecurityProperty {
	now := time.Now().UTC()
	return []*SecurityProperty{
		{
			ID:          uuid.New(),
			Class:       ClassAuthentication,
			Statement:   fmt.Sprintf("Endpoint %s requires valid authentication for access", endpoint),
			Subject:     endpoint,
			SubjectType: "endpoint",
			State:       StateUntested,
			Confidence:  0.5,
			Priority:    0.8,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New(),
			Class:       ClassAuthorization,
			Statement:   fmt.Sprintf("Only authorized principals can access resources on %s", endpoint),
			Subject:     endpoint,
			SubjectType: "endpoint",
			State:       StateUntested,
			Confidence:  0.5,
			Priority:    0.9,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New(),
			Class:       ClassIsolation,
			Statement:   fmt.Sprintf("Requests to %s cannot access resources belonging to other tenants", endpoint),
			Subject:     endpoint,
			SubjectType: "endpoint",
			State:       StateUntested,
			Confidence:  0.5,
			Priority:    0.95,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New(),
			Class:       ClassInputValidation,
			Statement:   fmt.Sprintf("Endpoint %s validates parameter types and bounds", endpoint),
			Subject:     endpoint,
			SubjectType: "endpoint",
			State:       StateUntested,
			Confidence:  0.5,
			Priority:    0.6,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
}

// GenerateForWorkflow generates workflow integrity properties for a state machine.
func (c *Catalog) GenerateForWorkflow(workflowName string, states []string) []*SecurityProperty {
	now := time.Now().UTC()
	var props []*SecurityProperty

	props = append(props, &SecurityProperty{
		ID:          uuid.New(),
		Class:       ClassWorkflowIntegrity,
		Statement:   fmt.Sprintf("Workflow %s transitions must proceed through mandatory intermediate states", workflowName),
		Subject:     workflowName,
		SubjectType: "workflow",
		State:       StateUntested,
		Confidence:  0.5,
		Priority:    0.95,
		CreatedAt:   now,
		UpdatedAt:   now,
	})

	if len(states) >= 3 {
		props = append(props, &SecurityProperty{
			ID:          uuid.New(),
			Class:       ClassWorkflowIntegrity,
			Statement:   fmt.Sprintf("Workflow %s terminal state %s cannot be reached directly without payment/completion", workflowName, states[len(states)-1]),
			Subject:     workflowName,
			SubjectType: "workflow",
			State:       StateUntested,
			Confidence:  0.5,
			Priority:    0.9,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
	}

	return props
}

// GenerateForIsolation generates multi-tenant boundary properties.
func (c *Catalog) GenerateForIsolation(tenantA, tenantB, resourceType string) []*SecurityProperty {
	now := time.Now().UTC()
	return []*SecurityProperty{
		{
			ID:          uuid.New(),
			Class:       ClassIsolation,
			Statement:   fmt.Sprintf("Tenant %s cannot read %s belonging to tenant %s", tenantA, resourceType, tenantB),
			Subject:     fmt.Sprintf("%s:%s", tenantA, tenantB),
			SubjectType: "tenant_pair",
			State:       StateUntested,
			Confidence:  0.5,
			Priority:    0.95,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New(),
			Class:       ClassIsolation,
			Statement:   fmt.Sprintf("Tenant %s cannot modify %s belonging to tenant %s", tenantA, resourceType, tenantB),
			Subject:     fmt.Sprintf("%s:%s", tenantA, tenantB),
			SubjectType: "tenant_pair",
			State:       StateUntested,
			Confidence:  0.5,
			Priority:    0.95,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
}

// GenerateForSecrets generates secret containment properties.
func (c *Catalog) GenerateForSecrets(endpoint string) []*SecurityProperty {
	now := time.Now().UTC()
	return []*SecurityProperty{
		{
			ID:          uuid.New(),
			Class:       ClassSecretContainment,
			Statement:   fmt.Sprintf("Endpoint %s does not leak credentials, tokens, or secret keys in response bodies or headers", endpoint),
			Subject:     endpoint,
			SubjectType: "endpoint",
			State:       StateUntested,
			Confidence:  0.5,
			Priority:    0.85,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
}
