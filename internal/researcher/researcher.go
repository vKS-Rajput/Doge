// Package researcher defines the researcher interface and specialized researcher implementations.
//
// Each researcher is a short-lived, focused worker that receives a MissionBrief,
// executes bounded experiments, and returns structured MissionResult.
// Researchers are retired after each mission to prevent bias accumulation.
//
// Architecture (inspired by XBOW's short-lived focused agents):
//
//	Coordinator → MissionBrief → Researcher → MissionResult → Coordinator
package researcher

import (
	"context"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Researcher is the interface for all specialized research workers.
// Each implementation handles a specific domain of security research.
type Researcher interface {
	// Type returns the researcher type identifier.
	Type() domain.ResearcherType

	// Execute performs the research mission and returns structured results.
	// The researcher must operate within the constraints specified in the brief.
	Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error)
}

// HTTPClient is the interface for making controlled HTTP requests during experiments.
// It captures full request/response pairs as evidence.
type HTTPClient interface {
	// Do executes an HTTP request and captures the full evidence.
	Do(ctx context.Context, method, url string, headers map[string]string, body string) (*domain.ExperimentEvidence, error)
}

// researchPrincipal represents an identified identity during research.
type researchPrincipal struct {
	credName string
	token    string
	userID   string
	tenantID string
}
