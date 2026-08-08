// Package reasoning provides the Reasoning Engine.
//
// All shared types (Response, Claim, VerificationStatus, etc.)
// live in pkg/ai to avoid import cycles between reasoning
// and verification packages.
package reasoning

import "github.com/vKS-Rajput/doge/pkg/ai"

// Re-export types from pkg/ai for convenience.
type (
	Response           = ai.Response
	Claim              = ai.Claim
	ClaimCategory      = ai.ClaimCategory
	VerificationStatus = ai.VerificationStatus
	VerificationResult = ai.VerificationResult
	VerifiedResponse   = ai.VerifiedResponse
	VerifiedClaim      = ai.VerifiedClaim
	ReasoningError     = ai.ReasoningError
	ModelMetrics       = ai.ModelMetrics
)

// Re-export constants.
const (
	ClaimObserved     = ai.ClaimObserved
	ClaimInferred     = ai.ClaimInferred
	ClaimHypothetical = ai.ClaimHypothetical

	StatusSupported          = ai.StatusSupported
	StatusPartiallySupported = ai.StatusPartiallySupported
	StatusUnsupported        = ai.StatusUnsupported
	StatusContradicted       = ai.StatusContradicted
	StatusUnverifiable       = ai.StatusUnverifiable
)
