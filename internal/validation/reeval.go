package validation

import (
	"github.com/vKS-Rajput/doge/internal/reasoning"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ReEvaluationResult is the outcome of re-evaluating a hypothesis
// after validation execution.
type ReEvaluationResult struct {
	// PreviousStatus is the hypothesis status before re-evaluation.
	PreviousStatus domain.HypothesisStatus `json:"previous_status"`

	// RecommendedStatus is what DOGE recommends based on evidence.
	RecommendedStatus domain.HypothesisStatus `json:"recommended_status"`

	// PreviousConfidence is the confidence before re-evaluation.
	PreviousConfidence float64 `json:"previous_confidence"`

	// NewConfidence is the recalculated confidence.
	NewConfidence float64 `json:"new_confidence"`

	// Reason explains why the status/confidence changed.
	Reason string `json:"reason"`

	// RequiresHumanReview is ALWAYS true in v0.9.5.
	// The human decides whether to accept the recommendation.
	RequiresHumanReview bool `json:"requires_human_review"`

	// ConfirmationSignals are validation results matching confirmation criteria.
	ConfirmationSignals int `json:"confirmation_signals"`

	// RefutationSignals are validation results matching refutation criteria.
	RefutationSignals int `json:"refutation_signals"`

	// TotalResults is the total number of validation results analyzed.
	TotalResults int `json:"total_results"`
}

// ReEvaluate updates hypothesis status based on validation results.
//
// This does an immediate deterministic check: do the validation
// results match confirmation or refutation criteria?
//
// The full AI re-evaluation (feeding observations back through
// correlation → novelty → opportunity → reasoning) happens
// asynchronously through the existing pipeline.
func ReEvaluate(
	hypothesis *domain.Hypothesis,
	results []ActionResult,
	tracker *reasoning.HypothesisTracker,
) ReEvaluationResult {
	eval := ReEvaluationResult{
		PreviousStatus:     hypothesis.Status,
		PreviousConfidence: hypothesis.Confidence,
		RequiresHumanReview: true, // ALWAYS true in v0.9.5
		TotalResults:       len(results),
	}

	// Count signals from validation results.
	var successCount, errorCount, accessDenied, accessGranted int
	for _, r := range results {
		if r.Error != nil {
			errorCount++
			continue
		}
		if r.Result == nil {
			continue
		}

		switch {
		case r.Result.StatusCode >= 200 && r.Result.StatusCode < 300:
			accessGranted++
		case r.Result.StatusCode == 401 || r.Result.StatusCode == 403:
			accessDenied++
		case r.Result.StatusCode >= 400:
			errorCount++
		}
		successCount++
	}

	// Determine signals.
	// For authorization testing: access granted where denied was expected
	// is a confirmation signal. Access denied is refutation.
	if accessGranted > 0 {
		eval.ConfirmationSignals = accessGranted
	}
	if accessDenied > 0 {
		eval.RefutationSignals = accessDenied
	}

	// Update tracker.
	if tracker != nil {
		if eval.RefutationSignals > eval.ConfirmationSignals {
			tracker.ContradictionCount++
		}
		if eval.ConfirmationSignals > 0 {
			tracker.EvaluationCount = 0 // Reset decay — new supporting evidence.
		} else {
			tracker.EvaluationCount++
		}
	}

	// Recalculate confidence.
	if tracker != nil {
		eval.NewConfidence = reasoning.RecalculateConfidence(
			hypothesis.Confidence, *tracker)
	} else {
		eval.NewConfidence = hypothesis.Confidence
	}

	// Recommend status.
	switch {
	case eval.RefutationSignals > 0 && eval.ConfirmationSignals == 0:
		eval.RecommendedStatus = domain.HypothesisRejected
		eval.Reason = "Validation results consistently match refutation criteria. " +
			"Authorization appears to be enforced."
	case eval.ConfirmationSignals > 0 && eval.RefutationSignals == 0:
		eval.RecommendedStatus = domain.HypothesisInvestigating
		eval.Reason = "Validation results match confirmation criteria. " +
			"Further investigation recommended."
	case eval.ConfirmationSignals > 0 && eval.RefutationSignals > 0:
		eval.RecommendedStatus = domain.HypothesisInconclusive
		eval.Reason = "Mixed signals: some results confirm, others refute. " +
			"Additional evidence needed."
	case errorCount == len(results):
		eval.RecommendedStatus = hypothesis.Status // No change.
		eval.Reason = "All validation requests failed. " +
			"Cannot determine hypothesis status."
	default:
		eval.RecommendedStatus = hypothesis.Status
		eval.Reason = "Insufficient signal to update hypothesis status."
	}

	return eval
}
