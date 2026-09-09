package hypothesis

import (
	"strings"
	"time"
)

// EvaluationResult summarizes the epistemic outcome of testing a hypothesis.
type EvaluationResult struct {
	PreviousStatus EpistemicStatus `json:"previous_status"`
	NewStatus      EpistemicStatus `json:"new_status"`
	ConfidenceOld  float64         `json:"confidence_old"`
	ConfidenceNew  float64         `json:"confidence_new"`
	Reason         string          `json:"reason"`
	IsFalsified    bool            `json:"is_falsified"`
	IsConfirmed    bool            `json:"is_confirmed"`
	EvaluatedAt    time.Time       `json:"evaluated_at"`
}

// EvaluateExecution analyzes stdout, stderr, and exit codes against hypothesis falsification and confirmation criteria.
func EvaluateExecution(hyp *ResearchHypothesis, stdout, stderr string, exitCode int) EvaluationResult {
	now := time.Now().UTC()
	res := EvaluationResult{
		PreviousStatus: hyp.Status,
		ConfidenceOld:  hyp.Confidence,
		EvaluatedAt:    now,
	}

	combinedOutput := strings.ToLower(stdout + "\n" + stderr)
	hyp.EvaluationCount++
	hyp.LastEvaluatedAt = now

	switch hyp.Category {
	case CatBOLA:
		// Refutation: 403 Forbidden, 401 Unauthorized, or 404 Not Found enforcing tenant boundary
		if strings.Contains(combinedOutput, "403 forbidden") ||
			strings.Contains(combinedOutput, "403") ||
			strings.Contains(combinedOutput, "access denied") ||
			strings.Contains(combinedOutput, "tenant mismatch") ||
			strings.Contains(combinedOutput, "unauthorized access to object") {
			hyp.Status = StatusRejected
			hyp.ContradictionCount++
			hyp.Confidence = 0.0
			hyp.RejectedAt = &now
			res.NewStatus = StatusRejected
			res.ConfidenceNew = 0.0
			res.IsFalsified = true
			res.Reason = "Refuted by server access control: 403 Forbidden enforcing strict tenant boundary"
			return res
		}

		// Confirmation: 200 OK with cross-tenant private data
		if (strings.Contains(combinedOutput, "200 ok") || strings.Contains(combinedOutput, "200")) &&
			(strings.Contains(combinedOutput, "email") || strings.Contains(combinedOutput, "account") || strings.Contains(combinedOutput, "private_data") || strings.Contains(combinedOutput, "user_b")) {
			hyp.Status = StatusConfirmed
			hyp.Tier = TierValidatedFinding
			hyp.Confidence = 1.0
			hyp.ConfirmedAt = &now
			res.NewStatus = StatusConfirmed
			res.ConfidenceNew = 1.0
			res.IsConfirmed = true
			res.Reason = "Confirmed: Received HTTP 200 containing unauthorized tenant data"
			return res
		}

		// Generic 200 OK without explicit private data match
		if strings.Contains(combinedOutput, "200") {
			hyp.Status = StatusSupported
			hyp.Tier = TierCandidateFinding
			hyp.RecalculateConfidence(true)
			res.NewStatus = StatusSupported
			res.ConfidenceNew = hyp.Confidence
			res.Reason = "Supported: Endpoint accessible with test context"
			return res
		}

	case CatSSRF:
		// Confirmation: Out-of-band interaction observed
		if strings.Contains(combinedOutput, "dns callback received") ||
			strings.Contains(combinedOutput, "http interaction received") ||
			strings.Contains(combinedOutput, "oob_interaction_confirmed") ||
			strings.Contains(combinedOutput, "callback_success") {
			hyp.Status = StatusConfirmed
			hyp.Tier = TierValidatedFinding
			hyp.Confidence = 0.95
			hyp.ConfirmedAt = &now
			res.NewStatus = StatusConfirmed
			res.ConfidenceNew = 0.95
			res.IsConfirmed = true
			res.Reason = "Confirmed: Out-of-band interaction detected from target infrastructure"
			return res
		}

		// Refutation: Strict whitelist or domain rejected
		if strings.Contains(combinedOutput, "invalid host") ||
			strings.Contains(combinedOutput, "domain not allowed") ||
			strings.Contains(combinedOutput, "whitelist_error") ||
			strings.Contains(combinedOutput, "egress blocked") {
			hyp.Status = StatusRejected
			hyp.ContradictionCount++
			hyp.Confidence = 0.0
			hyp.RejectedAt = &now
			res.NewStatus = StatusRejected
			res.ConfidenceNew = 0.0
			res.IsFalsified = true
			res.Reason = "Refuted: Target enforces strict URL whitelist or blocks remote egress"
			return res
		}

		// Supporting: parameter accepted
		if strings.Contains(combinedOutput, "200") || strings.Contains(combinedOutput, "accepted") {
			hyp.Status = StatusSupported
			hyp.Tier = TierCandidateFinding
			hyp.RecalculateConfidence(true)
			res.NewStatus = StatusSupported
			res.ConfidenceNew = hyp.Confidence
			res.Reason = "Supported: Server accepted destination parameter"
			return res
		}

	case CatAuthBoundary, CatPrivilegeEsc:
		if strings.Contains(combinedOutput, "401") || strings.Contains(combinedOutput, "403") || strings.Contains(combinedOutput, "302") || strings.Contains(combinedOutput, "login required") || strings.Contains(combinedOutput, "forbidden") || strings.Contains(combinedOutput, "mfa required") {
			hyp.Status = StatusRejected
			hyp.ContradictionCount++
			hyp.Confidence = 0.0
			hyp.RejectedAt = &now
			res.NewStatus = StatusRejected
			res.ConfidenceNew = 0.0
			res.IsFalsified = true
			res.Reason = "Refuted: Authentication/authorization boundary strictly enforced by gateway"
			return res
		}

		if strings.Contains(combinedOutput, "200 ok") && (strings.Contains(combinedOutput, "admin") || strings.Contains(combinedOutput, "dashboard")) {
			hyp.Status = StatusConfirmed
			hyp.Tier = TierValidatedFinding
			hyp.Confidence = 0.95
			res.NewStatus = StatusConfirmed
			res.ConfidenceNew = 0.95
			res.IsConfirmed = true
			res.Reason = "Confirmed: Administrative surface accessible without required credentials"
			return res
		}

	case CatNovelAnomaly, CatInjection:
		if strings.Contains(combinedOutput, "unescaped") || strings.Contains(combinedOutput, "reflection_detected") || strings.Contains(combinedOutput, "<script>") {
			hyp.Status = StatusSupported
			hyp.Tier = TierCandidateFinding
			hyp.RecalculateConfidence(true)
			res.NewStatus = StatusSupported
			res.ConfidenceNew = hyp.Confidence
			res.Reason = "Supported: Unencoded parameter reflection observed in response body"
			return res
		}

		if strings.Contains(combinedOutput, "encoded") || strings.Contains(combinedOutput, "sanitized") {
			hyp.Status = StatusRejected
			hyp.ContradictionCount++
			hyp.Confidence = 0.0
			res.NewStatus = StatusRejected
			res.ConfidenceNew = 0.0
			res.IsFalsified = true
			res.Reason = "Refuted: Output is safely HTML/JSON encoded by server framework"
			return res
		}
	}

	// Default evaluation fallback
	if exitCode == 0 && (strings.Contains(combinedOutput, "200") || strings.Contains(combinedOutput, "found")) {
		hyp.RecalculateConfidence(true)
		res.NewStatus = hyp.Status
		res.ConfidenceNew = hyp.Confidence
		res.Reason = "Observed supporting execution output"
	} else {
		hyp.RecalculateConfidence(false)
		res.NewStatus = hyp.Status
		res.ConfidenceNew = hyp.Confidence
		res.Reason = "No confirming evidence observed; confidence decayed"
	}

	return res
}
