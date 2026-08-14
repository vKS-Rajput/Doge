package validation

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// CaptureResult converts an execution result into an immutable
// Observation that re-enters the evidence pipeline.
//
// The observation has full provenance: links to plan, hypothesis,
// action type, and safety class. Tagged SourceTool: "doge-validation"
// so it is distinguishable from external tool output.
func CaptureResult(result ActionResult, projectID uuid.UUID) domain.RawObservation {
	data := map[string]any{
		"action_type":    string(result.Action.Type),
		"method":         result.Action.Method,
		"target":         result.Action.Target,
		"path":           result.Action.Path,
		"plan_id":        result.Action.PlanID.String(),
		"hypothesis_id":  result.Action.HypothesisID.String(),
		"safety_class":   string(result.Action.SafetyClass),
		"expected":       result.Action.ExpectedResult,
	}

	if result.Action.CredentialProfileID != "" {
		// Store role reference, NOT the credential itself.
		data["credential_role"] = result.Action.CredentialProfileID
	}

	if result.Result != nil {
		data["status_code"] = result.Result.StatusCode
		data["body_hash"] = result.Result.BodyHash
		data["body_size"] = result.Result.BodySize
		data["duration_ms"] = result.Result.Duration.Milliseconds()
		data["response_headers"] = result.Result.Headers
	}

	if result.Error != nil {
		data["error"] = result.Error.Error()
	}

	rawValue := formatRawValue(result)

	return domain.RawObservation{
		Type:       observationType(result.Action.Type),
		SourceTool: "doge-validation",
		Data:       data,
		RawValue:   rawValue,
		ObservedAt: result.ExecutedAt,
	}
}

// observationType maps action types to observation types.
func observationType(action ActionType) domain.ObservationType {
	switch action {
	case ActionRoleCompare:
		return domain.ObservationAuthProbe
	case ActionHeaderCheck:
		return domain.ObservationHTTPProbe
	case ActionEndpointProbe:
		return domain.ObservationEndpointDiscovery
	default:
		return domain.ObservationHTTPProbe
	}
}

func formatRawValue(result ActionResult) string {
	if result.Result != nil {
		return fmt.Sprintf("%s %s%s → %d (%dms)",
			result.Action.Method, result.Action.Target, result.Action.Path,
			result.Result.StatusCode, result.Result.Duration.Milliseconds())
	}
	if result.Error != nil {
		return fmt.Sprintf("%s %s%s → ERROR: %s",
			result.Action.Method, result.Action.Target, result.Action.Path,
			result.Error.Error())
	}
	return fmt.Sprintf("%s %s%s → (no result)",
		result.Action.Method, result.Action.Target, result.Action.Path)
}
