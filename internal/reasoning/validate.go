package reasoning

import (
	"fmt"
	"strings"

	"github.com/vKS-Rajput/doge/pkg/ai"
)

// validCategories are the allowed ClaimCategory values.
var validCategories = map[ai.ClaimCategory]bool{
	ai.ClaimObserved:     true,
	ai.ClaimInferred:     true,
	ai.ClaimHypothetical: true,
}

// validateResponse performs domain validation on the model's response.
//
// This is NOT json.Unmarshal. Unmarshal only checks JSON syntax.
// This function checks semantic invariants:
//   - Answer field is non-empty
//   - Each claim has non-empty text
//   - Each claim has valid category (observed/inferred/hypothetical)
//   - Confidence is in [0.0, 1.0]
//   - Evidence IDs are non-empty strings
//   - No claim text is suspiciously long (possible prompt leak)
func validateResponse(r *Response) error {
	if strings.TrimSpace(r.Answer) == "" {
		return fmt.Errorf("answer field is empty")
	}

	// Reject suspiciously long answers (possible model dump).
	if len(r.Answer) > 10000 {
		return fmt.Errorf("answer exceeds maximum length (10000 chars)")
	}

	for i, claim := range r.Claims {
		prefix := fmt.Sprintf("claim[%d]", i)

		// Required: non-empty text.
		if strings.TrimSpace(claim.Text) == "" {
			return fmt.Errorf("%s: empty claim text", prefix)
		}

		// Max claim length guard.
		if len(claim.Text) > 2000 {
			return fmt.Errorf("%s: claim text exceeds 2000 chars", prefix)
		}

		// Confidence must be [0.0, 1.0].
		if claim.Confidence < 0.0 || claim.Confidence > 1.0 {
			return fmt.Errorf("%s: confidence %.2f is outside [0.0, 1.0]", prefix, claim.Confidence)
		}

		// Category must be a valid enum.
		if !validCategories[claim.Category] {
			return fmt.Errorf("%s: invalid category %q (must be observed/inferred/hypothetical)", prefix, claim.Category)
		}

		// Evidence IDs: each must be non-empty.
		for j, eid := range claim.EvidenceIDs {
			if strings.TrimSpace(eid) == "" {
				return fmt.Errorf("%s: evidence_ids[%d] is empty", prefix, j)
			}
		}
	}

	return nil
}
