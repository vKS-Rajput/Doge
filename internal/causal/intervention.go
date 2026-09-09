package causal

import (
	"math"
	"strings"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Intervention defines a specific hard Pearlian intervention do(X = value) along a candidate dimension.
type Intervention struct {
	TargetVariable string `json:"target_variable"` // e.g. "request_timing", "path_normalization", "header_order"
	Dimension      string `json:"dimension"`        // Associated latent dimension
	Parameter      string `json:"parameter"`        // Specific mutated parameter
	Value          any    `json:"value"`            // Intervened constant value
	Description    string `json:"description"`      // Human/AI-readable explanation of intervention
}

// CausalSurprise quantifies the empirical divergence between baseline and intervened outcomes.
// It explicitly weights discrete security-boundary shifts and directional asymmetry
// to prevent chasing benign network noise (the PCA variance trap).
type CausalSurprise struct {
	Dimension            string   `json:"dimension"`
	Magnitude            float64  `json:"magnitude"`             // Divergence score [0.0, 1.0]
	Asymmetry            float64  `json:"asymmetry"`             // Directional asymmetry [0.0, 1.0]
	AffectedOutputs      []string `json:"affected_outputs"`      // Output variables that diverged
	IsSignificant        bool     `json:"is_significant"`        // Exceeds statistical surprise threshold
	SecurityImplication  string   `json:"security_implication"`  // Explanatory breakdown if security invariant broke
	ViolatesConfidential bool     `json:"violates_confidential"` // Leaked cross-tenant or private data
	ViolatesIntegrity    bool     `json:"violates_integrity"`    // Corrupted state or unauthorized transition
}

// EvaluateCausalSurprise compares baseline and intervened execution traces along a specified dimension.
func EvaluateCausalSurprise(
	baselineStatus int,
	baselineBody string,
	baselineHeaders map[string]string,
	intervenedStatus int,
	intervenedBody string,
	intervenedHeaders map[string]string,
	dimension string,
) *CausalSurprise {
	surprise := &CausalSurprise{
		Dimension:       dimension,
		AffectedOutputs: make([]string, 0),
	}

	var statusDelta float64
	var bodyDelta float64
	var headerDelta float64

	// 1. Status Code Shift
	if baselineStatus != intervenedStatus {
		surprise.AffectedOutputs = append(surprise.AffectedOutputs, "http_status")
		// Critical authorization boundary shift (e.g. 401/403/409 -> 200 or vice versa)
		if (isDenial(baselineStatus) && intervenedStatus == 200) ||
			(baselineStatus == 200 && isDenial(intervenedStatus)) {
			statusDelta = 0.90
			surprise.Asymmetry = 1.0
			if intervenedStatus == 200 {
				surprise.ViolatesConfidential = true
				surprise.SecurityImplication = "Status shifted from denial to success under intervention (Authorization Boundary Breach)"
			}
		} else {
			statusDelta = 0.40
			surprise.Asymmetry = 0.70
		}
	}

	// 2. Response Body Divergence
	if baselineBody != intervenedBody {
		surprise.AffectedOutputs = append(surprise.AffectedOutputs, "response_body")
		// Check for sensitive token/data exposure
		lowerBody := strings.ToLower(intervenedBody)
		if strings.Contains(lowerBody, "secret") ||
			strings.Contains(lowerBody, "token") ||
			strings.Contains(lowerBody, "balance") ||
			strings.Contains(lowerBody, "private") ||
			strings.Contains(lowerBody, "confidential") {
			bodyDelta = 0.85
			surprise.ViolatesConfidential = true
			surprise.SecurityImplication = "Intervened response contains confidential payload missing from baseline"
		} else {
			// Levenshtein / length ratio
			diffLen := math.Abs(float64(len(intervenedBody) - len(baselineBody)))
			maxLen := math.Max(float64(len(baselineBody)), float64(len(intervenedBody)))
			if maxLen > 0 {
				bodyDelta = math.Min(1.0, diffLen/maxLen)
			}
		}
	}

	// 3. Header Divergence (e.g. Cache Hits, Set-Cookie, Invalidation)
	for k, v := range intervenedHeaders {
		baseVal := baselineHeaders[k]
		if baseVal != v {
			surprise.AffectedOutputs = append(surprise.AffectedOutputs, "header:"+strings.ToLower(k))
			if strings.EqualFold(k, "X-Cache") || strings.EqualFold(k, "CF-Cache-Status") {
				if strings.Contains(strings.ToUpper(v), "HIT") {
					headerDelta = 0.80
					surprise.SecurityImplication = "Cache hit differential observed under normalization transformation"
				}
			}
		}
	}

	// Combined magnitude with security weighting
	surprise.Magnitude = (statusDelta * 0.50) + (bodyDelta * 0.35) + (headerDelta * 0.15)
	if surprise.Magnitude > 1.0 {
		surprise.Magnitude = 1.0
	}

	// Statistical significance threshold: divergence > 0.40 and directional asymmetry > 0.50
	// This zeroes out symmetric jitter (random 500s or minor timing variations)
	if surprise.Magnitude >= 0.35 && (surprise.Asymmetry >= 0.50 || statusDelta > 0 || surprise.ViolatesConfidential) {
		surprise.IsSignificant = true
	}

	return surprise
}

// ConvertEvidenceToCausalVariables registers trace parameters as variables in an SCMGraph.
func ConvertEvidenceToCausalVariables(g *SCMGraph, prefix string, ev domain.ExperimentEvidence) {
	statusVar := prefix + "_status"
	g.AddVariable(statusVar, "HTTP Response Status", VariableObserved, ev.ResponseStatus)

	bodyVar := prefix + "_body_length"
	g.AddVariable(bodyVar, "HTTP Response Body Length", VariableObserved, len(ev.ResponseBody))

	g.AddEdge(statusVar, bodyVar, 0.70, "Status dictates body schema")
}

func isDenial(status int) bool {
	return status == 401 || status == 403 || status == 409 || status == 422
}
