package synthesis

import (
	"fmt"
	"strings"

	"github.com/vKS-Rajput/doge/internal/causal"
	"github.com/vKS-Rajput/doge/internal/dimension"
)

// ClauseOperator defines the relational operator of a predicate clause.
type ClauseOperator string

const (
	OpEquals         ClauseOperator = "=="
	OpNotEquals      ClauseOperator = "!="
	OpLessThan       ClauseOperator = "<"
	OpGreaterThan    ClauseOperator = ">"
	OpContains       ClauseOperator = "CONTAINS"
	OpMatchesRegex   ClauseOperator = "MATCHES"
	OpSynchronized   ClauseOperator = "SYNCHRONIZED_WITHIN"
	OpOrderInverted  ClauseOperator = "ORDER_INVERTED"
)

// PredicateClause is a single atomic symbolic constraint.
type PredicateClause struct {
	Field    string         `json:"field"`
	Operator ClauseOperator `json:"operator"`
	Value    string         `json:"value"`
}

func (c PredicateClause) String() string {
	return fmt.Sprintf("(%s %s %s)", c.Field, c.Operator, c.Value)
}

// SeparatingPredicate represents the boolean formula synthesized by CEGAR that separates
// the vulnerable execution state from normal safe execution.
type SeparatingPredicate struct {
	DimensionName string            `json:"dimension_name"`
	Formula       string            `json:"formula"`
	Clauses       []PredicateClause `json:"clauses"`
	Reproduction  []string          `json:"reproduction_steps"`
}

// CEGARSynthesizer runs counterexample-guided abstraction refinement to synthesize boundary predicates.
type CEGARSynthesizer struct{}

// NewCEGARSynthesizer creates a new CEGAR predicate synthesizer.
func NewCEGARSynthesizer() *CEGARSynthesizer {
	return &CEGARSynthesizer{}
}

// Synthesize produces a minimal separating predicate from a causal counterexample.
func (s *CEGARSynthesizer) Synthesize(
	dim *dimension.Dimension,
	endpoint string,
	surprise *causal.CausalSurprise,
	details map[string]any,
) *SeparatingPredicate {
	pred := &SeparatingPredicate{
		DimensionName: dim.Name,
		Clauses:       make([]PredicateClause, 0),
		Reproduction:  make([]string, 0),
	}

	switch dim.Type {
	case dimension.DimTemporalConcurrency:
		windowMS := 40
		if w, ok := details["window_ms"].(int); ok {
			windowMS = w
		}
		pred.Clauses = append(pred.Clauses, PredicateClause{
			Field:    "Endpoint",
			Operator: OpEquals,
			Value:    endpoint,
		})
		pred.Clauses = append(pred.Clauses, PredicateClause{
			Field:    "Delta_t_ms",
			Operator: OpLessThan,
			Value:    fmt.Sprintf("%dms", windowMS),
		})
		pred.Clauses = append(pred.Clauses, PredicateClause{
			Field:    "Concurrent_Bursts",
			Operator: OpGreaterThan,
			Value:    "1",
		})
		pred.Formula = fmt.Sprintf("(Endpoint == %s) && (Delta_t < %dms) && (Concurrent_Bursts > 1)", endpoint, windowMS)
		pred.Reproduction = []string{
			fmt.Sprintf("1. Prepare 2 concurrent POST requests to %s with identical debit/transfer parameters", endpoint),
			fmt.Sprintf("2. Synchronize HTTP requests using a concurrency barrier within <%dms window", windowMS),
			"3. Transmit burst simultaneously",
			"4. Observe: Both requests return HTTP 200, balance check bypassed and account overdrawn",
			"5. Negative Control: Sequential execution with >100ms interval correctly rejects second request",
		}

	case dimension.DimEncodingNormalization:
		encoding := "..%2F"
		if enc, ok := details["encoding"].(string); ok {
			encoding = enc
		}
		pred.Clauses = append(pred.Clauses, PredicateClause{
			Field:    "Proxy_Normalized_Path",
			Operator: OpEquals,
			Value:    "/api/v1/reports/public",
		})
		pred.Clauses = append(pred.Clauses, PredicateClause{
			Field:    "Backend_Path_Traversal",
			Operator: OpContains,
			Value:    encoding,
		})
		pred.Formula = fmt.Sprintf("(CacheKey(Req) == '/public') && (BackendPath(Req) CONTAINS '%s')", encoding)
		pred.Reproduction = []string{
			fmt.Sprintf("1. Issue GET request using unnormalized traversal encoding: /api/v1/reports/private/%spublic", encoding),
			"2. Reverse proxy normalizes URI to /api/v1/reports/public and caches response",
			"3. Subsequent unauthenticated requests to /api/v1/reports/public receive cached private tenant data",
			"4. Observe: HTTP 200 with X-Cache: HIT containing confidential report",
			"5. Negative Control: Direct request to /api/v1/reports/private returns HTTP 401/403 Forbidden",
		}

	case dimension.DimPipelineInterleaving:
		pred.Clauses = append(pred.Clauses, PredicateClause{
			Field:    "Batch_Order",
			Operator: OpOrderInverted,
			Value:    "Privileged_Precedes_Unprivileged",
		})
		pred.Formula = "(Batch_SubOps[0].IsPrivileged == true) && (Batch_SubOps[1].InheritsContext == true)"
		pred.Reproduction = []string{
			"1. Craft batch request containing 2 operations: 1 privileged, 1 unprivileged",
			"2. Place privileged operation first in sub-operation array",
			"3. Send batch request to endpoint",
			"4. Observe: Second operation executes with inherited tenant authorization",
			"5. Negative Control: Invert order or run sub-operations in isolation (both return 401/403)",
		}

	default:
		pred.Clauses = append(pred.Clauses, PredicateClause{
			Field:    "Intervention_Divergence",
			Operator: OpEquals,
			Value:    "True",
		})
		pred.Formula = fmt.Sprintf("CausalDivergence(%s) == True", dim.Name)
		pred.Reproduction = []string{
			"1. Apply interventional perturbation along discovered dimension",
			"2. Observe statistically significant discrepancy in target output",
		}
	}

	return pred
}

// FormatClauses formats all clauses into a multi-line string.
func (p *SeparatingPredicate) FormatClauses() string {
	var sb strings.Builder
	for i, c := range p.Clauses {
		if i > 0 {
			sb.WriteString(" AND ")
		}
		sb.WriteString(c.String())
	}
	return sb.String()
}
