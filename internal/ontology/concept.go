package ontology

import (
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// SecurityConcept represents an autonomously discovered and formalized security concept
// expanding DOGE's internal ontological representation.
type SecurityConcept struct {
	ConceptID            string          `json:"concept_id"`
	Name                 string          `json:"name"`
	Dimension            string          `json:"dimension"`
	SeparatingPredicate  string          `json:"separating_predicate"`
	ViolationType        string          `json:"violation_type"`
	Severity             domain.Severity `json:"severity"`
	ReproductionTemplate string          `json:"reproduction_template"`
	Description          string          `json:"description"`
	LearnedAt            time.Time       `json:"learned_at"`
	EmpiricalEvidenceCount int           `json:"empirical_evidence_count"`
}
