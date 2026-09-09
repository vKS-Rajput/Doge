package ontology

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/dimension"
	"github.com/vKS-Rajput/doge/internal/synthesis"
	"github.com/vKS-Rajput/doge/pkg/ai"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// OntologyExpander manages dynamic expansion of DOGE's security concept knowledge.
type OntologyExpander struct {
	mu       sync.RWMutex
	router   *ai.ModelRouter
	concepts map[string]*SecurityConcept
}

// NewOntologyExpander creates an ontology expander powered by the ModelRouter.
func NewOntologyExpander(router *ai.ModelRouter) *OntologyExpander {
	return &OntologyExpander{
		router:   router,
		concepts: make(map[string]*SecurityConcept),
	}
}

// Expand mints a new SecurityConcept when an empirical boundary failure is validated
// along a previously unmodeled dimension.
func (e *OntologyExpander) Expand(
	ctx context.Context,
	dim *dimension.Dimension,
	pred *synthesis.SeparatingPredicate,
	severity domain.Severity,
	evidenceCount int,
) (*SecurityConcept, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if already expanded for this dimension
	for _, c := range e.concepts {
		if c.Dimension == dim.Name {
			c.EmpiricalEvidenceCount += evidenceCount
			return c, nil
		}
	}

	conceptName := dim.Name
	// Ask ModelRouter for concept naming & formalization if router available
	if e.router != nil {
		resp, err := e.router.Dispatch(ctx, ai.ReasoningRequest{
			TaskType: ai.TaskConceptNaming,
			Prompt: fmt.Sprintf(
				"Synthesize a formal security concept name for an empirical invariant violation along dimension '%s' with separating predicate '%s'",
				dim.Name, pred.Formula,
			),
		})
		if err == nil && resp != nil && strings.TrimSpace(resp.Content) != "" {
			conceptName = strings.TrimSpace(resp.Content)
		}
	}

	slug := strings.ToUpper(strings.ReplaceAll(conceptName, " ", "_"))
	conceptID := fmt.Sprintf("CONCEPT_%s_%s", slug, uuid.New().String()[:8])

	concept := &SecurityConcept{
		ConceptID:            conceptID,
		Name:                 conceptName,
		Dimension:            dim.Name,
		SeparatingPredicate:  pred.Formula,
		ViolationType:        string(dim.Type),
		Severity:             severity,
		ReproductionTemplate: strings.Join(pred.Reproduction, "\n"),
		Description:          fmt.Sprintf("Autonomously induced security concept along %s. Governed by predicate: %s", dim.Name, pred.Formula),
		LearnedAt:            time.Now().UTC(),
		EmpiricalEvidenceCount: evidenceCount,
	}

	e.concepts[conceptID] = concept
	return concept, nil
}

// GetConcepts returns all learned concepts.
func (e *OntologyExpander) GetConcepts() []*SecurityConcept {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]*SecurityConcept, 0, len(e.concepts))
	for _, c := range e.concepts {
		list = append(list, c)
	}
	return list
}

// ConceptCount returns total concepts.
func (e *OntologyExpander) ConceptCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.concepts)
}
