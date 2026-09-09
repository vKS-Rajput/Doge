package ontology

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/internal/dimension"
	"github.com/vKS-Rajput/doge/internal/synthesis"
	"github.com/vKS-Rajput/doge/pkg/ai"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestOntologyExpander_Expand(t *testing.T) {
	router := ai.NewModelRouter("deterministic_brain")
	router.RegisterProvider(ai.NewDeterministicModel())

	expander := NewOntologyExpander(router)
	ctx := context.Background()

	dim := &dimension.Dimension{
		Type: dimension.DimTemporalConcurrency,
		Name: "Temporal Concurrency Interleaving",
	}

	pred := &synthesis.SeparatingPredicate{
		DimensionName: dim.Name,
		Formula:       "(Endpoint == '/api/v1/wallet/transfer') && (Delta_t < 40ms)",
		Reproduction:  []string{"Step 1: Burst 2 concurrent requests"},
	}

	concept, err := expander.Expand(ctx, dim, pred, domain.SeverityCritical, 10)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}

	if !strings.Contains(concept.ConceptID, "CONCEPT_") {
		t.Errorf("expected concept ID to have prefix CONCEPT_, got %s", concept.ConceptID)
	}
	if concept.Name != "Latent Race Window Serialization Collapse" {
		t.Errorf("expected deterministic model to name concept 'Latent Race Window Serialization Collapse', got: %s", concept.Name)
	}
	if concept.Severity != domain.SeverityCritical {
		t.Errorf("expected critical severity, got %v", concept.Severity)
	}
	if expander.ConceptCount() != 1 {
		t.Errorf("expected 1 concept, got %d", expander.ConceptCount())
	}
}
