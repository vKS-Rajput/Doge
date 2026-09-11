package worldmodel

import (
	"testing"

	"github.com/google/uuid"
)

func TestUnifiedWorldModelGraph(t *testing.T) {
	wm := NewUnifiedWorldModelGraph("target_system_alpha")

	// Add State, Capability, Hypothesis, and Concept vertices
	vState := wm.AddVertex(RoleState, "UserSessionAuthenticated", 0.95, 0.1, nil)
	vCap := wm.AddVertex(RoleCapability, "CacheKeyNormalizationBleed", 0.85, 0.90, nil)
	vHypo := wm.AddVertex(RoleHypothesis, "Hypothesis_ProxyCacheDesync", 0.40, 0.75, nil)
	vConcept := wm.AddVertex(RoleConcept, "CONCEPT_CACHE_BLEED", 0.98, 0.05, nil)

	expID := uuid.New()

	// Add provenance-tracked edges
	e1 := wm.AddEdge(vState.ID, vCap.ID, EdgeLeadsToCapability, 0.90, expID, "Recon Probe 42")
	e2 := wm.AddEdge(vCap.ID, vHypo.ID, EdgeSupportsHypothesis, 0.85, expID, "Differential Probe 43")

	if e1 == nil || e2 == nil {
		t.Fatalf("expected edges created")
	}

	// 1. Test Frontier View: F_t = { v : conf < 0.50 OR anomaly > 0.80 }
	frontier := wm.GetFrontierView(0.50, 0.80)
	if len(frontier) == 0 {
		t.Fatalf("expected nodes on frontier")
	}

	foundCap := false
	foundHypo := false
	for _, f := range frontier {
		if f.ID == vCap.ID {
			foundCap = true
		}
		if f.ID == vHypo.ID {
			foundHypo = true
		}
	}

	if !foundCap || !foundHypo {
		t.Errorf("expected vCap (anomaly=0.90) and vHypo (conf=0.40) on frontier")
	}
	t.Logf("Frontier View F_t contains %d active research nodes", len(frontier))

	// 2. Test Attack Graph View
	nodes, edges := wm.AttackGraphView()
	if len(nodes) < 2 || len(edges) < 1 {
		t.Errorf("expected attack graph projection to have at least 2 nodes and 1 edge, got %d nodes, %d edges", len(nodes), len(edges))
	}

	// 3. Test Concept Graph View
	conceptNodes, _ := wm.ConceptGraphView()
	if len(conceptNodes) < 2 {
		t.Errorf("expected concept view to have at least 2 nodes (concept + hypo), got %d", len(conceptNodes))
	}

	// 4. Test Confidence Decay
	oldConf := vHypo.Confidence
	wm.DecayStaleConfidence(0.90)
	if vHypo.Confidence >= oldConf {
		t.Errorf("expected confidence to decay from %.2f, got %.2f", oldConf, vHypo.Confidence)
	}

	t.Logf("Decayed Confidence on stale hypothesis: %.2f -> %.2f (Concept confidence maintained at %.2f)",
		oldConf, vHypo.Confidence, vConcept.Confidence)
}
