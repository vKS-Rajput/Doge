package attackgraph

import (
	"testing"
)

func TestAttackGraph_AddNodesAndEdges(t *testing.T) {
	g := NewGraph()

	p := g.AddNode(NodePrincipal, "user-alice", "Alice identity", 0.9)
	r := g.AddNode(NodeResource, "/api/v1/orders/{id}/confirm", "Order confirmation endpoint", 0.95)
	w := g.AddNode(NodeWeakness, "Workflow State Bypass", "Payment step can be skipped", 0.9)
	i := g.AddNode(NodeImpact, "Financial Loss", "Unpaid order confirmed", 0.98)

	if g.NodeCount() != 4 {
		t.Fatalf("expected 4 nodes, got %d", g.NodeCount())
	}

	edge1, err := g.AddEdge(p.ID, r.ID, EdgeEnables, "can access", 0.9)
	if err != nil {
		t.Fatalf("failed to add edge: %v", err)
	}
	if edge1 == nil {
		t.Fatal("expected non-nil edge")
	}

	_, err = g.AddEdge(r.ID, w.ID, EdgeLeadsTo, "exposes weakness", 0.95)
	if err != nil {
		t.Fatalf("failed to add edge: %v", err)
	}

	_, err = g.AddEdge(w.ID, i.ID, EdgeUnlocks, "unlocks impact", 0.95)
	if err != nil {
		t.Fatalf("failed to add edge: %v", err)
	}

	if g.EdgeCount() != 3 {
		t.Fatalf("expected 3 edges, got %d", g.EdgeCount())
	}

	// Test ChainSearcher
	searcher := NewChainSearcher(g)
	chains := searcher.FindChains(5)
	if len(chains) == 0 {
		t.Fatal("expected at least 1 attack chain, got 0")
	}

	foundImpact := false
	for _, c := range chains {
		if c.IsComplete {
			foundImpact = true
			t.Logf("Found complete attack chain: steps=%d, min_confidence=%.2f", c.TotalSteps, c.MinConfidence)
		}
	}
	if !foundImpact {
		t.Fatal("expected complete attack chain reaching impact node")
	}
}

func TestAttackGraph_Deduplication(t *testing.T) {
	g := NewGraph()

	n1 := g.AddNode(NodeResource, "/api/v1/me", "Profile endpoint", 0.5)
	n2 := g.AddNode(NodeResource, "/api/v1/me", "Profile endpoint updated", 0.9)

	if n1.ID != n2.ID {
		t.Fatalf("expected duplicate labels to return same node ID, got %s != %s", n1.ID, n2.ID)
	}
	if n2.Confidence != 0.9 {
		t.Fatalf("expected confidence to update to higher value 0.9, got %.2f", n2.Confidence)
	}
	if g.NodeCount() != 1 {
		t.Fatalf("expected 1 node after dedup, got %d", g.NodeCount())
	}
}
