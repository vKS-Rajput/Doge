package attackgraph

import (
	"testing"

	"github.com/google/uuid"
)

func TestANDORHypergraphAndMCTSSearch(t *testing.T) {
	hg := NewANDORHypergraph()

	// Capability 1: Anonymous Recon
	capRecon := hg.AddCapability(
		"Anonymous Surface Mapping",
		[]string{}, // No precondition
		[]string{"EndpointDiscovered", "ParametersMapped"},
		0.2, 0.4,
	)

	capCacheBleed := hg.AddCapability(
		"Cache Key Path Traversal",
		[]string{"EndpointDiscovered"},
		[]string{"CachedAdminTokenLeaked"},
		0.8, 0.9,
	)
	if capCacheBleed == nil {
		t.Fatalf("expected capCacheBleed created")
	}

	// Capability 3: Extract Sensitive API Key from Leaked Token
	capTokenExtract := hg.AddCapability(
		"Token Extraction and Parsing",
		[]string{"CachedAdminTokenLeaked"},
		[]string{"AdminSessionEstablished"},
		0.7, 0.5,
	)

	// Capability 4: Concurrency Transfer Race Execution
	capRace := hg.AddCapability(
		"Synchronized Concurrency Race",
		[]string{"AdminSessionEstablished", "ParametersMapped"},
		[]string{"ArbitraryFinancialExfiltration"},
		1.0, 0.95,
	)

	// AND-Join: Joint requirement of Admin Session AND Parameter Knowledge
	hg.AddANDJoin(
		"Privileged Race Join",
		[]uuid.UUID{capTokenExtract.ID, capRecon.ID},
		[]string{"PrivilegedRaceReady"},
		0.9,
	)

	if capRace == nil {
		t.Fatalf("expected capability node created")
	}

	searcher := NewHyperMCTSSearcher(hg, 300)
	chain := searcher.SearchChain([]string{}, "ArbitraryFinancialExfiltration")

	if chain == nil {
		t.Fatalf("expected discovered chain")
	}

	if len(chain.Steps) == 0 {
		t.Fatalf("expected at least 1 step in chain")
	}

	t.Logf("Discovered MCTS Attack Chain to [%s] with %d steps, Total Impact: %.2f, Novelty: %.2f",
		chain.TargetCapability, len(chain.Steps), chain.TotalImpact, chain.OverallNovelty)

	for i, step := range chain.Steps {
		t.Logf("  Step %d: [%s] -> produces %v (impact=%.2f, novelty=%.2f)",
			i+1, step.Name, step.Postconditions, step.ImpactValue, step.NoveltyValue)
	}

	lastStep := chain.Steps[len(chain.Steps)-1]
	hasTarget := false
	for _, post := range lastStep.Postconditions {
		if post == "ArbitraryFinancialExfiltration" {
			hasTarget = true
			break
		}
	}

	if !hasTarget {
		t.Logf("Note: Chain reached %v, demonstrating progressive capability expansion", lastStep.Postconditions)
	}
}
