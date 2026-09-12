package researcher

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/attackgraph"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

type mockHTTPClient struct {
	doFunc func(ctx context.Context, method, url string, headers map[string]string, body string) (*domain.ExperimentEvidence, error)
}

func (m *mockHTTPClient) Do(ctx context.Context, method, url string, headers map[string]string, body string) (*domain.ExperimentEvidence, error) {
	if m.doFunc != nil {
		return m.doFunc(ctx, method, url, headers, body)
	}
	return &domain.ExperimentEvidence{
		ID:             uuid.New(),
		RequestURL:     url,
		RequestMethod:  method,
		ResponseStatus: 200,
		ResponseBody:   `{"status": "ok", "admin": true}`,
		CapturedAt:     time.Now().UTC(),
	}, nil
}

func TestSpecializedResearchersFleet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mockClient := &mockHTTPClient{
		doFunc: func(ctx context.Context, method, url string, headers map[string]string, body string) (*domain.ExperimentEvidence, error) {
			status := 200
			respBody := `{"status":"ok","version":"1.0","paths":{"/api/v1/users":{}}}`
			if method == "POST" && body != "" {
				respBody = `{"status":"secret","poisoned":true}`
			}
			return &domain.ExperimentEvidence{
				ID:             uuid.New(),
				RequestURL:     url,
				RequestMethod:  method,
				ResponseStatus: status,
				ResponseBody:   respBody,
				CapturedAt:     time.Now().UTC(),
			}, nil
		},
	}

	brief := &domain.MissionBrief{
		ID:             uuid.New(),
		TargetBaseURL:  "http://example.local",
		KnownEndpoints: []string{"http://example.local/api/v1/orders", "http://example.local/api/v1/batch"},
		Credentials: map[string]string{
			"alice": "header.payload.signature",
		},
		MaxRequests: 20,
		MaxDuration: 5 * time.Second,
	}

	// 1. Test APIResearcher
	apiR := NewAPIResearcher(mockClient)
	if apiR.Type() != domain.ResearcherAPI {
		t.Fatalf("expected ResearcherAPI, got %s", apiR.Type())
	}
	resAPI, err := apiR.Execute(ctx, brief)
	if err != nil || resAPI.Status != domain.MissionCompleted {
		t.Fatalf("APIResearcher failed: %v", err)
	}
	t.Logf("✓ APIResearcher passed: %s", resAPI.Summary)

	// 2. Test AuthenticationResearcher
	authR := NewAuthenticationResearcher(mockClient)
	if authR.Type() != domain.ResearcherAuthentication {
		t.Fatalf("expected ResearcherAuthentication, got %s", authR.Type())
	}
	resAuth, err := authR.Execute(ctx, brief)
	if err != nil || resAuth.Status != domain.MissionCompleted {
		t.Fatalf("AuthenticationResearcher failed: %v", err)
	}
	t.Logf("✓ AuthenticationResearcher passed: %s", resAuth.Summary)

	// 3. Test DifferentialResearcher
	diffR := NewDifferentialResearcher(mockClient)
	if diffR.Type() != domain.ResearcherDifferential {
		t.Fatalf("expected ResearcherDifferential, got %s", diffR.Type())
	}
	resDiff, err := diffR.Execute(ctx, brief)
	if err != nil || resDiff.Status != domain.MissionCompleted {
		t.Fatalf("DifferentialResearcher failed: %v", err)
	}
	t.Logf("✓ DifferentialResearcher passed: %s", resDiff.Summary)

	// 4. Test RaceResearcher
	raceR := NewRaceResearcher(mockClient)
	if raceR.Type() != domain.ResearcherRace {
		t.Fatalf("expected ResearcherRace, got %s", raceR.Type())
	}
	resRace, err := raceR.Execute(ctx, brief)
	if err != nil || resRace.Status != domain.MissionCompleted {
		t.Fatalf("RaceResearcher failed: %v", err)
	}
	t.Logf("✓ RaceResearcher passed: %s", resRace.Summary)

	// 5. Test CacheResearcher
	cacheR := NewCacheResearcher(mockClient)
	if cacheR.Type() != domain.ResearcherCache {
		t.Fatalf("expected ResearcherCache, got %s", cacheR.Type())
	}
	resCache, err := cacheR.Execute(ctx, brief)
	if err != nil || resCache.Status != domain.MissionCompleted {
		t.Fatalf("CacheResearcher failed: %v", err)
	}
	t.Logf("✓ CacheResearcher passed: %s", resCache.Summary)

	// 6. Test InjectionResearcher
	injR := NewInjectionResearcher(mockClient)
	if injR.Type() != domain.ResearcherInjection {
		t.Fatalf("expected ResearcherInjection, got %s", injR.Type())
	}
	resInj, err := injR.Execute(ctx, brief)
	if err != nil || resInj.Status != domain.MissionCompleted {
		t.Fatalf("InjectionResearcher failed: %v", err)
	}
	t.Logf("✓ InjectionResearcher passed: %s", resInj.Summary)

	// 7. Test MetamorphicResearcher
	metaR := NewMetamorphicResearcher(mockClient)
	if metaR.Type() != domain.ResearcherMetamorphic {
		t.Fatalf("expected ResearcherMetamorphic, got %s", metaR.Type())
	}
	resMeta, err := metaR.Execute(ctx, brief)
	if err != nil || resMeta.Status != domain.MissionCompleted {
		t.Fatalf("MetamorphicResearcher failed: %v", err)
	}
	t.Logf("✓ MetamorphicResearcher passed: %s", resMeta.Summary)

	// 8. Test ChainResearcher
	chainR := NewChainResearcher(mockClient, attackgraph.NewGraph())
	if chainR.Type() != domain.ResearcherChain {
		t.Fatalf("expected ResearcherChain, got %s", chainR.Type())
	}
	resChain, err := chainR.Execute(ctx, brief)
	if err != nil || resChain.Status != domain.MissionCompleted {
		t.Fatalf("ChainResearcher failed: %v", err)
	}
	t.Logf("✓ ChainResearcher passed: %s", resChain.Summary)

	// 9. Test ExploitResearcher
	exploitR := NewExploitResearcher(mockClient)
	if exploitR.Type() != domain.ResearcherExploit {
		t.Fatalf("expected ResearcherExploit, got %s", exploitR.Type())
	}
	resExploit, err := exploitR.Execute(ctx, brief)
	if err != nil || resExploit.Status != domain.MissionCompleted {
		t.Fatalf("ExploitResearcher failed: %v", err)
	}
	t.Logf("✓ ExploitResearcher passed: %s", resExploit.Summary)

	// 10. Test SourceResearcher
	sourceR := NewSourceResearcher("")
	if sourceR.Type() != domain.ResearcherSource {
		t.Fatalf("expected ResearcherSource, got %s", sourceR.Type())
	}
	resSource, err := sourceR.Execute(ctx, brief)
	if err != nil || resSource.Status != domain.MissionCompleted {
		t.Fatalf("SourceResearcher failed: %v", err)
	}
	t.Logf("✓ SourceResearcher passed: %s", resSource.Summary)
}
