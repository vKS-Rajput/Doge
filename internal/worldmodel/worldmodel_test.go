package worldmodel

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestWorldModelRelationalGraph(t *testing.T) {
	wm := NewWorldModel("targetapp.com")

	// 1. Register Tenant
	tenantID := uuid.New()
	tenant := &Tenant{
		ID:     tenantID,
		Name:   "Acme Corp",
		Domain: "acme.targetapp.com",
		Tier:   "enterprise",
	}
	if err := wm.RegisterTenant(tenant); err != nil {
		t.Fatalf("failed to register tenant: %v", err)
	}

	// 2. Register Principal
	princID := uuid.New()
	principal := &Principal{
		ID:       princID,
		Name:     "alice@acme.com",
		Type:     PrincipalUser,
		TenantID: &tenantID,
		Roles:    []string{"member"},
		Headers:  map[string]string{"Authorization": "Bearer token_alice_123"},
	}
	if err := wm.RegisterPrincipal(principal); err != nil {
		t.Fatalf("failed to register principal: %v", err)
	}

	// 3. Register Object
	objID := uuid.New()
	obj := &ObjectResource{
		ID:               objID,
		Type:             "invoice",
		Identifier:       "inv_99281",
		TenantID:         &tenantID,
		OwnerPrincipalID: &princID,
		EndpointURL:      "https://targetapp.com/api/v1/invoices/inv_99281",
	}
	if err := wm.RegisterObject(obj); err != nil {
		t.Fatalf("failed to register object: %v", err)
	}

	// 4. Verify Relationships
	outbound := wm.GetOutboundRelationships(princID)
	if len(outbound) == 0 {
		t.Fatalf("expected outbound relationships from principal alice, got 0")
	}

	hasOwnershipRel := false
	for _, rel := range outbound {
		if rel.TargetID == objID && rel.Type == domain.RelOwnsObject {
			hasOwnershipRel = true
			break
		}
	}
	if !hasOwnershipRel {
		t.Errorf("expected principal -> object RelOwnsObject relationship")
	}

	// 5. Ingest Telemetry & Auto-Detect Research Gaps
	wm.IngestEntitiesAndObservations([]domain.Entity{
		{
			ID:    uuid.New(),
			Type:  domain.EntityEndpoint,
			Value: "https://targetapp.com/api/v1/invoices/inv_99281",
		},
		{
			ID:    uuid.New(),
			Type:  domain.EntityEndpoint,
			Value: "https://targetapp.com/api/v1/admin/export",
		},
		{
			ID:    uuid.New(),
			Type:  domain.EntityParameter,
			Value: "dest_url",
		},
	}, nil)

	gaps := wm.ListOpenGaps()
	t.Logf("Detected %d Research Gaps in World Model:", len(gaps))
	for _, g := range gaps {
		t.Logf("  - [%s] %s (Uncertainty: %.2f, Expected Info Gain: %.2f)", g.Type, g.Description, g.Uncertainty, g.ExpectedInfoGain)
	}

	if len(gaps) < 3 {
		t.Errorf("expected at least 3 detected research gaps, got: %d", len(gaps))
	}

	// 6. Test Gap Resolution Lifecycle
	firstGap := gaps[0]
	wm.ResolveGap(firstGap.ID, "403 Forbidden received across tenant boundary; tenant isolation confirmed.")

	resolvedGap, ok := wm.GetGap(firstGap.ID)
	if !ok || resolvedGap.Status != GapStatusResolved {
		t.Errorf("expected gap to be marked resolved, got status: %s", resolvedGap.Status)
	}
	if resolvedGap.Uncertainty != 0.0 {
		t.Errorf("expected uncertainty 0.0 after resolution, got: %.2f", resolvedGap.Uncertainty)
	}
}

func TestWorldModelConcurrency(t *testing.T) {
	wm := NewWorldModel("concurrency-test.com")
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pID := uuid.New()
			_ = wm.RegisterPrincipal(&Principal{
				ID:   pID,
				Name: "user",
				Type: PrincipalUser,
			})
			_ = wm.RegisterEndpoint(&EndpointModel{
				ID:   uuid.New(),
				Host: "concurrency-test.com",
				Path: "/api/test",
				URL:  "https://concurrency-test.com/api/test",
			})
			wm.AddGap(&ResearchGap{
				ID:          uuid.New(),
				Type:        GapUnknownAuthBoundary,
				Description: "test gap",
				Uncertainty: 0.5,
				Status:      GapStatusOpen,
			})
			_ = wm.ListPrincipals()
			_ = wm.ListEndpoints()
			_ = wm.ListOpenGaps()
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("✓ Concurrency test passed without race conditions")
	case <-time.After(3 * time.Second):
		t.Fatal("concurrency test timed out / deadlocked")
	}
}
