package invariant

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/property"
)

// Verifier evaluates candidate invariants against metamorphic experiment evidence.
type Verifier struct {
	mu         sync.RWMutex
	invariants map[uuid.UUID]*Invariant
}

// NewVerifier creates a new invariant verifier.
func NewVerifier(invariants []*Invariant) *Verifier {
	invMap := make(map[uuid.UUID]*Invariant)
	for _, inv := range invariants {
		invMap[inv.ID] = inv
	}
	return &Verifier{invariants: invMap}
}

// RegisterInvariant adds an invariant to be verified.
func (v *Verifier) RegisterInvariant(inv *Invariant) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.invariants[inv.ID] = inv
}

// RecordSupport notes that an experiment was consistent with the invariant.
func (v *Verifier) RecordSupport(invID uuid.UUID, evidenceID uuid.UUID) {
	v.mu.Lock()
	defer v.mu.Unlock()

	inv, ok := v.invariants[invID]
	if !ok {
		return
	}

	inv.ObservedSupportCount++
	inv.EvidenceIDs = append(inv.EvidenceIDs, evidenceID)
	inv.State = property.StateSupported
	inv.Confidence = minFloat(0.99, inv.Confidence+0.05)
	inv.UpdatedAt = time.Now().UTC()
}

// RecordContradiction notes that an experiment contradicted the invariant,
// indicating an invariant breakdown (emergent vulnerability candidate).
func (v *Verifier) RecordContradiction(invID uuid.UUID, evidenceID uuid.UUID, description string) (*property.SecurityProperty, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	inv, ok := v.invariants[invID]
	if !ok {
		return nil, fmt.Errorf("invariant %s not found", invID)
	}

	inv.ContradictionCount++
	inv.EvidenceIDs = append(inv.EvidenceIDs, evidenceID)
	inv.State = property.StateViolated
	inv.Confidence = 0.96
	inv.ViolationDescription = description
	inv.UpdatedAt = time.Now().UTC()

	// Convert into an Emergent Security Property with violated status
	emergentProp := inv.ToSecurityProperty()
	emergentProp.State = property.StateViolated
	emergentProp.ViolationDetails = description

	return emergentProp, nil
}

// ViolatedInvariants returns all invariants that have been broken.
func (v *Verifier) ViolatedInvariants() []*Invariant {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var violated []*Invariant
	for _, inv := range v.invariants {
		if inv.State == property.StateViolated || inv.ContradictionCount > 0 {
			violated = append(violated, inv)
		}
	}
	return violated
}
