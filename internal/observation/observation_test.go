package observation

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestValidateRaw_Valid(t *testing.T) {
	obs := domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: "httpx",
		Data:       map[string]any{"url": "https://example.com"},
		RawValue:   `{"url":"https://example.com"}`,
		ObservedAt: time.Now().Add(-time.Hour),
	}

	if err := ValidateRaw(obs); err != nil {
		t.Errorf("expected valid, got error: %v", err)
	}
}

func TestValidateRaw_EmptyType(t *testing.T) {
	obs := domain.RawObservation{
		SourceTool: "httpx",
		Data:       map[string]any{},
		RawValue:   "raw",
		ObservedAt: time.Now(),
	}

	if err := ValidateRaw(obs); err == nil {
		t.Error("expected error for empty Type")
	}
}

func TestValidateRaw_UnknownType(t *testing.T) {
	obs := domain.RawObservation{
		Type:       "invented_type",
		SourceTool: "httpx",
		Data:       map[string]any{},
		RawValue:   "raw",
		ObservedAt: time.Now(),
	}

	if err := ValidateRaw(obs); err == nil {
		t.Error("expected error for unknown Type")
	}
}

func TestValidateRaw_EmptySourceTool(t *testing.T) {
	obs := domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		Data:       map[string]any{},
		RawValue:   "raw",
		ObservedAt: time.Now(),
	}

	if err := ValidateRaw(obs); err == nil {
		t.Error("expected error for empty SourceTool")
	}
}

func TestValidateRaw_NilData(t *testing.T) {
	obs := domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: "httpx",
		Data:       nil,
		RawValue:   "raw",
		ObservedAt: time.Now(),
	}

	if err := ValidateRaw(obs); err == nil {
		t.Error("expected error for nil Data")
	}
}

func TestValidateRaw_ZeroObservedAt(t *testing.T) {
	obs := domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: "httpx",
		Data:       map[string]any{},
		RawValue:   "raw",
	}

	if err := ValidateRaw(obs); err == nil {
		t.Error("expected error for zero ObservedAt")
	}
}

func TestValidateRaw_FutureObservedAt(t *testing.T) {
	obs := domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: "httpx",
		Data:       map[string]any{},
		RawValue:   "raw",
		ObservedAt: time.Now().Add(time.Hour),
	}

	if err := ValidateRaw(obs); err == nil {
		t.Error("expected error for future ObservedAt")
	}
}

func TestValidateRaw_EmptyRawValue(t *testing.T) {
	obs := domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: "httpx",
		Data:       map[string]any{},
		ObservedAt: time.Now(),
	}

	if err := ValidateRaw(obs); err == nil {
		t.Error("expected error for empty RawValue")
	}
}

func TestValidate_MissingProvenance(t *testing.T) {
	obs := domain.Observation{
		ID:         uuid.New(),
		Type:       domain.ObservationHTTPProbe,
		ArtifactID: uuid.Nil, // Missing provenance.
		ProjectID:  uuid.New(),
		SourceTool: "httpx",
		Data:       map[string]any{},
		Checksum:   "abc123",
		ObservedAt: time.Now(),
	}

	if err := Validate(obs); err == nil {
		t.Error("expected error for nil ArtifactID (missing provenance)")
	}
}

func TestComputeChecksum_Deterministic(t *testing.T) {
	data := map[string]any{"url": "https://example.com", "status_code": 200}

	c1, err := ComputeChecksum(data)
	if err != nil {
		t.Fatal(err)
	}

	c2, err := ComputeChecksum(data)
	if err != nil {
		t.Fatal(err)
	}

	if c1 != c2 {
		t.Error("same data should produce same checksum")
	}
}

func TestComputeChecksum_DifferentData(t *testing.T) {
	c1, _ := ComputeChecksum(map[string]any{"url": "https://a.com"})
	c2, _ := ComputeChecksum(map[string]any{"url": "https://b.com"})

	if c1 == c2 {
		t.Error("different data should produce different checksums")
	}
}

func TestNormalize(t *testing.T) {
	raw := domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: "httpx",
		Data:       map[string]any{"url": "https://example.com"},
		RawValue:   `{"url":"https://example.com"}`,
		ObservedAt: time.Now().Add(-time.Hour),
	}

	artifactID := uuid.New()
	projectID := uuid.New()

	obs, err := Normalize(raw, artifactID, projectID, "1.0.0")
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if obs.ID == uuid.Nil {
		t.Error("normalized observation should have an ID")
	}
	if obs.ArtifactID != artifactID {
		t.Error("ArtifactID should match")
	}
	if obs.ProjectID != projectID {
		t.Error("ProjectID should match")
	}
	if obs.Checksum == "" {
		t.Error("Checksum should be computed")
	}
	if obs.IngestedAt.IsZero() {
		t.Error("IngestedAt should be set")
	}
	if obs.ParserVersion != "1.0.0" {
		t.Errorf("ParserVersion = %q, want '1.0.0'", obs.ParserVersion)
	}
}
