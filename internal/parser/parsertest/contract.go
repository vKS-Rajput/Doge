// Package parsertest provides reusable contract test helpers for parser authors.
//
// Every parser in the system must produce observations that satisfy
// these contracts. Use [AssertValidObservations] in your parser tests
// to verify compliance.
//
// Usage in a parser test:
//
//	observations, err := myParser.Parse(ctx, artifact, reader)
//	require.NoError(t, err)
//	parsertest.AssertValidObservations(t, observations)
package parsertest

import (
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// AssertValidObservations runs the standard observation contract tests
// on a slice of RawObservations. Every parser must produce observations
// that pass all of these checks.
//
// Contracts enforced:
//   - Type is a known ObservationType (not empty)
//   - SourceTool is non-empty
//   - Data is non-nil
//   - ObservedAt is set (not zero)
//   - RawValue is non-empty
//   - No duplicate observations in the slice
func AssertValidObservations(t *testing.T, observations []domain.RawObservation) {
	t.Helper()

	if len(observations) == 0 {
		t.Error("contract: parser returned zero observations")
		return
	}

	seen := make(map[string]bool)
	for i, obs := range observations {
		prefix := func(msg string) string {
			return formatPrefix(i, msg)
		}

		// Type must be set.
		if obs.Type == "" {
			t.Error(prefix("Type is empty"))
		}

		// Type must be a known ObservationType.
		if !isKnownObservationType(obs.Type) {
			t.Errorf(prefix("Type %q is not a known ObservationType"), obs.Type)
		}

		// SourceTool must be set.
		if obs.SourceTool == "" {
			t.Error(prefix("SourceTool is empty"))
		}

		// Data must not be nil.
		if obs.Data == nil {
			t.Error(prefix("Data is nil"))
		}

		// ObservedAt must be set.
		if obs.ObservedAt.IsZero() {
			t.Error(prefix("ObservedAt is zero (not set)"))
		}

		// ObservedAt must not be in the future.
		if obs.ObservedAt.After(time.Now().Add(time.Minute)) {
			t.Error(prefix("ObservedAt is in the future"))
		}

		// RawValue must be non-empty.
		if obs.RawValue == "" {
			t.Error(prefix("RawValue is empty"))
		}

		// Check for duplicates (by raw value + type).
		key := string(obs.Type) + ":" + obs.RawValue
		if seen[key] {
			t.Errorf(prefix("duplicate observation (type=%s, raw_value=%s)"), obs.Type, truncate(obs.RawValue, 50))
		}
		seen[key] = true
	}
}

// AssertObservationCount verifies the parser produced the expected number
// of observations.
func AssertObservationCount(t *testing.T, observations []domain.RawObservation, expected int) {
	t.Helper()
	if len(observations) != expected {
		t.Errorf("expected %d observations, got %d", expected, len(observations))
	}
}

// AssertAllSameTool verifies that all observations came from the same tool.
func AssertAllSameTool(t *testing.T, observations []domain.RawObservation, tool string) {
	t.Helper()
	for i, obs := range observations {
		if obs.SourceTool != tool {
			t.Errorf("observation[%d]: SourceTool = %q, want %q", i, obs.SourceTool, tool)
		}
	}
}

// AssertAllSameType verifies that all observations have the same type.
func AssertAllSameType(t *testing.T, observations []domain.RawObservation, obsType domain.ObservationType) {
	t.Helper()
	for i, obs := range observations {
		if obs.Type != obsType {
			t.Errorf("observation[%d]: Type = %q, want %q", i, obs.Type, obsType)
		}
	}
}

// AssertDataField verifies that a specific field exists in every
// observation's Data map.
func AssertDataField(t *testing.T, observations []domain.RawObservation, field string) {
	t.Helper()
	for i, obs := range observations {
		if _, ok := obs.Data[field]; !ok {
			t.Errorf("observation[%d]: Data missing required field %q", i, field)
		}
	}
}

// isKnownObservationType checks if a type is in the defined enum.
func isKnownObservationType(t domain.ObservationType) bool {
	known := map[domain.ObservationType]bool{
		domain.ObservationSubdomainDiscovery: true,
		domain.ObservationHTTPProbe:          true,
		domain.ObservationEndpointDiscovery:  true,
		domain.ObservationVulnerabilityScan:  true,
		domain.ObservationJavaScriptAnalysis: true,
		domain.ObservationScreenshotCapture:  true,
		domain.ObservationDNSLookup:          true,
		domain.ObservationPortScan:           true,
		domain.ObservationTechnologyDetect:   true,
		domain.ObservationCertificateInfo:    true,
		domain.ObservationHARCapture:         true,
		domain.ObservationResearcherNote:     true,
		domain.ObservationCrawlResult:        true,
		domain.ObservationAPIDiscovery:       true,
		domain.ObservationAuthProbe:          true,
	}
	return known[t]
}

func formatPrefix(index int, msg string) string {
	return "contract: observation[" + itoa(index) + "]: " + msg
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
