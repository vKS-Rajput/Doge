package reasoning

import (
	"testing"

	"github.com/vKS-Rajput/doge/pkg/ai"
)

func TestValidateResponse_Valid(t *testing.T) {
	r := &Response{
		Answer: "Admin endpoints exist.",
		Claims: []Claim{
			{Text: "admin.example.com exists", EvidenceIDs: []string{"e1234567"}, Confidence: 0.95, Category: ai.ClaimObserved},
			{Text: "might have IDOR", EvidenceIDs: []string{"e1234567"}, Confidence: 0.3, Category: ai.ClaimHypothetical},
		},
		Limitations: []string{"No auth evidence."},
	}
	if err := validateResponse(r); err != nil {
		t.Errorf("valid response rejected: %v", err)
	}
}

func TestValidateResponse_EmptyAnswer(t *testing.T) {
	r := &Response{Answer: "  ", Claims: nil}
	if err := validateResponse(r); err == nil {
		t.Error("expected error for empty answer")
	}
}

func TestValidateResponse_EmptyClaimText(t *testing.T) {
	r := &Response{
		Answer: "Something",
		Claims: []Claim{{Text: "", EvidenceIDs: []string{"e1"}, Confidence: 0.5, Category: ai.ClaimObserved}},
	}
	if err := validateResponse(r); err == nil {
		t.Error("expected error for empty claim text")
	}
}

func TestValidateResponse_ConfidenceOutOfBounds(t *testing.T) {
	tests := []struct {
		name       string
		confidence float64
		wantErr    bool
	}{
		{"negative", -0.1, true},
		{"over_one", 1.7, true},
		{"zero", 0.0, false},
		{"one", 1.0, false},
		{"normal", 0.85, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Response{
				Answer: "Test",
				Claims: []Claim{{Text: "claim", EvidenceIDs: []string{"e1"}, Confidence: tt.confidence, Category: ai.ClaimObserved}},
			}
			err := validateResponse(r)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for confidence %.2f", tt.confidence)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for confidence %.2f: %v", tt.confidence, err)
			}
		})
	}
}

func TestValidateResponse_InvalidCategory(t *testing.T) {
	r := &Response{
		Answer: "Test",
		Claims: []Claim{{Text: "claim", EvidenceIDs: []string{"e1"}, Confidence: 0.5, Category: "whatever"}},
	}
	if err := validateResponse(r); err == nil {
		t.Error("expected error for invalid category")
	}
}

func TestValidateResponse_EmptyEvidenceID(t *testing.T) {
	r := &Response{
		Answer: "Test",
		Claims: []Claim{{Text: "claim", EvidenceIDs: []string{"e1", ""}, Confidence: 0.5, Category: ai.ClaimObserved}},
	}
	if err := validateResponse(r); err == nil {
		t.Error("expected error for empty evidence ID")
	}
}

func TestValidateResponse_NoClaims(t *testing.T) {
	r := &Response{Answer: "No findings.", Claims: nil, Limitations: []string{"Insufficient data."}}
	if err := validateResponse(r); err != nil {
		t.Errorf("response with no claims should be valid: %v", err)
	}
}

func TestValidateResponse_AnswerTooLong(t *testing.T) {
	longAnswer := make([]byte, 10001)
	for i := range longAnswer {
		longAnswer[i] = 'a'
	}
	r := &Response{Answer: string(longAnswer)}
	if err := validateResponse(r); err == nil {
		t.Error("expected error for answer exceeding 10000 chars")
	}
}
