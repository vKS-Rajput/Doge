package report

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestProofBundleGenerationAndIntegrity(t *testing.T) {
	findingID := uuid.New()
	secretKey := []byte("test-enterprise-attestation-secret-2026")

	finding := domain.ProvenFinding{
		ID:          findingID,
		Title:       "BOLA on Order API",
		Type:        "BOLA",
		Severity:    "high",
		Endpoint:    "/api/orders/100",
		Description: "Principal B accessed Principal A order",
		ValidationEvidence: []domain.ExperimentEvidence{
			{
				ID:             uuid.New(),
				RequestMethod:  "GET",
				RequestURL:     "http://localhost:8080/api/orders/100",
				RequestBody:    "",
				ResponseStatus: 200,
				ResponseBody:   `{"order_id":100,"owner":"alice","total":500}`,
				ResponseTimeMs: 12,
				CapturedAt:     time.Now().UTC(),
			},
		},
		ImpactEvidence: []domain.ExperimentEvidence{
			{
				ID:             uuid.New(),
				RequestMethod:  "POST",
				RequestURL:     "http://localhost:8080/api/orders/100/cancel",
				RequestBody:    `{"reason":"unauthorized"}`,
				ResponseStatus: 200,
				ResponseBody:   `{"status":"cancelled","order_id":100}`,
				ResponseTimeMs: 15,
				CapturedAt:     time.Now().UTC(),
			},
		},
		ValidatedAt: time.Now().UTC(),
	}

	bundle, err := GenerateProofBundle(finding, "http://localhost:8080", secretKey)
	if err != nil {
		t.Fatalf("GenerateProofBundle failed: %v", err)
	}

	if bundle.FindingID != findingID {
		t.Fatalf("expected finding ID %s, got %s", findingID, bundle.FindingID)
	}
	if len(bundle.Steps) != 2 {
		t.Fatalf("expected 2 replay steps, got %d", len(bundle.Steps))
	}
	if bundle.ChainDigest == "" || bundle.MerkleRoot == "" {
		t.Fatalf("expected non-empty cryptographic digests")
	}

	// 1. Verify valid bundle
	valid, err := VerifyProofBundleIntegrity(bundle, secretKey)
	if err != nil || !valid {
		t.Fatalf("expected bundle to be valid, got valid=%v, err=%v", valid, err)
	}

	// 2. Test Tamper Detection: modify a step's expected status
	tampered := *bundle
	tamperedSteps := make([]ReplayStep, len(bundle.Steps))
	copy(tamperedSteps, bundle.Steps)
	tamperedSteps[0].ExpectedStatus = 403
	tampered.Steps = tamperedSteps

	validTampered, err := VerifyProofBundleIntegrity(&tampered, secretKey)
	if validTampered || err == nil {
		t.Fatalf("expected tampered bundle to be rejected, but it was accepted: err=%v", err)
	}

	// 3. Test HMAC Attestation tampering: wrong key
	wrongKey := []byte("wrong-attestation-key-123456789")
	validWrongKey, err := VerifyProofBundleIntegrity(bundle, wrongKey)
	if validWrongKey || err == nil {
		t.Fatalf("expected invalid signature with wrong key, but verification passed: err=%v", err)
	}
}

func TestReplayProofBundleWithServer(t *testing.T) {
	// Setup test mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/data" && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"leak":"sensitive_telemetry_payload"}`))
			return
		}
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer server.Close()

	bundle := &ProofBundle{
		ID:                 uuid.New(),
		FindingID:          uuid.New(),
		VulnerabilityClass: "InformationDisclosure",
		TargetURL:          server.URL,
		Steps: []ReplayStep{
			{
				Index:                 0,
				Method:                "GET",
				URL:                   server.URL + "/api/data",
				ExpectedStatus:        http.StatusOK,
				ExpectedBodySubstring: "sensitive_telemetry",
			},
		},
	}

	res, err := ReplayProofBundle(context.Background(), bundle, server.Client())
	if err != nil {
		t.Fatalf("ReplayProofBundle failed: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected replay success, got error: %s", res.ErrorMessage)
	}
	if res.StepsExecuted != 1 {
		t.Fatalf("expected 1 step executed, got %d", res.StepsExecuted)
	}
}

func TestCVSS31Calculation(t *testing.T) {
	tests := []struct {
		vector       string
		expectedBase float64
		expectedSev  string
	}{
		{
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			expectedBase: 10.0,
			expectedSev:  "Critical",
		},
		{
			vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			expectedBase: 9.1,
			expectedSev:  "Critical",
		},
		{
			vector:       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			expectedBase: 8.1,
			expectedSev:  "High",
		},
		{
			vector:       "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
			expectedBase: 5.3,
			expectedSev:  "Medium",
		},
	}

	for _, tt := range tests {
		parsed, err := ParseCVSSVector(tt.vector)
		if err != nil {
			t.Fatalf("ParseCVSSVector failed for %s: %v", tt.vector, err)
		}
		score := CalculateCVSS(parsed)
		if score.BaseScore != tt.expectedBase {
			t.Errorf("vector %s: expected base score %.1f, got %.1f", tt.vector, tt.expectedBase, score.BaseScore)
		}
		if score.Severity != tt.expectedSev {
			t.Errorf("vector %s: expected severity %s, got %s", tt.vector, tt.expectedSev, score.Severity)
		}
	}
}

func TestExportSARIFAndMultiFormat(t *testing.T) {
	now := time.Now().UTC()
	rep := &Report{
		ID:          uuid.New(),
		Title:       "Security Assessment: Mock Bank Enterprise",
		ProjectID:   uuid.New(),
		GeneratedAt: now,
		Executive: ExecutiveSummary{
			Target:    "Mock Bank Enterprise",
			StartDate: now.Add(-2 * time.Hour),
			EndDate:   now,
			Summary:   "Identified 2 critical security findings.",
			FindingCounts: SeverityCounts{
				Critical: 1,
				High:     1,
			},
		},
		Findings: []FindingSection{
			{
				Title:       "HTTP Request Smuggling TE.CL Desync",
				Severity:    domain.SeverityCritical,
				Category:    domain.FindingCatMisconfiguration,
				Description: "Frontend parses Content-Length, backend parses chunked encoding.",
				Remediation: "Normalize HTTP framing at reverse proxy.",
				ReproductionSteps: []domain.ReproductionStep{
					{
						Order:          1,
						Description:    "POST / HTTP/1.1",
						ExpectedResult: "HTTP/1.1 200 OK",
					},
				},
				Impact: domain.ImpactAssessment{
					Description: "Complete tenant session hijacking.",
				},
				ConfirmedBy: "DOGE Independent Validator",
			},
		},
	}

	proofBundle := &ProofBundle{
		ID:                 uuid.New(),
		FindingID:          uuid.New(),
		VulnerabilityClass: "RequestSmuggling",
		ChainDigest:        "mock-chain-digest-12345",
		MerkleRoot:         "mock-merkle-root-67890",
		Steps: []ReplayStep{
			{
				Index:          0,
				Method:         "POST",
				URL:            "http://target.local/",
				ExpectedStatus: 200,
			},
		},
		Attestation: AttestationRecord{
			EngineVersion: DogeEngineVersion,
			EngineCommit:  DogeEngineCommit,
		},
	}

	exporter := NewExporter()

	// 1. Export SARIF
	sarifBytes, err := exporter.Export(rep, []*ProofBundle{proofBundle}, FormatSARIF)
	if err != nil {
		t.Fatalf("ExportSARIF failed: %v", err)
	}

	var sarifLog SarifLog
	if err := json.Unmarshal(sarifBytes, &sarifLog); err != nil {
		t.Fatalf("unmarshal SARIF JSON failed: %v", err)
	}
	if sarifLog.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarifLog.Version)
	}
	if len(sarifLog.Runs) == 0 || len(sarifLog.Runs[0].Results) == 0 {
		t.Fatalf("expected at least 1 SARIF result")
	}
	resProps := sarifLog.Runs[0].Results[0].Properties
	if resProps["proof_chain_digest"] != "mock-chain-digest-12345" {
		t.Errorf("expected proof_chain_digest to be attached to SARIF result")
	}

	// 2. Export Markdown
	mdBytes, err := exporter.Export(rep, []*ProofBundle{proofBundle}, FormatMarkdown)
	if err != nil {
		t.Fatalf("Export Markdown failed: %v", err)
	}
	mdStr := string(mdBytes)
	if !strings.Contains(mdStr, "Executive Security Assessment") || !strings.Contains(mdStr, "HTTP Request Smuggling") {
		t.Errorf("markdown report missing expected titles")
	}
	if !strings.Contains(mdStr, "```diff") {
		t.Errorf("markdown report missing developer remediation diff")
	}
}
