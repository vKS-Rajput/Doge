package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/benchmark"
	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/report"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestV7EnterpriseReportingAndGating(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// -------------------------------------------------------------
	// 1. Launch Live Benchmark Target (BENCH-010 Request Smuggling)
	// -------------------------------------------------------------
	smuggleApp := benchmark.NewSmugglingApp()
	defer smuggleApp.Close()
	targetURL := smuggleApp.URL()

	secretKey := []byte("doge-enterprise-secret-key-production-2026")

	// -------------------------------------------------------------
	// 2. Synthesize Real Confirmed Findings from Assessment
	// -------------------------------------------------------------
	smuggleFindingID := uuid.New()
	jwtFindingID := uuid.New()

	provenSmuggle := domain.ProvenFinding{
		ID:          smuggleFindingID,
		Title:       "HTTP Request Smuggling TE.CL Protocol Desynchronization",
		Type:        "RequestSmuggling",
		Severity:    "critical",
		Endpoint:    "/api/v1/gateway/forward",
		Description: "Ambiguity in Transfer-Encoding chunk boundary allows unauthenticated request smuggling.",
		ValidationEvidence: []domain.ExperimentEvidence{
			{
				ID:             uuid.New(),
				RequestMethod:  "POST",
				RequestURL:     targetURL + "/api/v1/gateway/forward",
				RequestHeaders: map[string]string{"Transfer-Encoding": "chunked", "Content-Length": "4"},
				RequestBody:    "0\r\n\r\nGET /api/v1/admin/vault HTTP/1.1\r\nHost: target\r\n\r\n",
				ResponseStatus: http.StatusOK,
				ResponseBody:   `{"status":"desync_success","poisoned":true}`,
				CapturedAt:     time.Now().UTC(),
			},
		},
		ValidatedAt: time.Now().UTC(),
	}

	provenJWT := domain.ProvenFinding{
		ID:          jwtFindingID,
		Title:       "JWT RS256 to HS256 Public Key Confusion",
		Type:        "JWTConfusion",
		Severity:    "critical",
		Endpoint:    "/api/auth/token",
		Description: "Backend verifies HMAC tokens using RSA public key bytes.",
		ValidationEvidence: []domain.ExperimentEvidence{
			{
				ID:             uuid.New(),
				RequestMethod:  "POST",
				RequestURL:     targetURL + "/api/auth/token",
				RequestBody:    `{"token":"fake.hs256.token"}`,
				ResponseStatus: http.StatusOK,
				ResponseBody:   `{"authenticated":true,"role":"superadmin"}`,
				CapturedAt:     time.Now().UTC(),
			},
		},
		ValidatedAt: time.Now().UTC(),
	}

	// -------------------------------------------------------------
	// 3. Cryptographic Proof Bundle Generation & Integrity Verification
	// -------------------------------------------------------------
	bundleSmuggle, err := report.GenerateProofBundle(provenSmuggle, targetURL, secretKey)
	if err != nil {
		t.Fatalf("failed generating proof bundle for smuggling: %v", err)
	}

	bundleJWT, err := report.GenerateProofBundle(provenJWT, targetURL, secretKey)
	if err != nil {
		t.Fatalf("failed generating proof bundle for JWT: %v", err)
	}

	// Verify un-tampered integrity
	validSmuggle, err := report.VerifyProofBundleIntegrity(bundleSmuggle, secretKey)
	if err != nil || !validSmuggle {
		t.Fatalf("expected valid smuggle bundle, got valid=%v, err=%v", validSmuggle, err)
	}

	validJWT, err := report.VerifyProofBundleIntegrity(bundleJWT, secretKey)
	if err != nil || !validJWT {
		t.Fatalf("expected valid JWT bundle, got valid=%v, err=%v", validJWT, err)
	}

	// Tamper Detection Test: flip a byte in request body
	tamperedBundle := *bundleSmuggle
	tamperedSteps := make([]report.ReplayStep, len(bundleSmuggle.Steps))
	copy(tamperedSteps, bundleSmuggle.Steps)
	tamperedSteps[0].Body = "MALICIOUS_TAMPERED_BODY"
	tamperedBundle.Steps = tamperedSteps

	validTampered, err := report.VerifyProofBundleIntegrity(&tamperedBundle, secretKey)
	if validTampered || err == nil {
		t.Fatalf("expected tampered bundle to be rejected by cryptographic verifier, but it passed")
	}

	// -------------------------------------------------------------
	// 4. Live Active Replay Verification
	// -------------------------------------------------------------
	replayRes, err := report.ReplayProofBundle(ctx, bundleSmuggle, http.DefaultClient)
	if err != nil {
		t.Fatalf("ReplayProofBundle execution error: %v", err)
	}
	if !replayRes.Success {
		t.Fatalf("expected live replay success, got failure: %s", replayRes.ErrorMessage)
	}
	if replayRes.StepsExecuted != 1 {
		t.Fatalf("expected 1 step executed, got %d", replayRes.StepsExecuted)
	}

	// -------------------------------------------------------------
	// 5. Build Enterprise Assessment Report
	// -------------------------------------------------------------
	findings := []domain.Finding{
		{
			ID:          smuggleFindingID,
			Title:       provenSmuggle.Title,
			Severity:    domain.SeverityCritical,
			Category:    domain.FindingCatMisconfiguration,
			Description: provenSmuggle.Description,
			Status:      domain.FindingConfirmed,
			ConfirmedBy: "DOGE Autonomous Science Fleet",
			ConfirmedAt: timePtr(time.Now().UTC()),
		},
		{
			ID:          jwtFindingID,
			Title:       provenJWT.Title,
			Severity:    domain.SeverityCritical,
			Category:    domain.FindingCatAuthentication,
			Description: provenJWT.Description,
			Status:      domain.FindingConfirmed,
			ConfirmedBy: "DOGE Autonomous Science Fleet",
			ConfirmedAt: timePtr(time.Now().UTC()),
		},
	}

	reportInput := report.ReportInput{
		ProjectName: "Enterprise Cloud Payment Gateway",
		ProjectID:   uuid.New(),
		TargetScope: []string{targetURL},
		StartDate:   time.Now().UTC().Add(-2 * time.Hour),
		EndDate:     time.Now().UTC(),
		Findings:    findings,
		ToolsUsed:   []string{"doge-mdl-operator", "doge-causal-scm", "doge-tactical-sandbox"},
		ObservationsCollected: 142,
		HypothesesTested:      18,
		ValidationsExecuted:   2,
		GeneratedBy:           "DOGE Autonomous Fleet Node-01",
	}

	assessmentReport, err := report.Generate(reportInput)
	if err != nil {
		t.Fatalf("report.Generate failed: %v", err)
	}

	bundles := []*report.ProofBundle{bundleSmuggle, bundleJWT}

	// -------------------------------------------------------------
	// 6. OASIS SARIF v2.1.0 Exporter Verification
	// -------------------------------------------------------------
	exporter := report.NewExporter()
	sarifBytes, err := exporter.Export(assessmentReport, bundles, report.FormatSARIF)
	if err != nil {
		t.Fatalf("SARIF export failed: %v", err)
	}

	var sarifLog report.SarifLog
	if err := json.Unmarshal(sarifBytes, &sarifLog); err != nil {
		t.Fatalf("SARIF JSON invalid: %v", err)
	}

	if sarifLog.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarifLog.Version)
	}
	if len(sarifLog.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 SARIF results, got %d", len(sarifLog.Runs[0].Results))
	}

	firstRes := sarifLog.Runs[0].Results[0]
	if firstRes.Level != "error" {
		t.Errorf("expected critical finding to map to SARIF level 'error', got %s", firstRes.Level)
	}
	if firstRes.Properties["cwe_id"] != "CWE-444" {
		t.Errorf("expected CWE-444 for request smuggling, got %v", firstRes.Properties["cwe_id"])
	}
	if firstRes.Properties["proof_chain_digest"] == "" {
		t.Errorf("expected cryptographic proof chain digest attached to SARIF")
	}

	// -------------------------------------------------------------
	// 7. Executive Markdown & Developer Remediation Advisory
	// -------------------------------------------------------------
	mdBytes, err := exporter.Export(assessmentReport, bundles, report.FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown export failed: %v", err)
	}
	mdContent := string(mdBytes)

	if !strings.Contains(mdContent, "Executive Security Assessment: Enterprise Cloud Payment Gateway") {
		t.Errorf("executive title missing from Markdown report")
	}
	if !strings.Contains(mdContent, "0.0%") {
		t.Errorf("zero false positive guarantee missing from report")
	}
	if !strings.Contains(mdContent, "```diff") {
		t.Errorf("developer remediation code patch diff missing")
	}
	if !strings.Contains(mdContent, "nginx.conf") && !strings.Contains(mdContent, "jwt.go") {
		t.Errorf("expected remediation patch files not mentioned in Markdown report")
	}

	// -------------------------------------------------------------
	// 8. CI/CD Security Gating & Policy Engine Evaluation
	// -------------------------------------------------------------
	policy := gates.DefaultEnterprisePolicy()
	verdict := gates.EvaluatePolicy(findings, bundles, policy)

	// In the presence of 2 critical findings (including disallowed CWE-444), the policy must FAIL closed
	if verdict.Passed {
		t.Fatalf("expected CI/CD gate to fail on critical findings, but it passed")
	}
	if verdict.ExitCode != 1 {
		t.Errorf("expected exit code 1 for failing gate, got %d", verdict.ExitCode)
	}
	if verdict.TotalViolations == 0 {
		t.Errorf("expected violations, got 0")
	}

	// Now simulate clean pipeline: evaluate with exclusions or after remediation
	policyClean := policy
	policyClean.ExcludedFindingIDs = []string{smuggleFindingID.String(), jwtFindingID.String()}
	cleanVerdict := gates.EvaluatePolicy(findings, bundles, policyClean)

	if !cleanVerdict.Passed {
		t.Fatalf("expected clean policy to pass when findings are excluded, got failure: %s", cleanVerdict.Summary)
	}
	if cleanVerdict.ExitCode != 0 {
		t.Errorf("expected exit code 0 for clean gate, got %d", cleanVerdict.ExitCode)
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
