package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/report"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ScanConfig parameterizes an autonomous security scan.
type ScanConfig struct {
	TargetURL      string
	Budget         int
	RatePerSecond  int
	TimeoutMinutes int
	OutOfScope     []string
	CustomHeaders  map[string]string
	SkipTLSVerify  bool
	SecretKey      []byte
}

// ScanResult encapsulates the complete output of an autonomous scan.
type ScanResult struct {
	TargetURL         string
	StartedAt         time.Time
	FinishedAt        time.Time
	Duration          time.Duration
	EndpointsFound    int
	RequestsMade      int
	Findings          []Finding
	ProvenFindings    []domain.ProvenFinding
	ProofBundles      []*report.ProofBundle
	GatingPassed      bool
	GatingSummary     string
	Report            string
}

// Scanner is the autonomous security research engine.
// Give it a URL and it will discover, test, and prove vulnerabilities.
type Scanner struct {
	config    ScanConfig
	client    *RateLimitedClient
	logLines  []string
	logFn     func(string)
}

// NewScanner creates an autonomous scanner ready to hunt bugs.
func NewScanner(cfg ScanConfig) *Scanner {
	if cfg.Budget <= 0 {
		cfg.Budget = 200
	}
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = 10
	}
	if cfg.TimeoutMinutes <= 0 {
		cfg.TimeoutMinutes = 5
	}
	if len(cfg.SecretKey) == 0 {
		cfg.SecretKey = []byte("doge-autonomous-scanner-seal-2026")
	}

	client := NewRateLimitedClient(ClientConfig{
		RatePerSecond:  cfg.RatePerSecond,
		Budget:         cfg.Budget,
		TimeoutSeconds: 15,
		Headers:        cfg.CustomHeaders,
		FollowRedirect: false,
		SkipTLSVerify:  cfg.SkipTLSVerify,
	})

	s := &Scanner{
		config:   cfg,
		client:   client,
		logLines: make([]string, 0, 200),
	}
	s.logFn = func(msg string) {
		line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
		s.logLines = append(s.logLines, line)
		fmt.Println(line)
	}
	return s
}

// Run executes the complete autonomous security scan pipeline.
func (s *Scanner) Run(ctx context.Context) (*ScanResult, error) {
	start := time.Now()
	timeout := time.Duration(s.config.TimeoutMinutes) * time.Minute
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	s.logFn("========================================================")
	s.logFn("🐕 DOGE Autonomous Security Scanner")
	s.logFn("========================================================")
	s.logFn(fmt.Sprintf("Target:  %s", s.config.TargetURL))
	s.logFn(fmt.Sprintf("Budget:  %d requests", s.config.Budget))
	s.logFn(fmt.Sprintf("Rate:    %d req/s", s.config.RatePerSecond))
	s.logFn(fmt.Sprintf("Timeout: %d minutes", s.config.TimeoutMinutes))
	s.logFn("========================================================")
	s.logFn("")

	// PHASE 1: Endpoint Discovery
	s.logFn("━━━ PHASE 1: Reconnaissance & Endpoint Discovery ━━━")
	discovery := NewDiscovery(s.client, s.config.TargetURL, s.config.OutOfScope, s.logFn)
	endpoints := discovery.Run()
	s.logFn(fmt.Sprintf("Discovered %d live endpoints (used %d/%d requests)", len(endpoints), s.client.RequestsSent(), s.config.Budget))
	s.logFn("")

	if len(endpoints) == 0 {
		s.logFn("[!] No live endpoints found. Target may be down or blocking requests.")
		return &ScanResult{
			TargetURL:  s.config.TargetURL,
			StartedAt:  start,
			FinishedAt: time.Now(),
			Duration:   time.Since(start),
		}, nil
	}

	// Check context
	select {
	case <-ctx.Done():
		s.logFn("[!] Scan timeout reached during discovery phase")
		return &ScanResult{
			TargetURL:      s.config.TargetURL,
			StartedAt:      start,
			FinishedAt:     time.Now(),
			Duration:       time.Since(start),
			EndpointsFound: len(endpoints),
			RequestsMade:   s.client.RequestsSent(),
		}, nil
	default:
	}

	// PHASE 2: Vulnerability Detection
	s.logFn("━━━ PHASE 2: Vulnerability Detection & Testing ━━━")
	detector := NewDetector(s.client, s.config.TargetURL, s.logFn)
	findings := detector.RunAll(endpoints)
	s.logFn(fmt.Sprintf("Found %d vulnerabilities (used %d/%d requests)", len(findings), s.client.RequestsSent(), s.config.Budget))
	s.logFn("")

	// PHASE 3: Generate Cryptographic Proofs
	s.logFn("━━━ PHASE 3: Cryptographic Proof Generation ━━━")
	provenFindings, proofBundles := s.generateProofs(findings)
	s.logFn(fmt.Sprintf("Sealed %d proof bundles with SHA-256 Merkle chain", len(proofBundles)))
	s.logFn("")

	// PHASE 4: Generate Report
	s.logFn("━━━ PHASE 4: Report Generation ━━━")
	reportText := s.generateReport(provenFindings, proofBundles, endpoints, start)

	finish := time.Now()

	s.logFn("")
	s.logFn("========================================================")
	s.logFn("🏁 SCAN COMPLETE")
	s.logFn(fmt.Sprintf("   Duration:       %v", finish.Sub(start).Round(time.Millisecond)))
	s.logFn(fmt.Sprintf("   Endpoints:      %d discovered", len(endpoints)))
	s.logFn(fmt.Sprintf("   Requests:       %d / %d budget", s.client.RequestsSent(), s.config.Budget))
	s.logFn(fmt.Sprintf("   Vulnerabilities: %d found", len(findings)))
	s.logFn(fmt.Sprintf("   Proof Bundles:  %d sealed", len(proofBundles)))
	s.logFn("========================================================")

	return &ScanResult{
		TargetURL:      s.config.TargetURL,
		StartedAt:      start,
		FinishedAt:     finish,
		Duration:       finish.Sub(start),
		EndpointsFound: len(endpoints),
		RequestsMade:   s.client.RequestsSent(),
		Findings:       findings,
		ProvenFindings: provenFindings,
		ProofBundles:   proofBundles,
		Report:         reportText,
	}, nil
}

func (s *Scanner) generateProofs(findings []Finding) ([]domain.ProvenFinding, []*report.ProofBundle) {
	provenFindings := make([]domain.ProvenFinding, 0, len(findings))
	proofBundles := make([]*report.ProofBundle, 0, len(findings))

	for _, f := range findings {
		if f.Confidence < 0.6 {
			continue
		}

		findingID := uuid.New()
		bundleID := uuid.New()
		now := time.Now().UTC()

		// Build replay steps from evidence
		steps := make([]report.ReplayStep, 0, len(f.Evidence))
		for i, ev := range f.Evidence {
			payloadHash := sha256Hash(ev.ReqBody)
			responseHash := sha256Hash(string(ev.Body))

			step := report.ReplayStep{
				Index:          i,
				Method:         ev.Method,
				URL:            ev.URL,
				Headers:        ev.ReqHeaders,
				Body:           ev.ReqBody,
				ExpectedStatus: ev.StatusCode,
				PayloadHash:    payloadHash,
				ResponseHash:   responseHash,
				Timestamp:      now,
			}

			// Extract a body substring for verification
			bodyStr := string(ev.Body)
			if len(bodyStr) > 100 {
				step.ExpectedBodySubstring = bodyStr[:100]
			} else if len(bodyStr) > 0 {
				step.ExpectedBodySubstring = bodyStr
			}

			steps = append(steps, step)
		}

		if len(steps) == 0 {
			continue
		}

		// Compute step hashes and chain
		stepHashes := make([]string, len(steps))
		for i, st := range steps {
			stepHashes[i] = report.BuildStepHash(st)
		}

		genesis := fmt.Sprintf("DOGE-GENESIS:%s:%s", bundleID.String(), findingID.String())
		chainDigest := report.ComputeChainDigest(genesis, stepHashes)
		merkleRoot := report.ComputeMerkleRoot(stepHashes)

		sig := report.SignAttestation(bundleID, findingID, chainDigest, merkleRoot, s.config.SecretKey)

		bundle := &report.ProofBundle{
			ID:                 bundleID,
			FindingID:          findingID,
			VulnerabilityClass: string(f.Type),
			TargetURL:          f.Endpoint,
			DiscoveredAt:       now,
			Steps:              steps,
			StepHashes:         stepHashes,
			ChainDigest:        chainDigest,
			MerkleRoot:         merkleRoot,
			Attestation: report.AttestationRecord{
				EngineVersion: report.DogeEngineVersion,
				EngineCommit:  report.DogeEngineCommit,
				SignerKeyID:   report.DefaultKeyID,
				ExecutionHost: "doge-autonomous-scanner",
				AttestedAt:    now,
				HMACSignature: sig,
			},
		}

		provenFinding := domain.ProvenFinding{
			ID:          findingID,
			Title:       f.Title,
			Type:        string(f.Type),
			Severity:    f.Severity,
			Endpoint:    f.Endpoint,
			Description: f.Description,
			ValidatedAt: now,
		}

		proofBundles = append(proofBundles, bundle)
		provenFindings = append(provenFindings, provenFinding)

		s.logFn(fmt.Sprintf("[PROOF] Sealed: %s [%s] — Merkle: %s", f.Title, f.Severity, merkleRoot[:16]+"..."))
	}

	return provenFindings, proofBundles
}

func (s *Scanner) generateReport(findings []domain.ProvenFinding, bundles []*report.ProofBundle, endpoints []*DiscoveredEndpoint, startTime time.Time) string {
	var b strings.Builder

	b.WriteString("# DOGE Autonomous Security Assessment Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s\n", s.config.TargetURL))
	b.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	b.WriteString(fmt.Sprintf("**Duration:** %v\n", time.Since(startTime).Round(time.Millisecond)))
	b.WriteString(fmt.Sprintf("**Endpoints Discovered:** %d\n", len(endpoints)))
	b.WriteString(fmt.Sprintf("**Requests Made:** %d / %d\n", s.client.RequestsSent(), s.config.Budget))
	b.WriteString(fmt.Sprintf("**Vulnerabilities Found:** %d\n\n", len(findings)))

	if len(findings) == 0 {
		b.WriteString("No vulnerabilities were discovered during this scan.\n")
		return b.String()
	}

	b.WriteString("---\n\n## Findings\n\n")

	// Group by severity
	severityOrder := []string{"Critical", "High", "Medium", "Low", "Info"}
	for _, sev := range severityOrder {
		for i, f := range findings {
			if f.Severity != sev {
				continue
			}

			b.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, f.Severity, f.Title))
			b.WriteString(fmt.Sprintf("- **Type:** %s\n", f.Type))
			b.WriteString(fmt.Sprintf("- **Endpoint:** `%s`\n", f.Endpoint))
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))

			// Find matching proof bundle
			for _, bundle := range bundles {
				if bundle.FindingID == f.ID {
					b.WriteString(fmt.Sprintf("- **Proof Bundle:** `%s`\n", bundle.ID))
					b.WriteString(fmt.Sprintf("- **Merkle Root:** `%s`\n", bundle.MerkleRoot))
					b.WriteString(fmt.Sprintf("- **Chain Digest:** `%s`\n", bundle.ChainDigest))
					b.WriteString(fmt.Sprintf("- **HMAC Sealed:** ✅\n"))
					break
				}
			}

			b.WriteString("\n")
		}
	}

	b.WriteString("---\n\n## Discovered Endpoints\n\n")
	b.WriteString("| # | URL | Status | Source |\n")
	b.WriteString("|---|-----|--------|--------|\n")
	for i, ep := range endpoints {
		b.WriteString(fmt.Sprintf("| %d | `%s` | %d | %s |\n", i+1, ep.URL, ep.StatusCode, ep.Source))
	}

	b.WriteString("\n---\n\n*Generated by DOGE Autonomous Security Scanner v7.0.0-enterprise*\n")

	return b.String()
}

func sha256Hash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
