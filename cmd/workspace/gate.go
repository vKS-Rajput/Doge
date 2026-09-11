package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/report"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func newGateCmd() *cobra.Command {
	var (
		policyFile      string
		maxSevStr       string
		maxCVSS         float64
		requireProof    bool
		findingsPath    string
		proofBundlePath string
	)

	cmd := &cobra.Command{
		Use:   "gate",
		Short: "CI/CD security policy evaluation and fail-closed build gating",
		Long: `Evaluate security findings against organizational risk thresholds.
Enforces zero-false-positive validation via required cryptographic proof bundles,
maximum CVSS 3.1 score boundaries, and zero-tolerance disallowed CWE classes.
Exits with status 0 on pass, and status 1 on policy violation for CI/CD automation.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			policy := gates.DefaultEnterprisePolicy()

			if policyFile != "" {
				loaded, err := gates.LoadPolicyConfig(policyFile)
				if err != nil {
					return fmt.Errorf("failed loading policy from %s: %w", policyFile, err)
				}
				policy = *loaded
			} else {
				if maxSevStr != "" {
					policy.Rules.MaxAllowedSeverity = domain.Severity(maxSevStr)
				}
				if maxCVSS > 0 {
					policy.Rules.MaxAllowedCVSS = maxCVSS
				}
				policy.Rules.RequireProofBundle = requireProof
			}

			var findings []domain.Finding
			if findingsPath != "" {
				data, err := os.ReadFile(findingsPath)
				if err != nil {
					return fmt.Errorf("failed reading findings from %s: %w", findingsPath, err)
				}
				if err := json.Unmarshal(data, &findings); err != nil {
					return fmt.Errorf("failed parsing findings JSON: %w", err)
				}
			}

			var bundles []*report.ProofBundle
			if proofBundlePath != "" {
				data, err := os.ReadFile(proofBundlePath)
				if err != nil {
					return fmt.Errorf("failed reading proof bundles from %s: %w", proofBundlePath, err)
				}
				if err := json.Unmarshal(data, &bundles); err != nil {
					return fmt.Errorf("failed parsing proof bundles JSON: %w", err)
				}
			}

			verdict := gates.EvaluatePolicy(findings, bundles, policy)

			fmt.Println()
			fmt.Println("🛡️  ========================================================")
			fmt.Printf("🛡️  CI/CD Security Policy Gate: %s\n", verdict.PolicyName)
			fmt.Println("🛡️  ========================================================")
			fmt.Printf("📊 Evaluated Findings: %d | Violations: %d\n", verdict.TotalFindings, verdict.TotalViolations)
			fmt.Printf("⏱️  Evaluated At:        %s\n", verdict.EvaluatedAt.Format("2006-01-02 15:04:05 UTC"))
			fmt.Println()

			if verdict.Passed {
				fmt.Printf("✅ PASS: %s\n\n", verdict.Summary)
				return nil
			}

			fmt.Printf("❌ FAIL: %s\n\n", verdict.Summary)
			fmt.Println("Violations:")
			for i, v := range verdict.Violations {
				fmt.Printf("  [%d] Rule: %s | Severity: %s | CVSS: %.1f | CWE: %s\n",
					i+1, v.RuleName, v.Severity, v.CVSS, v.CWE)
				fmt.Printf("      Title:  %s\n", v.FindingTitle)
				fmt.Printf("      Reason: %s\n\n", v.Reason)
			}

			return fmt.Errorf("security policy gate failure: %d violation(s) detected", verdict.TotalViolations)
		},
	}

	cmd.Flags().StringVarP(&policyFile, "policy", "p", "", "Path to custom security policy JSON file")
	cmd.Flags().StringVar(&maxSevStr, "max-severity", "medium", "Maximum allowed finding severity (low, medium, high, critical)")
	cmd.Flags().Float64Var(&maxCVSS, "max-cvss", 7.0, "Maximum allowed CVSS 3.1 base score")
	cmd.Flags().BoolVar(&requireProof, "require-proof", true, "Require tamper-evident cryptographic proof bundle for each finding")
	cmd.Flags().StringVar(&findingsPath, "findings", "", "Path to findings JSON file to evaluate")
	cmd.Flags().StringVar(&proofBundlePath, "proofs", "", "Path to proof bundles JSON file")

	return cmd
}
