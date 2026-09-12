package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/gates"
)

func newPolicyCmd() *cobra.Command {
	var autonomyLevel int

	cmd := &cobra.Command{
		Use:     "policy",
		Aliases: []string{"safety", "rules"},
		Short:   "Inspect and configure deterministic safety policies, budgets, and autonomy levels",
		Long: `DOGE Safety & Policy Engine — Configures hard scope boundaries, rate limits,
request budgets, tool permissions, and autonomy governance.

Autonomy Levels:
  Level 0: Observe Only (Passive mapping, zero invasive requests)
  Level 1: Analyze & Suggest (Generate hypotheses and experiment plans without execution)
  Level 2: Execute Low-Risk Authorized Research (Recon and schema probes automatically)
  Level 3: Autonomous Research with Approval Gates (High-risk probes paused for approval)
  Level 4: Long-Running Autonomous Research under Bounded Policy (Default production hunt)
  Level 5: Self-Directed Research within Strict Authorization and Safety Boundaries`,
		Run: func(cmd *cobra.Command, args []string) {
			pol := gates.DefaultEnterprisePolicy()

			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
			fmt.Println("║               🐕 DOGE DETERMINISTIC SAFETY POLICY                ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
			fmt.Printf(" Active Autonomy Level:   Level %d\n", autonomyLevel)
			fmt.Printf(" Rate Limit Ceiling:      25 requests/second\n")
			fmt.Printf(" Request Budget Ceiling:  5,000 requests\n")
			fmt.Printf(" Fail-Closed Scope Gate:  ENABLED (Deterministic regex & CIDR checks)\n")
			fmt.Printf(" Human Approval Gate:     REQUIRED for State-Changing / Destructive Probes\n")
			fmt.Printf(" LLM Authorization Override: STRICTLY FORBIDDEN\n")
			fmt.Println("──────────────────────────────────────────────────────────────────")

			fmt.Println("\n🛡️ CI/CD & ENTERPRISE GATING THRESHOLDS:")
			fmt.Printf("  • Policy Name:           %s\n", pol.PolicyName)
			fmt.Printf("  • Max Allowed Severity:  %s\n", pol.Rules.MaxAllowedSeverity)
			fmt.Printf("  • Max Allowed CVSS:      %.1f\n", pol.Rules.MaxAllowedCVSS)
			fmt.Printf("  • Require Proof Bundle:  %v\n", pol.Rules.RequireProofBundle)
			fmt.Printf("  • Min Confidence:        %.2f\n", pol.Rules.MinEpistemicConfidence)
			fmt.Printf("  • Fail Closed:           %v\n", pol.Rules.FailClosed)

			fmt.Println("\n🔒 PERMITTED RESEARCH CAPABILITIES:")
			fmt.Println("  [X] Reconnaissance & Endpoint Discovery")
			fmt.Println("  [X] API Schema Contract Discovery & Verb Tampering")
			fmt.Println("  [X] Object Isolation & BOLA Differential Probes")
			fmt.Println("  [X] State Machine & Workflow Transition Integrity")
			fmt.Println("  [X] Metamorphic Invariant Induction")
			fmt.Println("  [X] Latent Race Window Timing Probes")
			fmt.Println("  [X] Cache Key Normalization Bleed Probes")
			fmt.Println("  [X] Independent Deterministic Validation")
			fmt.Println("  [ ] Destructive Exploitation (Requires Level 5 + Explicit Operator Key)")
		},
	}

	cmd.Flags().IntVarP(&autonomyLevel, "autonomy", "a", 4, "Set active autonomy level (0-5)")

	return cmd
}
