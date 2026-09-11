package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/coordinator"
	"github.com/vKS-Rajput/doge/internal/gates"
)

func newAutoCmd() *cobra.Command {
	var (
		budget      int
		whiteboxDir string
		timeout     time.Duration
		reportFile  string
	)

	cmd := &cobra.Command{
		Use:   "auto [target-url]",
		Short: "Run autonomous research fleet against a target",
		Long: `Executes the end-to-end autonomous research pipeline per DOGE-NEXT specification:
1. Surface Reconnaissance & Discovery
2. Deterministic AST / Whitebox Taint Analysis (if source path provided)
3. Minimum Description Length (MDL) Anomaly Detection
4. Representation Expansion (rho Operator)
5. Multi-Objective Pareto Strategy Synthesis & Static Type Checking
6. Tactical Execution Sandboxing with Budget Tracking
7. CEGAR Falsification & Version-Space Narrowing
8. Independent Deterministic Validation & Proven Finding Output
9. Tamper-Evident Cryptographic Proof Bundles
10. Fail-Closed CI/CD Security Gating & Multi-Format Reporting`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]

			fmt.Println()
			fmt.Println("🐕 ========================================================")
			fmt.Println("🐕 DOGE Autonomous Security Science System (Fleet Engine)")
			fmt.Println("🐕 ========================================================")
			fmt.Printf("🎯 Target: %s\n", targetURL)
			fmt.Printf("📊 Request Budget: %d | Timeout: %v\n", budget, timeout)

			engineCfg := coordinator.EngineConfig{
				TargetURL:   targetURL,
				Budget:      budget,
				Timeout:     timeout,
				WhiteboxDir: whiteboxDir,
				ReportPath:  reportFile,
				Policy:      gates.DefaultEnterprisePolicy(),
			}

			engine := coordinator.NewAutonomousEngine(engineCfg)
			res, err := engine.Run(cmd.Context())
			if err != nil {
				return fmt.Errorf("autonomous research engagement failed: %w", err)
			}

			fmt.Println()
			fmt.Println("🎯 Autonomous Research Engagement Complete.")
			fmt.Printf("⏱️  Execution Duration: %v\n", res.ExecutionDuration.Round(time.Millisecond))
			fmt.Printf("📊 Total Requests Made: %d\n", res.TotalRequests)
			fmt.Printf("💡 Proven Findings Discovered: %d\n", len(res.ProvenFindings))
			fmt.Printf("🔐 Cryptographic Proof Bundles: %d\n", len(res.ProofBundles))

			for i, pf := range res.ProvenFindings {
				fmt.Printf("  [%d] [%s] %s (%s)\n", i+1, pf.Severity, pf.Title, pf.Endpoint)
			}

			if res.GatingVerdict != nil {
				fmt.Println()
				if res.GatingVerdict.Passed {
					fmt.Printf("🛡️  CI/CD Gate Verdict: ✅ PASS (%s)\n", res.GatingVerdict.Summary)
				} else {
					fmt.Printf("🛡️  CI/CD Gate Verdict: ❌ FAIL (%s)\n", res.GatingVerdict.Summary)
				}
			}

			if reportFile != "" {
				fmt.Printf("📄 Assessment Report exported to: %s\n", reportFile)
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&budget, "budget", 100, "Maximum requests to issue")
	cmd.Flags().StringVar(&whiteboxDir, "whitebox", "", "Path to source directory for static taint analysis")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Execution timeout")
	cmd.Flags().StringVar(&reportFile, "report", "doge_report.md", "Output report markdown file")

	return cmd
}
