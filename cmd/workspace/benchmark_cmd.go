package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/benchmark"
)

func newBenchmarkCmd() *cobra.Command {
	var (
		scenarioID string
		maxIter    int
		reportPath string
	)

	cmd := &cobra.Command{
		Use:     "benchmark",
		Aliases: []string{"bench"},
		Short:   "Execute adversarial security research benchmarks and evaluate discovery accuracy",
		Long: `DOGE Adversarial Research Benchmark Suite — Tests autonomous discovery,
falsification rate, distractor rejection, and epistemic efficiency against planted vulnerabilities.

Challenges include:
  - scenario-bola-vs-honeypot: Multi-Tenant BOLA vs Hardened Admin Decoy
  - scenario-ssrf-falsification: Out-of-Band SSRF with Whitelist Refutation Decoy
  - scenario-priv-esc: Vertical Privilege Escalation on Role Management

Examples:
  doge benchmark
  doge benchmark --scenario scenario-bola-vs-honeypot
  doge benchmark --report scorecard.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			suite := benchmark.DefaultBenchmarkSuite()

			if scenarioID != "" {
				var filtered []*benchmark.BenchmarkScenario
				for _, sc := range suite {
					if sc.ID == scenarioID {
						filtered = append(filtered, sc)
					}
				}
				if len(filtered) == 0 {
					return fmt.Errorf("scenario '%s' not found in benchmark suite", scenarioID)
				}
				suite = filtered
			}

			if maxIter > 0 {
				for _, sc := range suite {
					sc.MaxAllowedIter = maxIter
				}
			}

			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
			fmt.Println("║       🐕 DOGE ADVERSARIAL SECURITY RESEARCH BENCHMARK            ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
			fmt.Printf(" Running Scenarios: %d\n", len(suite))
			for i, sc := range suite {
				fmt.Printf("   [%d] %s — %s\n", i+1, sc.ID, sc.Title)
			}
			fmt.Println("──────────────────────────────────────────────────────────────────")

			runner := benchmark.NewRunner()
			ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
			defer cancel()

			startTime := time.Now()
			scorecard, err := runner.RunSuite(ctx, suite)
			if err != nil {
				return fmt.Errorf("benchmark run failed: %w", err)
			}
			duration := time.Since(startTime).Round(time.Millisecond)

			fmt.Println()
			fmt.Println("══════════════════════════════════════════════════════════════════")
			fmt.Println("                   BENCHMARK SCORECARD                            ")
			fmt.Println("══════════════════════════════════════════════════════════════════")
			fmt.Printf(" Total Scenarios:         %d\n", scorecard.TotalScenarios)
			fmt.Printf(" Passed Scenarios:        %d / %d (%.1f%%)\n", scorecard.PassedScenarios, scorecard.TotalScenarios, scorecard.PassRatePercent)
			fmt.Printf(" Distractors Refuted:     %d / %d (%.1f%%)\n", scorecard.FalsifiedDistractors, scorecard.TotalDistractors, scorecard.FalsificationRate)
			fmt.Printf(" Average Iterations:      %.1f\n", scorecard.AverageIterations)
			fmt.Printf(" Suite Duration:          %v\n", duration)
			fmt.Println("──────────────────────────────────────────────────────────────────")

			for _, res := range scorecard.ScenarioResults {
				passStr := "✅ PASS"
				if !res.Passed {
					passStr = "❌ FAIL"
				}
				fmt.Printf(" %s  [%s] %s (Iter: %d/%d, Duration: %v)\n",
					passStr, res.ScenarioID, res.Title, res.IterationsUsed, res.MaxAllowedIter, res.Duration.Round(time.Millisecond))
				fmt.Printf("       %s\n", res.Notes)
			}

			if reportPath != "" {
				reportMarkdown := fmt.Sprintf("# DOGE Adversarial Benchmark Scorecard\n\n"+
					"- **Date**: %s\n"+
					"- **Pass Rate**: %.1f%% (%d/%d)\n"+
					"- **Distractor Falsification Rate**: %.1f%% (%d/%d)\n"+
					"- **Average Iterations**: %.1f\n\n"+
					"## Scenario Results\n\n",
					time.Now().Format(time.RFC3339),
					scorecard.PassRatePercent, scorecard.PassedScenarios, scorecard.TotalScenarios,
					scorecard.FalsificationRate, scorecard.FalsifiedDistractors, scorecard.TotalDistractors,
					scorecard.AverageIterations,
				)
				for _, res := range scorecard.ScenarioResults {
					reportMarkdown += fmt.Sprintf("### %s: %s\n- **Passed**: %v\n- **Iterations**: %d/%d\n- **Notes**: %s\n\n",
						res.ScenarioID, res.Title, res.Passed, res.IterationsUsed, res.MaxAllowedIter, res.Notes)
				}
				_ = os.WriteFile(reportPath, []byte(reportMarkdown), 0644)
				fmt.Printf("\n📄 Scorecard saved to: %s\n", reportPath)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&scenarioID, "scenario", "s", "", "Run specific scenario by ID")
	cmd.Flags().IntVarP(&maxIter, "iterations", "i", 5, "Override max iterations per scenario")
	cmd.Flags().StringVarP(&reportPath, "report", "r", "", "Filepath to save the scorecard report (.md)")

	return cmd
}
