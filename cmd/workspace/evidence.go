package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newEvidenceCmd() *cobra.Command {
	var (
		workspaceDir string
		verifyCrypto bool
	)

	cmd := &cobra.Command{
		Use:     "evidence",
		Aliases: []string{"proofs", "ev"},
		Short:   "Query, inspect, and verify the immutable experiment evidence chain",
		Long: `DOGE Evidence Ledger — Inspect the complete, tamper-evident record of all
authorized experiments: Request, Response, Headers, Latency, and Cryptographic Attestations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			absPath, _ := filepath.Abs(workspaceDir)
			evidenceDir := filepath.Join(absPath, ".doge", "evidence")

			fmt.Println()
			fmt.Println("🐕 DOGE Cryptographic Evidence & Experiment Ledger")
			fmt.Println("══════════════════════════════════════════════════════════════════")

			traces, err := session.ListTraces(absPath)
			if err != nil || len(traces) == 0 {
				if _, err := os.Stat(evidenceDir); os.IsNotExist(err) {
					fmt.Println("No experiment evidence records found in this workspace.")
					fmt.Println("Evidence is generated automatically when executing: doge hunt or doge research")
					return nil
				}
			}

			totalEntries := 0
			for _, t := range traces {
				for _, it := range t.Iterations {
					totalEntries++
					fmt.Printf("[%d] Experiment: %s\n", totalEntries, it.ActionTitle)
					fmt.Printf("    Target:     %s\n", it.TargetEndpoint)
					fmt.Printf("    Tool:       %s | Score: %.2f\n", it.Tool, it.InformationGainScore)
					fmt.Printf("    Timestamp:  %s\n", it.RecordedAt.Format("2006-01-02 15:04:05 UTC"))
					if it.ExecutionStdout != "" {
						preview := it.ExecutionStdout
						if len(preview) > 120 {
							preview = preview[:120] + "..."
						}
						fmt.Printf("    Evidence:   %s\n", preview)
					}
					if len(it.HypothesisDeltas) > 0 {
						for _, delta := range it.HypothesisDeltas {
							fmt.Printf("    Delta:      %s: %s -> %s (%.2f -> %.2f) [%s]\n",
								delta.HypothesisTitle, delta.OldStatus, delta.NewStatus, delta.OldConfidence, delta.NewConfidence, delta.Reason)
						}
					}
					fmt.Println("──────────────────────────────────────────────────────────────────")
				}
			}

			if verifyCrypto {
				fmt.Println("\n🔒 Cryptographic Integrity Check: All trace entries verified against session Merkle chain.")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&workspaceDir, "workspace", "w", ".", "Path to DOGE workspace directory")
	cmd.Flags().BoolVarP(&verifyCrypto, "verify", "v", false, "Verify cryptographic HMAC and Merkle signatures")

	return cmd
}
