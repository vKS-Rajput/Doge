package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/coordinator"
	"github.com/vKS-Rajput/doge/internal/db"
	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/session"
	"github.com/vKS-Rajput/doge/pkg/ai"
)

func newHuntCmd() *cobra.Command {
	var (
		budget      int
		rateLimit   int
		timeoutMins int
		autonomyLvl int
		whiteboxDir string
		reportPath  string
	)

	cmd := &cobra.Command{
		Use:   "hunt [target-url]",
		Short: "Launch end-to-end autonomous security research on an authorized target",
		Long: `DOGE Autonomous Security Research OS — "hunt" initiates the full cognitive loop:

  TARGET → OBSERVE → WORLD MODEL → UNKNOWN SPACE → HYPOTHESES → COMPETING HYPOTHESES
  → EXPERIMENT SELECTION (EIG) → AUTHORIZED EXECUTION → CONTRADICTION DETECTION
  → INDEPENDENT VALIDATION → ATTACK GRAPH → IMPACT → PROVEN FINDINGS → META-LEARNING.

DOGE operates autonomously under deterministic safety policies and stops when the
research objective is satisfied or budget is exhausted without requiring manual prompting.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]

			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
			fmt.Println("║               🐕 DOGE SECURITY RESEARCH OS — HUNT                ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
			fmt.Printf(" Target:         %s\n", targetURL)
			fmt.Printf(" Request Budget: %d requests\n", budget)
			fmt.Printf(" Rate Limit:     %d req/sec\n", rateLimit)
			fmt.Printf(" Timeout:        %d minutes\n", timeoutMins)
			fmt.Printf(" Autonomy Level: Level %d\n", autonomyLvl)
			if whiteboxDir != "" {
				fmt.Printf(" Whitebox AST:   %s\n", whiteboxDir)
			}
			fmt.Println("──────────────────────────────────────────────────────────────────")
			fmt.Println("◈ Booting Autonomous Research Kernel...")

			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutMins)*time.Minute)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Println("\n🛑 Research hunt halted by user. Finalizing evidence and proof bundles...")
				cancel()
			}()

			engineCfg := coordinator.EngineConfig{
				TargetURL:   targetURL,
				Budget:      budget,
				Timeout:     time.Duration(timeoutMins) * time.Minute,
				WhiteboxDir: whiteboxDir,
				ReportPath:  reportPath,
				SecretKey:   []byte("doge-enterprise-hunt-attestation-secret-key-2026"),
				Policy:      gates.DefaultEnterprisePolicy(),
				ModelRouter: ai.NewModelRouter("deterministic_brain"),
			}
			engineCfg.ModelRouter.RegisterProvider(ai.NewDeterministicModel())

			engine := coordinator.NewAutonomousEngine(engineCfg)

			fmt.Println("◈ Engaging Unified World Model & Research Frontier...")
			startTime := time.Now()

			res, err := engine.Run(ctx)
			if err != nil {
				return fmt.Errorf("autonomous hunt error: %w", err)
			}

			elapsed := time.Since(startTime).Round(time.Millisecond)

			fmt.Println()
			fmt.Println("══════════════════════════════════════════════════════════════════")
			fmt.Println("                   HUNT MISSION SUMMARY                           ")
			fmt.Println("══════════════════════════════════════════════════════════════════")
			fmt.Printf(" Duration:            %v\n", elapsed)
			fmt.Printf(" Requests Executed:   %d / %d\n", res.TotalRequests, budget)
			fmt.Printf(" Proven Findings:     %d\n", len(res.ProvenFindings))
			fmt.Printf(" Proof Bundles:       %d (HMAC-SHA256 Sealed)\n", len(res.ProofBundles))
			fmt.Printf(" Novelty Yield:       %.2f\n", res.NoveltyScore)

			if len(res.ProvenFindings) > 0 {
				fmt.Println()
				fmt.Println("PROVEN FINDINGS:")
				for i, pf := range res.ProvenFindings {
					fmt.Printf("  [%d] [%s] %s\n", i+1, pf.Severity, pf.Title)
					fmt.Printf("      Type:      %s\n", pf.Type)
					fmt.Printf("      Endpoint:  %s\n", pf.Endpoint)
					fmt.Printf("      Evidence:  %d discovery, %d validation, %d impact\n",
						len(pf.DiscoveryEvidence), len(pf.ValidationEvidence), len(pf.ImpactEvidence))
				}
			} else {
				fmt.Println("\n✓ No exploitable vulnerabilities verified within authorized boundaries.")
			}

			if reportPath != "" && res.GeneratedReport != "" {
				_ = os.WriteFile(reportPath, []byte(res.GeneratedReport), 0644)
				fmt.Printf("\n📄 Research report written to: %s\n", reportPath)
			}

			// Persist experiment trace to .doge/traces
			absPath, _ := filepath.Abs(".")
			traceRec := session.NewTraceRecorder(uuid.New(), targetURL, session.ProfileThorough)
			for i, pf := range res.ProvenFindings {
				stdoutPreview := pf.Description
				targetEndpoint := pf.Endpoint
				if len(pf.ValidationEvidence) > 0 {
					stdoutPreview = fmt.Sprintf("Validated %s at %s (%d ms)", pf.Type, pf.Endpoint, pf.ValidationEvidence[0].ResponseTimeMs)
					targetEndpoint = pf.ValidationEvidence[0].RequestURL
				}
				traceRec.RecordIteration(&session.IterationTraceEntry{
					IterationNumber:           i + 1,
					ActionTitle:               pf.Title,
					Tool:                      "AutonomousEngine/CEGAR",
					TargetEndpoint:            targetEndpoint,
					InformationGainScore:      0.95,
					ExecutionStdout:           stdoutPreview,
					ObservedObservationsCount: len(pf.ValidationEvidence) + len(pf.DiscoveryEvidence),
					RecordedAt:                pf.ValidatedAt,
				})
			}
			savedTrace := traceRec.Finalize(len(res.ProvenFindings), "Autonomous hunt completed")
			_ = session.SaveTrace(absPath, savedTrace)

			// Persist findings and entities if workspace DB exists
			dbPath := filepath.Join(absPath, ".doge", "workspace.db")
			if _, err := os.Stat(dbPath); err == nil {
				if dbConn, err := db.Open(dbPath, db.Options{WALMode: true}); err == nil {
					for _, pf := range res.ProvenFindings {
						_, _ = dbConn.Conn().ExecContext(ctx,
							`INSERT OR REPLACE INTO findings (id, title, description, severity, status, entity_ids, evidence_ids, project_id, created_at, updated_at)
							 VALUES (?, ?, ?, ?, ?, '[]', '[]', COALESCE((SELECT id FROM projects LIMIT 1), '00000000-0000-0000-0000-000000000000'), ?, ?)`,
							pf.ID.String(), pf.Title, pf.Description, pf.Severity, "confirmed",
							pf.ValidatedAt.Format(time.RFC3339), pf.ValidatedAt.Format(time.RFC3339),
						)
						_, _ = dbConn.Conn().ExecContext(ctx,
							`INSERT OR IGNORE INTO entities (id, type, canonical_value, display_name, project_id, first_seen_at, last_seen_at)
							 VALUES (?, 'endpoint', ?, ?, COALESCE((SELECT id FROM projects LIMIT 1), '00000000-0000-0000-0000-000000000000'), ?, ?)`,
							uuid.New().String(), pf.Endpoint, pf.Endpoint,
							pf.ValidatedAt.Format(time.RFC3339), pf.ValidatedAt.Format(time.RFC3339),
						)
					}
					_ = dbConn.Close()
				}
			}

			// Persist session state to .doge/session.json
			if _, err := os.Stat(filepath.Join(absPath, ".doge")); err == nil {
				persistedState := session.PersistedState{
					InvestigationID: savedTrace.InvestigationID,
					Target:          targetURL,
					Status:          session.StatusActive,
					Phase:           session.PhaseComplete,
					PhaseSummary:    fmt.Sprintf("Autonomous hunt completed: %d findings", len(res.ProvenFindings)),
					StartedAt:       startTime,
					UpdatedAt:       time.Now().UTC(),
					PID:             os.Getpid(),
					Observations:    res.TotalRequests,
					Entities:        len(res.ProvenFindings),
					Findings:        len(res.ProvenFindings),
					WorkspacePath:   absPath,
				}
				data, _ := json.MarshalIndent(persistedState, "", "  ")
				_ = os.WriteFile(filepath.Join(absPath, ".doge", "session.json"), data, 0644)
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&budget, "budget", "b", 100, "Maximum number of probe requests to execute")
	cmd.Flags().IntVarP(&rateLimit, "rate-limit", "r", 25, "Maximum requests per second")
	cmd.Flags().IntVarP(&timeoutMins, "timeout", "t", 10, "Mission timeout in minutes")
	cmd.Flags().IntVar(&autonomyLvl, "autonomy", 4, "Autonomy Level (0: Observe, 2: Auto-Recon, 4: Bounded Hunt, 5: Fully Autonomous)")
	cmd.Flags().StringVar(&whiteboxDir, "whitebox", "", "Path to source code directory for AST taint correlation")
	cmd.Flags().StringVar(&reportPath, "report", "", "Filepath to save the executive Markdown report")

	return cmd
}
