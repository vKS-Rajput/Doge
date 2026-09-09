package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/gates"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/research"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newResearchCmd() *cobra.Command {
	var (
		iterations   int
		rateLimit    int
		autoRecon    bool
		stepOnce     bool
	)

	cmd := &cobra.Command{
		Use:   "research [workspace]",
		Short: "Run the autonomous research loop engine",
		Long: `Executes the DOGE Epistemic Research Loop:
Observe → Understand → Hypothesize → Prioritize → Gate Check → Execute → Evaluate → Learn.

Enforces fail-closed hard scope boundaries, epistemic tiers, and human-in-the-loop decision gates.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wsPath := "."
			if len(args) > 0 {
				wsPath = args[0]
			}
			absPath, _ := filepath.Abs(wsPath)

			state, err := session.LoadState(absPath)
			if err != nil {
				fmt.Println("🐕 DOGE — No active session found.")
				fmt.Println("  Initialize with: doge start --target <domain/IP>")
				return nil
			}

			// Build Scope Engine (from persisted scope config or session target)
			cfg, err := scope.LoadConfig(absPath)
			if err != nil {
				cfg = &scope.Config{
					Target:      state.Target,
					Environment: string(state.Environment),
					InScope:     []string{state.Target, "*." + state.Target},
					Rules:       scope.DefaultProgramRules(),
				}
			}

			scopeEngine, err := scope.NewEngine(*cfg)
			if err != nil {
				return fmt.Errorf("initializing scope: %w", err)
			}

			gateMgr := gates.NewManager(absPath)
			parserReg := parser.NewRegistry(slog.Default())
			app.RegisterParsers(parserReg)

			mem := learning.NewMemory(nil)
			learner := learning.NewLearner(mem)

			researchCfg := research.Config{
				Target:          state.Target,
				Environment:     string(state.Environment),
				WorkspacePath:   absPath,
				MaxIterations:   iterations,
				RateLimitPerSec: rateLimit,
				AllowAutoRecon:  autoRecon || state.Environment == "htb" || state.Environment == "lab",
			}

			engine := research.NewLoopEngine(researchCfg, scopeEngine, gateMgr, parserReg, learner, mem)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Println("\n🛑 Research loop interrupted by user. Checkpointing state...")
				engine.Pause()
				cancel()
			}()

			fmt.Println()
			fmt.Println("🐕 DOGE Autonomous Research Engine")
			fmt.Printf("Target:       %s (%s)\n", state.Target, state.Environment)
			fmt.Printf("Auto-Recon:   %v\n", researchCfg.AllowAutoRecon)
			fmt.Printf("Iterations:   %d (max)\n", researchCfg.MaxIterations)
			fmt.Println("──────────────────────────────────────────")
			fmt.Println()

			for {
				if ctx.Err() != nil {
					break
				}

				res, err := engine.Step(ctx)
				if err != nil {
					fmt.Printf("⚠️  Step error: %v\n", err)
					break
				}

				snap := engine.GetSnapshot()

				// Display step output
				switch res.CurrentState {
				case research.StateGated:
					fmt.Printf("⏸️  [GATE] Paused at human gate: %s\n", res.PendingGate.Title)
					fmt.Printf("    Reason: %s\n", res.PendingGate.Description)
					fmt.Printf("    Type 'doge approvals' in another terminal to authorize or direct.\n\n")
					time.Sleep(3 * time.Second)

				case research.StateExecuting:
					if res.ActionExecuted != nil {
						fmt.Printf("⚙️  [EXEC] Phase: %s | Tool: %s on %s (Risk: %s)\n",
							res.ActionExecuted.Phase, res.ActionExecuted.Tool, res.ActionExecuted.Target, res.ActionExecuted.Risk)
					}

				case research.StatePlanning:
					if res.NewObservations > 0 || res.NewHypotheses > 0 {
						fmt.Printf("💡 [KNOWLEDGE] +%d observations, +%d research hypotheses\n",
							res.NewObservations, res.NewHypotheses)
					}

				case research.StateCompleted:
					fmt.Println("🏁 [COMPLETED] Research cycle finished.")
					fmt.Printf("   Total Entities: %d | Observations: %d | Hypotheses: %d\n",
						snap.EntityCount, snap.ObservationCount, len(snap.Hypotheses))
					return nil
				}

				if stepOnce {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&iterations, "iterations", "i", 50, "Maximum research loop iterations")
	cmd.Flags().IntVarP(&rateLimit, "rate-limit", "r", 10, "Maximum requests per second")
	cmd.Flags().BoolVar(&autoRecon, "auto-recon", false, "Auto-approve non-intrusive recon tools")
	cmd.Flags().BoolVar(&stepOnce, "step", false, "Execute exactly one research step and exit")

	return cmd
}
