package main

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newMissionCmd() *cobra.Command {
	var workspaceDir string

	cmd := &cobra.Command{
		Use:     "mission",
		Aliases: []string{"missions"},
		Short:   "Inspect and manage research missions and autonomous briefs",
		Long: `Inspect and review DOGE autonomous research missions, their assigned
researchers, scope briefs, hypothesis updates, and evidence traces.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			absPath, _ := filepath.Abs(workspaceDir)
			state, err := session.LoadState(absPath)
			if err != nil {
				fmt.Println("🐕 DOGE — No active research session found in workspace.")
				fmt.Println("  Start a research mission with: doge hunt <target> or doge research")
				return nil
			}

			fmt.Println()
			fmt.Printf("🐕 DOGE Missions for Target: %s (%s)\n", state.Target, state.Environment)
			fmt.Printf("   Current Phase: %s\n", state.Phase)
			fmt.Printf("   Entities: %d | Observations: %d | Hypotheses: %d | Findings: %d\n",
				state.Entities, state.Observations, state.Hypotheses, state.Findings)
			fmt.Println("──────────────────────────────────────────────────────────────────")

			traces, err := session.ListTraces(absPath)
			if err != nil || len(traces) == 0 {
				fmt.Println("No recorded mission traces found.")
				return nil
			}

			fmt.Printf("Found %d recorded research mission traces:\n\n", len(traces))
			for i, t := range traces {
				fmt.Printf("[%d] Trace ID:      %s\n", i+1, t.ID)
				fmt.Printf("    Target:        %s\n", t.Target)
				fmt.Printf("    Started:       %s\n", t.StartedAt.Format("2006-01-02 15:04:05 UTC"))
				fmt.Printf("    Iterations:    %d\n", len(t.Iterations))
				fmt.Printf("    Findings:      %d\n", t.TotalFindings)
				fmt.Printf("    Summary:       %s\n", t.FinalSummary)
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&workspaceDir, "workspace", "w", ".", "Path to DOGE workspace directory")

	return cmd
}
