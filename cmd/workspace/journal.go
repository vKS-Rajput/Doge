package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/journal"
)

// newJournalCmd creates the 'journal' command to view execution history.
func newJournalCmd() *cobra.Command {
	var wsPath string
	var toolFilter string
	var limit int

	cmd := &cobra.Command{
		Use:   "journal",
		Short: "View command execution history",
		Long: `Show the investigation journal — every tool execution DOGE has recorded.

Each entry includes the tool, command, target, timestamps, observation count,
and researcher notes.

Examples:
  doge journal              # last 20 entries
  doge journal --limit 50   # last 50 entries
  doge journal --tool nmap  # only nmap entries`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			absPath, _ := filepath.Abs(wsPath)
			journalDB, err := openJournalDB(absPath)
			if err != nil {
				return fmt.Errorf("failed to open journal: %w", err)
			}
			defer journalDB.Close()

			store := journal.NewStore(journalDB)
			if err := store.EnsureTable(); err != nil {
				return fmt.Errorf("journal table: %w", err)
			}

			var entries []journal.Execution
			if toolFilter != "" {
				entries, err = store.ByTool(application.DefaultProjectID, toolFilter)
			} else {
				entries, err = store.Recent(application.DefaultProjectID, limit)
			}
			if err != nil {
				return fmt.Errorf("querying journal: %w", err)
			}

			if len(entries) == 0 {
				fmt.Println()
				fmt.Println("🐕 DOGE Journal — Empty")
				fmt.Println()
				fmt.Println("  No commands recorded yet.")
				fmt.Println("  Use 'doge ingest <file>' to feed tool output.")
				fmt.Println()
				return nil
			}

			count, _ := store.Count(application.DefaultProjectID)
			totalObs, _ := store.TotalObservations(application.DefaultProjectID)

			fmt.Println()
			fmt.Println("🐕 DOGE Investigation Journal")
			fmt.Printf("  Total entries: %d | Total observations: %d\n", count, totalObs)
			fmt.Println("────────────────────────────────────")
			fmt.Println()

			for i, e := range entries {
				ago := time.Since(e.IngestedAt).Round(time.Second)
				fmt.Printf("  #%d  %s\n", i+1, e.Tool)
				if e.Command != "" {
					fmt.Printf("      Command: %s\n", e.Command)
				}
				fmt.Printf("      Target:  %s\n", e.Target)
				fmt.Printf("      Result:  %d observations\n", e.Observations)
				fmt.Printf("      When:    %s (%v ago)\n", e.IngestedAt.Format("15:04:05"), ago)
				if e.Notes != "" {
					fmt.Printf("      Notes:   %s\n", e.Notes)
				}
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	cmd.Flags().StringVar(&toolFilter, "tool", "", "filter by tool name")
	cmd.Flags().IntVar(&limit, "limit", 20, "number of entries to show")

	return cmd
}
