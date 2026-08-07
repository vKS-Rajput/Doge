package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newTimelineCmd creates the 'timeline' command.
func newTimelineCmd() *cobra.Command {
	var wsPath string
	var limit int

	cmd := &cobra.Command{
		Use:   "timeline",
		Short: "Show workspace event timeline",
		Long: `Show a chronological timeline of all significant workspace events.

Events include:
  • Artifact imports
  • Observation creation
  • Entity discovery and enrichment
  • Relationship creation`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			entries, err := application.TimelineEntries(cmd.Context(), limit)
			if err != nil {
				return fmt.Errorf("failed to query timeline: %w", err)
			}

			if len(entries) == 0 {
				fmt.Println("No timeline events yet.")
				fmt.Println("\nImport a file to get started:")
				fmt.Println("  doge import <file>")
				return nil
			}

			fmt.Printf("Timeline (%d events)\n", len(entries))
			fmt.Println("─────────────────────────────────────────────")

			for _, e := range entries {
				ts := e.OccurredAt.Format(time.RFC3339)
				fmt.Printf("  %s  │  %s\n", ts, e.Action)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	cmd.Flags().IntVar(&limit, "limit", 25, "maximum number of events to show")
	return cmd
}
