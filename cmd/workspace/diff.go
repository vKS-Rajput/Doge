package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newDiffCmd creates the 'diff' command.
func newDiffCmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "diff <snapshot-a> <snapshot-b>",
		Short: "Compare two Knowledge Graph snapshots",
		Long: `Compute structural differences between two snapshots.

Shows what entities were added, removed, or changed between
two points in time.

Use 'doge snapshots' to list available snapshot IDs.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			// Resolve snapshot IDs. Support short IDs (first 8 chars).
			snapAID, err := resolveSnapshotID(cmd.Context(), application, args[0])
			if err != nil {
				return fmt.Errorf("snapshot A: %w", err)
			}
			snapBID, err := resolveSnapshotID(cmd.Context(), application, args[1])
			if err != nil {
				return fmt.Errorf("snapshot B: %w", err)
			}

			result, err := application.ComputeDiff(cmd.Context(), snapAID, snapBID)
			if err != nil {
				return fmt.Errorf("diff failed: %w", err)
			}

			// Display.
			fmt.Printf("Diff: %s → %s\n", result.SnapshotA.Label, result.SnapshotB.Label)
			fmt.Println("─────────────────────────────────────────────")

			if len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Changed) == 0 {
				fmt.Println("  No differences.")
				return nil
			}

			if len(result.Added) > 0 {
				fmt.Printf("\n  Added (%d)\n", len(result.Added))
				for _, c := range result.Added {
					fmt.Printf("    + %-14s  %s\n", c.EntityType, c.Value)
				}
			}

			if len(result.Removed) > 0 {
				fmt.Printf("\n  Removed (%d)\n", len(result.Removed))
				for _, c := range result.Removed {
					fmt.Printf("    - %-14s  %s\n", c.EntityType, c.Value)
				}
			}

			if len(result.Changed) > 0 {
				fmt.Printf("\n  Changed (%d)\n", len(result.Changed))
				for _, c := range result.Changed {
					fmt.Printf("    ~ %-14s  %s\n", c.EntityType, c.Value)
				}
			}

			fmt.Printf("\nSummary: %s\n", result.Summary())
			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	return cmd
}

// resolveSnapshotID resolves a full or short (prefix) snapshot ID.
func resolveSnapshotID(ctx context.Context, application *app.App, idStr string) (uuid.UUID, error) {
	// Try full UUID first.
	if id, err := uuid.Parse(idStr); err == nil {
		return id, nil
	}

	// Short ID — scan snapshots for prefix match.
	snapshots, err := application.ListSnapshots(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("listing snapshots: %w", err)
	}

	for _, s := range snapshots {
		full := s.ID.String()
		if len(idStr) <= len(full) && full[:len(idStr)] == idStr {
			return s.ID, nil
		}
	}

	return uuid.Nil, fmt.Errorf("snapshot not found: %s", idStr)
}
