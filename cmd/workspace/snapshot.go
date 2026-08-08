package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newSnapshotCmd creates the 'snapshot' command.
func newSnapshotCmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "snapshot [label]",
		Short: "Take a Knowledge Graph snapshot",
		Long: `Take a point-in-time snapshot of the Knowledge Graph.

Snapshots capture entity state hashes for efficient diffing.
Use 'doge diff' to compare two snapshots.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			label := time.Now().Format("2006-01-02T15:04:05")
			if len(args) > 0 {
				label = args[0]
			}

			snap, err := application.TakeSnapshot(cmd.Context(), label)
			if err != nil {
				return fmt.Errorf("failed to take snapshot: %w", err)
			}

			fmt.Printf("Snapshot created: %s\n", label)
			fmt.Printf("  ID:            %s\n", snap.ID.String()[:8])
			fmt.Printf("  Entities:      %d\n", snap.EntityCount)
			fmt.Printf("  Relationships: %d\n", snap.RelationshipCount)
			fmt.Printf("  Observations:  %d\n", snap.ObservationCount)
			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	return cmd
}

// newSnapshotsCmd creates the 'snapshots' list command.
func newSnapshotsCmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "snapshots",
		Short: "List Knowledge Graph snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			snapshots, err := application.ListSnapshots(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to list snapshots: %w", err)
			}

			if len(snapshots) == 0 {
				fmt.Println("No snapshots yet.")
				fmt.Println("\nTake a snapshot:")
				fmt.Println("  doge snapshot [label]")
				return nil
			}

			fmt.Printf("Snapshots (%d)\n", len(snapshots))
			fmt.Println("─────────────────────────────────────────────")

			for _, s := range snapshots {
				fmt.Printf("  %s  │  %-20s  │  %d entities  │  %d rels\n",
					s.ID.String()[:8], s.Label, s.EntityCount, s.RelationshipCount)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	return cmd
}
