package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// newGraphCmd creates the 'graph' command group.
func newGraphCmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Knowledge Graph commands",
		Long:  `Interact with the Knowledge Graph: view statistics, inspect entities, and explore relationships.`,
	}

	// Subcommand: graph stats
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show Knowledge Graph statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			stats, err := application.GraphStats(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to get graph stats: %w", err)
			}

			fmt.Println("Knowledge Graph")
			fmt.Println("─────────────────────────────────────────────")
			fmt.Printf("  Entities:       %d\n", stats.EntityCount)
			fmt.Printf("  Relationships:  %d\n", stats.RelationshipCount)
			fmt.Printf("  Observations:   %d\n", stats.ObservationCount)
			fmt.Printf("  Artifacts:      %d\n", stats.ArtifactCount)

			if len(stats.EntityCountByType) > 0 {
				fmt.Println()
				fmt.Println("  Entity Types:")
				for t, count := range stats.EntityCountByType {
					fmt.Printf("    %-20s %d\n", t, count)
				}
			}

			return nil
		},
	}

	// Subcommand: graph entities
	entitiesCmd := &cobra.Command{
		Use:   "entities [query]",
		Short: "List or search entities",
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			query := ""
			if len(args) > 0 {
				query = args[0]
			}

			var entities []domain.Entity
			if query != "" {
				entities, err = application.GraphSearch(cmd.Context(), query, 50)
			} else {
				entities, err = application.GraphSearch(cmd.Context(), "", 50)
			}
			if err != nil {
				return fmt.Errorf("failed to query entities: %w", err)
			}

			if len(entities) == 0 {
				fmt.Println("No entities found.")
				return nil
			}

			fmt.Printf("Entities (%d)\n", len(entities))
			fmt.Println("─────────────────────────────────────────────")

			for _, e := range entities {
				fmt.Printf("  %-14s  %s  (%d obs)\n",
					e.Type, e.Value, e.ObservationCount)
			}

			return nil
		},
	}

	statsCmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	entitiesCmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")

	cmd.AddCommand(statsCmd, entitiesCmd)
	return cmd
}
