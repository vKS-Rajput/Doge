package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newSearchCmd creates the 'search' command.
func newSearchCmd() *cobra.Command {
	var wsPath string
	var limit int

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search the workspace",
		Long: `Search across all workspace data: entities, observations, and artifacts.

Results are ranked by relevance. Entity matches with more supporting
observations are ranked higher.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]

			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			results, err := application.Search(cmd.Context(), query, limit)
			if err != nil {
				return fmt.Errorf("search failed: %w", err)
			}

			if len(results) == 0 {
				fmt.Printf("No results for '%s'\n", query)
				return nil
			}

			fmt.Printf("Search: '%s' (%d results)\n", query, len(results))
			fmt.Println("─────────────────────────────────────────────")

			for i, r := range results {
				icon := typeIcon(string(r.Type))
				fmt.Printf("  %s  %d. %s\n", icon, i+1, r.Title)
				fmt.Printf("       %s\n", r.Subtitle)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of results")
	return cmd
}

func typeIcon(t string) string {
	switch t {
	case "entity":
		return "◆"
	case "observation":
		return "●"
	case "artifact":
		return "■"
	default:
		return "○"
	}
}
