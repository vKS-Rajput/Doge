package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newInsightsCmd creates the 'insights' command.
func newInsightsCmd() *cobra.Command {
	var wsPath string
	var limit int

	cmd := &cobra.Command{
		Use:   "insights",
		Short: "Show detected insights",
		Long: `Show insights detected by the rule-based Insight Engine.

Insights are deterministic pattern matches — no AI required.
Each insight is linked to the entity that triggered it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			insights, err := application.Insights(cmd.Context(), limit)
			if err != nil {
				return fmt.Errorf("failed to query insights: %w", err)
			}

			if len(insights) == 0 {
				fmt.Println("No insights detected yet.")
				return nil
			}

			fmt.Printf("Insights (%d)\n", len(insights))
			fmt.Println("─────────────────────────────────────────────")

			for _, i := range insights {
				icon := severityIcon(string(i.Severity))
				fmt.Printf("  %s [%s] %s\n", icon, i.Severity, i.Title)
				if i.Description != "" {
					fmt.Printf("       %s\n", truncateStr(i.Description, 70))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	cmd.Flags().IntVar(&limit, "limit", 25, "maximum number of insights")
	return cmd
}

func severityIcon(s string) string {
	switch s {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
