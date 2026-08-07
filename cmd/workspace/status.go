package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newStatusCmd creates the 'status' command.
//
// Usage: doge status [--path <dir>]
//
// Shows the current workspace status: database health, event bus stats,
// cache size, AI configuration.
func newStatusCmd() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show workspace status",
		Long:  `Show the current workspace status including database health, cache size, and AI configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if path == "" {
				path = "."
			}

			application, err := app.Open(cmd.Context(), path)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			status, err := application.Status(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to get status: %w", err)
			}

			fmt.Printf("Workspace: %s\n", status.WorkspaceName)
			fmt.Printf("Path:      %s\n", status.RootPath)
			fmt.Println()

			// Database
			dbStatus := "✓ healthy"
			if !status.DatabaseOK {
				dbStatus = "✗ unhealthy"
			}
			fmt.Printf("Database:  %s\n", dbStatus)

			// Cache
			fmt.Printf("Cache:     %d entries\n", status.CacheEntries)

			// Event Bus
			fmt.Printf("Events:    %d published, %d delivered, %d errors\n",
				status.BusPublished, status.BusDelivered, status.BusErrors)

			// AI
			aiStatus := "disabled"
			if status.AIEnabled {
				aiStatus = "enabled"
			}
			fmt.Printf("AI:        %s\n", aiStatus)

			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "workspace directory (defaults to current directory)")
	return cmd
}
