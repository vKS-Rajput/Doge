package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newInitCmd creates the 'init' command.
//
// Usage: doge init <name> [--path <dir>]
//
// Creates a new workspace with the given name. If --path is not specified,
// creates a directory with the workspace name in the current directory.
func newInitCmd() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "init <name>",
		Short: "Initialize a new workspace",
		Long: `Initialize a new workspace directory with the given name.

Creates the workspace structure:
  <name>/
    workspace.toml      Configuration
    projects/           Project directories
    .doge/
      workspace.db      SQLite database
      artifacts/        Content-addressable file store`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			if path == "" {
				path = name
			}

			application, err := app.Init(cmd.Context(), path, name)
			if err != nil {
				return fmt.Errorf("failed to initialize workspace: %w", err)
			}
			defer application.Shutdown()

			fmt.Printf("Workspace '%s' initialized at %s\n", name, application.Workspace.RootPath)
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Printf("  cd %s\n", application.Workspace.RootPath)
			fmt.Println("  doge status")
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "directory path (defaults to workspace name)")
	return cmd
}
