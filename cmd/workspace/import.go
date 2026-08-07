package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newImportCmd creates the 'import' command.
//
// Usage: doge import <file> [--path <workspace>] [--project <slug>]
//
// Imports a file through the full pipeline:
// File → Artifact Store → Parser → Observation Validation → Observation Store
func newImportCmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import a file into the workspace",
		Long: `Import a security tool's output file into the workspace.

The file flows through the full pipeline:
  1. Artifact Store (content-addressable storage, deduplication)
  2. Parser Registry (automatic parser selection)
  3. Observation Validation (bad observations rejected)
  4. Observation Store (persistence, deduplication)

Supported formats: httpx JSON (more coming soon).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]

			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			result, err := application.Import(cmd.Context(), filePath, application.DefaultProjectID)
			if err != nil {
				return fmt.Errorf("import failed: %w", err)
			}

			if !result.ArtifactIsNew {
				fmt.Printf("File '%s' already imported (duplicate)\n", result.ArtifactFileName)
				return nil
			}

			fmt.Printf("Imported: %s\n", result.ArtifactFileName)
			if result.ParserUsed != "" {
				fmt.Printf("Parser:   %s\n", result.ParserUsed)
				fmt.Printf("Results:  %d observations, %d duplicates, %d rejected\n",
					result.Observations, result.Duplicates, result.Rejected)
			} else {
				fmt.Println("Parser:   none (no parser available for this file type)")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory (defaults to current directory)")
	return cmd
}
