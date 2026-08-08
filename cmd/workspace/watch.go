package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/internal/watch"
)

func newWatchCmd() *cobra.Command {
	var wsPath string
	var quiet bool

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch workspace for changes and process them live",
		Long: `Start live research mode. Doge monitors the workspace for new
tool output, automatically imports and processes it, and surfaces
meaningful changes.

  doge watch                    Watch workspace
  doge watch --path ./targets   Watch specific directory
  doge watch --quiet            Suppress low-priority output

Watched content is treated as UNTRUSTED DATA. Doge will never
execute commands based on file contents.

When AI reasoning is recommended, Doge suggests it but does NOT
auto-invoke the LLM. The researcher maintains control.

Press Ctrl+C to stop.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			logger := logging.WithModule(application.Logger, "watch")

			orchestrator := watch.NewOrchestrator(application, watch.OrchestratorOptions{
				Quiet: quiet,
			}, logger)

			// Handle graceful shutdown on Ctrl+C.
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				fmt.Println("\n\nStopping watch...")
				cancel()
			}()

			return orchestrator.Start(ctx)
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress low-priority output")

	return cmd
}
