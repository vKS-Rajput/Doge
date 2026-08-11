package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/investigation"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/internal/memory"
	"github.com/vKS-Rajput/doge/internal/tui"
	"github.com/vKS-Rajput/doge/internal/watch"
)

func newTUICmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch interactive Research Cockpit",
		Long: `Start the interactive TUI with live workspace monitoring.

The cockpit shows four panes:
  • Live Events — real-time file changes and import results
  • Investigation — current research state
  • Attention — items needing researcher attention
  • Workspace — knowledge graph statistics

Navigation:
  Tab        Switch focus between panes
  Enter      Execute command
  Ctrl+C     Quit

Commands:
  ask <question>      Ask AI a question
  search <query>      Search entities
  investigate ...     Investigation commands
  quit                Exit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			logger := logging.WithModule(application.Logger, "tui")

			// Create memory service.
			eventBus := bus.New(bus.Options{Logger: logging.WithModule(logger, "bus")})
			repo := investigation.New(application.DB.Conn(), eventBus, logging.WithModule(logger, "investigation"))
			mem := memory.NewService(application.DB.Conn(), repo, logging.WithModule(logger, "memory"))

			// Create bounded event sink.
			sink := tui.NewEventSink()

			// Start watch orchestrator in background.
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				cancel()
			}()

			go func() {
				orchestrator := watch.NewOrchestrator(application, watch.OrchestratorOptions{
					Quiet: true, // TUI handles display
				}, logging.WithModule(logger, "watch"))

				orchestrator.Start(ctx)
			}()

			// Create and run TUI.
			model := tui.NewModel(application, mem, sink, ctx)
			p := tea.NewProgram(model, tea.WithAltScreen())

			if _, err := p.Run(); err != nil {
				return fmt.Errorf("TUI error: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	return cmd
}
