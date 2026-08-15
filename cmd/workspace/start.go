package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/investigation"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/internal/memory"
	"github.com/vKS-Rajput/doge/internal/session"
	"github.com/vKS-Rajput/doge/internal/tui"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func newStartCmd() *cobra.Command {
	var targetFlag string
	var envFlag string
	var headless bool

	cmd := &cobra.Command{
		Use:   "start [workspace]",
		Short: "Start DOGE investigation machine",
		Long: `Start DOGE as a persistent investigation machine.

DOGE owns the investigation session. It automatically:
  • Discovers services (nmap)
  • Probes HTTP (httpx)
  • Crawls surfaces (katana)
  • Enumerates directories (ffuf)
  • Scans vulnerabilities (nuclei)
  • Correlates evidence
  • Detects novelty
  • Generates research opportunities
  • Produces AI hypotheses
  • Waits for YOUR approval at human gates

Interactive:
  doge start

Quick start:
  doge start --target 10.10.11.123 --env htb
  doge start myworkspace --target 10.10.11.123 --env htb

The TUI attaches automatically. Close it without stopping DOGE
by pressing 'q'. Ctrl+C stops the entire machine.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Determine workspace path.
			wsPath := "."
			if len(args) > 0 {
				wsPath = args[0]
			}

			// Interactive target setup if flags not provided.
			if targetFlag == "" {
				targetFlag, envFlag = interactiveSetup()
			}

			if targetFlag == "" {
				return fmt.Errorf("target is required")
			}

			// Detect target type.
			targetType := domain.DetectTargetType(targetFlag)

			// Default environment.
			env := domain.EnvHTB
			switch strings.ToLower(envFlag) {
			case "htb":
				env = domain.EnvHTB
			case "lab":
				env = domain.EnvLab
			case "owned":
				env = domain.EnvOwned
			case "authorized":
				env = domain.EnvAuthorized
			case "other":
				env = domain.EnvOther
			}

			// Create/open workspace.
			application, err := openOrInit(cmd.Context(), wsPath, targetFlag)
			if err != nil {
				return err
			}
			defer application.Shutdown()

			logger := logging.WithModule(application.Logger, "session")

			// Create target.
			target := &domain.Target{
				Primary:     targetFlag,
				TargetType:  targetType,
				Environment: env,
				Scope:       domain.DefaultScope(targetFlag, targetType),
				ProjectID:   application.DefaultProjectID,
			}

			// Create event bus for session.
			eventBus := bus.New(bus.Options{
				QueueSize: 256,
				Logger:    logging.WithModule(logger, "bus"),
			})
			eventBus.Start()

			// Create session.
			sess, err := session.New(session.Config{
				Target:   target,
				EventBus: eventBus,
				Logger:   logger,
			})
			if err != nil {
				return fmt.Errorf("session creation failed: %w", err)
			}

			// Handle shutdown.
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				fmt.Println("\n\n🐕 Stopping DOGE...")
				sess.Stop()
				cancel()
			}()

			// Start the machine.
			printBanner(target, env)

			if err := sess.Start(ctx); err != nil {
				return fmt.Errorf("session start failed: %w", err)
			}

			// Print status.
			printStartupComplete(sess)

			if headless {
				// Headless mode: block until signal.
				<-ctx.Done()
			} else {
				// TUI mode: attach the cockpit.
				repo := investigation.New(
					application.DB.Conn(),
					eventBus,
					logging.WithModule(logger, "investigation"),
				)
				mem := memory.NewService(
					application.DB.Conn(),
					repo,
					logging.WithModule(logger, "memory"),
				)
				sink := tui.NewEventSink()
				model := tui.NewModel(application, mem, sink, ctx)
				p := tea.NewProgram(model, tea.WithAltScreen())

				if _, err := p.Run(); err != nil {
					return fmt.Errorf("TUI error: %w", err)
				}
			}

			// Graceful stop.
			sess.Stop()
			eventBus.Drain()

			printShutdown(sess)
			return nil
		},
	}

	cmd.Flags().StringVar(&targetFlag, "target", "", "primary target (IP, domain, or URL)")
	cmd.Flags().StringVar(&envFlag, "env", "htb", "environment (htb, lab, owned, authorized, other)")
	cmd.Flags().BoolVar(&headless, "headless", false, "run without TUI")

	return cmd
}

// interactiveSetup prompts the user for target information.
func interactiveSetup() (target, env string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("🐕 DOGE")
	fmt.Println()
	fmt.Print("Target: ")
	target, _ = reader.ReadString('\n')
	target = strings.TrimSpace(target)

	if target == "" {
		return "", ""
	}

	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  [1] HTB")
	fmt.Println("  [2] Lab")
	fmt.Println("  [3] Authorized")
	fmt.Println("  [4] Owned")
	fmt.Println("  [5] Other")
	fmt.Print("> ")
	envStr, _ := reader.ReadString('\n')
	envStr = strings.TrimSpace(envStr)

	switch envStr {
	case "1", "htb":
		env = "htb"
	case "2", "lab":
		env = "lab"
	case "3", "authorized":
		env = "authorized"
	case "4", "owned":
		env = "owned"
	case "5", "other":
		env = "other"
	default:
		env = "htb"
	}

	return target, env
}

// openOrInit opens an existing workspace or initializes a new one.
func openOrInit(ctx context.Context, path, name string) (*app.App, error) {
	// Try opening first.
	application, err := app.Open(ctx, path)
	if err == nil {
		return application, nil
	}

	// If open fails, try init.
	application, err = app.Init(ctx, path, name)
	if err != nil {
		return nil, fmt.Errorf("failed to open or create workspace: %w", err)
	}

	return application, nil
}

// printBanner shows the startup banner.
func printBanner(target *domain.Target, env domain.TargetEnvironment) {
	fmt.Println()
	fmt.Println("🐕 DOGE Investigation Machine")
	fmt.Println()
	fmt.Printf("  Target:      %s\n", target.Primary)
	fmt.Printf("  Type:        %s\n", target.TargetType)
	fmt.Printf("  Environment: %s\n", env)
	fmt.Printf("  Scope:       %s\n", target.Primary)
	fmt.Println()
}

// printStartupComplete shows what started successfully.
func printStartupComplete(sess *session.Session) {
	fmt.Println("  [✓] Database")
	fmt.Println("  [✓] Artifact store")
	fmt.Println("  [✓] Event bus")
	fmt.Println("  [✓] Orchestrator")
	fmt.Println("  [✓] Pipeline handlers")
	fmt.Println("  [✓] Scheduler")
	fmt.Println("  [✓] TUI")
	fmt.Println()
	fmt.Printf("  Phase: %s\n", sess.Controller.Phase)
	fmt.Printf("  Policy: auto-recon=%v\n", sess.Policy.AutoRecon)
	fmt.Println()
	fmt.Println("  Status: ACTIVE")
	fmt.Println()
}

// printShutdown shows final stats.
func printShutdown(sess *session.Session) {
	snap := sess.Snapshot()
	fmt.Println()
	fmt.Println("🐕 DOGE Session Complete")
	fmt.Println()
	fmt.Printf("  Observations:  %d\n", snap.Observations)
	fmt.Printf("  Correlations:  %d\n", snap.Correlations)
	fmt.Printf("  Opportunities: %d\n", snap.Opportunities)
	fmt.Printf("  Hypotheses:    %d\n", snap.Hypotheses)
	fmt.Printf("  Findings:      %d\n", snap.Findings)
	fmt.Printf("  Jobs completed:%d\n", snap.JobsCompleted)
	fmt.Printf("  Jobs failed:   %d\n", snap.JobsFailed)
	fmt.Println()
}
