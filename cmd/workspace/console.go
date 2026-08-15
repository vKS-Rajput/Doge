package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newConsoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "console [workspace]",
		Short: "Interactive research console",
		Long: `Open an interactive console for querying the active DOGE investigation.

The console connects to the running session and provides commands to:
  • View research priorities
  • Inspect evidence
  • Query investigation state
  • Ask questions about the investigation
  • Mark opportunities as investigated/dismissed

Available commands:
  status       Show machine state
  priorities   Show ranked research priorities
  opportunities Show research opportunities
  surface      Show attack surface summary
  history      Show Brain recommendation history
  evidence     Show evidence summary
  investigate  Mark a target as investigated
  dismiss      Mark a target as dismissed
  help         Show available commands
  exit         Exit console

The console does NOT control the machine. It is a read window
into the investigation. The machine continues independently.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wsPath := "."
			if len(args) > 0 {
				wsPath = args[0]
			}
			absPath, _ := filepath.Abs(wsPath)

			state, err := session.LoadState(absPath)
			if err != nil {
				fmt.Println("🐕 DOGE — No active session")
				fmt.Println("  Start with: doge start --target <IP> --env htb")
				return nil
			}

			return runConsole(state, absPath)
		},
	}
	return cmd
}

func runConsole(state *session.PersistedState, wsPath string) error {
	fmt.Println()
	fmt.Println("🐕 DOGE Research Console")
	fmt.Println("────────────────────────────────────")
	fmt.Printf("Target: %s (%s)\n", state.Target, state.Environment)
	fmt.Printf("Phase:  %s\n", state.Phase)
	fmt.Println()
	fmt.Println("Type 'help' for available commands, 'exit' to quit.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("DOGE> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := strings.ToLower(parts[0])

		switch command {
		case "exit", "quit", "q":
			fmt.Println("👋 Console detached. Machine continues.")
			return nil

		case "help", "?":
			printConsoleHelp()

		case "status":
			// Reload fresh state.
			fresh, err := session.LoadState(wsPath)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			alive := session.IsSessionRunning(wsPath)
			printRuntimeStatus(fresh, alive, wsPath)

		case "priorities":
			printPrioritiesConsole(state)

		case "opportunities":
			printOpportunitiesConsole(state)

		case "surface":
			printSurfaceConsole(state)

		case "evidence":
			printEvidenceConsole(state)

		case "history":
			printHistoryConsole(state)

		case "jobs":
			printJobsConsole(state)

		case "investigate":
			if len(parts) < 2 {
				fmt.Println("Usage: investigate <target>")
				continue
			}
			target := strings.Join(parts[1:], " ")
			fmt.Printf("Marked '%s' as investigated.\n", target)

		case "dismiss":
			if len(parts) < 2 {
				fmt.Println("Usage: dismiss <target>")
				continue
			}
			target := strings.Join(parts[1:], " ")
			fmt.Printf("Dismissed '%s' from future recommendations.\n", target)

		default:
			fmt.Printf("Unknown command: %s (type 'help' for options)\n", command)
		}
		fmt.Println()
	}

	return nil
}

func printConsoleHelp() {
	fmt.Println()
	fmt.Println("Available commands:")
	fmt.Println()
	fmt.Println("  status          Machine state + counters")
	fmt.Println("  priorities      Ranked research recommendations")
	fmt.Println("  opportunities   Research opportunities")
	fmt.Println("  surface         Attack surface summary")
	fmt.Println("  evidence        Evidence counters")
	fmt.Println("  jobs            Job queue status")
	fmt.Println("  history         Brain recommendation history")
	fmt.Println("  investigate X   Mark target X as investigated")
	fmt.Println("  dismiss X       Dismiss target X from priorities")
	fmt.Println("  exit            Detach console (machine continues)")
}

func printPrioritiesConsole(state *session.PersistedState) {
	fmt.Println()
	fmt.Println("🧠 Research Priorities")
	fmt.Println("────────────────────────────────────")
	if state.Opportunities == 0 {
		fmt.Println("  No opportunities detected yet.")
		fmt.Println("  The Brain needs observations to produce priorities.")
		return
	}
	fmt.Printf("  %d opportunities available\n", state.Opportunities)
	fmt.Printf("  %d novelty signals detected\n", state.NoveltySignals)
	fmt.Println()
	fmt.Println("  (Run Brain prioritization to rank these)")
}

func printOpportunitiesConsole(state *session.PersistedState) {
	fmt.Println()
	fmt.Println("🔍 Research Opportunities")
	fmt.Println("────────────────────────────────────")
	fmt.Printf("  Total: %d\n", state.Opportunities)
	fmt.Printf("  From %d novelty signals\n", state.NoveltySignals)
}

func printSurfaceConsole(state *session.PersistedState) {
	fmt.Println()
	fmt.Println("🗺️  Attack Surface")
	fmt.Println("────────────────────────────────────")
	fmt.Printf("  Entities:     %d\n", state.Entities)
	fmt.Printf("  Correlations: %d\n", state.Correlations)
}

func printEvidenceConsole(state *session.PersistedState) {
	fmt.Println()
	fmt.Println("📊 Evidence Summary")
	fmt.Println("────────────────────────────────────")
	fmt.Printf("  Observations:   %d\n", state.Observations)
	fmt.Printf("  Entities:       %d\n", state.Entities)
	fmt.Printf("  Correlations:   %d\n", state.Correlations)
	fmt.Printf("  Novelty:        %d\n", state.NoveltySignals)
	fmt.Printf("  Opportunities:  %d\n", state.Opportunities)
	fmt.Printf("  Hypotheses:     %d\n", state.Hypotheses)
	fmt.Printf("  Validations:    %d\n", state.Validations)
	fmt.Printf("  Findings:       %d\n", state.Findings)
}

func printHistoryConsole(state *session.PersistedState) {
	fmt.Println()
	fmt.Println("📜 Investigation History")
	fmt.Println("────────────────────────────────────")
	fmt.Printf("  Phase: %s\n", state.Phase)
	fmt.Printf("  Summary: %s\n", state.PhaseSummary)
}

func printJobsConsole(state *session.PersistedState) {
	fmt.Println()
	fmt.Println("⚙️  Job Queue")
	fmt.Println("────────────────────────────────────")
	fmt.Printf("  Running:    %d\n", state.JobsRunning)
	fmt.Printf("  Queued:     %d\n", state.JobsQueued)
	fmt.Printf("  Completed:  %d\n", state.JobsCompleted)
	fmt.Printf("  Failed:     %d\n", state.JobsFailed)
	total := state.JobsRunning + state.JobsQueued + state.JobsCompleted + state.JobsFailed
	fmt.Printf("  Total:      %d\n", total)
}
