package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newRuntimeStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runtime [workspace]",
		Short: "Show DOGE machine state",
		Long: `Show the current state of the DOGE investigation machine.

This reads the persistent session state and displays:
  • Target and scope
  • Investigation phase
  • Job queue status
  • Evidence counters
  • Research priorities
  • Human gates pending

Works from any terminal attached to the same workspace.`,
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
				fmt.Println()
				fmt.Println("  Start an investigation:")
				fmt.Println("    doge start --target <IP> --env htb")
				return nil
			}

			// Check if session is still alive.
			alive := session.IsSessionRunning(absPath)

			printRuntimeStatus(state, alive, absPath)
			return nil
		},
	}
	return cmd
}

func printRuntimeStatus(state *session.PersistedState, alive bool, wsPath string) {
	fmt.Println()
	fmt.Println("🐕 DOGE v1.2")
	fmt.Println("────────────────────────────────────")
	fmt.Println()

	// Target.
	fmt.Println("Target")
	fmt.Printf("  %-20s %s\n", "Address:", state.Target)
	fmt.Printf("  %-20s %s\n", "Type:", state.TargetType)
	fmt.Printf("  %-20s %s\n", "Environment:", state.Environment)
	fmt.Println()

	// Session.
	fmt.Println("Session")
	if alive {
		fmt.Printf("  %-20s \033[32mACTIVE\033[0m\n", "Status:")
	} else {
		fmt.Printf("  %-20s \033[31mSTOPPED\033[0m\n", "Status:")
	}
	if !state.StartedAt.IsZero() {
		duration := time.Since(state.StartedAt)
		fmt.Printf("  %-20s %s\n", "Runtime:", formatDuration(duration))
	}
	fmt.Printf("  %-20s %s\n", "Phase:", state.Phase)
	fmt.Printf("  %-20s %s\n", "Summary:", state.PhaseSummary)
	fmt.Printf("  %-20s %d\n", "PID:", state.PID)
	if state.Mode != "" {
		switch state.Mode {
		case "research":
			fmt.Printf("  %-20s \033[36m%s\033[0m\n", "Mode:", "RESEARCH (you run tools)")
		case "hunt":
			fmt.Printf("  %-20s \033[32m%s\033[0m\n", "Mode:", "HUNT (autonomous)")
		default:
			fmt.Printf("  %-20s %s\n", "Mode:", state.Mode)
		}
	}
	fmt.Println()

	// Jobs.
	fmt.Println("Jobs")
	fmt.Printf("  %-20s %d\n", "Running:", state.JobsRunning)
	fmt.Printf("  %-20s %d\n", "Queued:", state.JobsQueued)
	fmt.Printf("  %-20s %d\n", "Completed:", state.JobsCompleted)
	fmt.Printf("  %-20s %d\n", "Failed:", state.JobsFailed)
	fmt.Println()

	// Evidence.
	fmt.Println("Evidence")
	fmt.Printf("  %-20s %d\n", "Observations:", state.Observations)
	fmt.Printf("  %-20s %d\n", "Entities:", state.Entities)
	fmt.Printf("  %-20s %d\n", "Correlations:", state.Correlations)
	fmt.Println()

	// Research.
	fmt.Println("Research")
	fmt.Printf("  %-20s %d\n", "Novelty signals:", state.NoveltySignals)
	fmt.Printf("  %-20s %d\n", "Opportunities:", state.Opportunities)
	fmt.Printf("  %-20s %d\n", "Hypotheses:", state.Hypotheses)
	fmt.Println()

	// Human gates.
	fmt.Println("Human Gates")
	if state.PendingApproval > 0 {
		fmt.Printf("  %-20s \033[33m%d ⚠\033[0m\n", "Approvals pending:", state.PendingApproval)
	} else {
		fmt.Printf("  %-20s %d\n", "Approvals pending:", state.PendingApproval)
	}
	if state.PendingConfirm > 0 {
		fmt.Printf("  %-20s \033[33m%d ⚠\033[0m\n", "Candidates pending:", state.PendingConfirm)
	} else {
		fmt.Printf("  %-20s %d\n", "Candidates pending:", state.PendingConfirm)
	}
	fmt.Printf("  %-20s %d\n", "Findings:", state.Findings)
	fmt.Println()

	// Policy.
	fmt.Println("Policy")
	fmt.Printf("  %-20s %v\n", "Auto-recon:", state.AutoRecon)
	authStatus := state.ReconAuthStatus
	if authStatus == "" {
		authStatus = "auto"
	}
	switch authStatus {
	case "pending":
		fmt.Printf("  %-20s \033[33m%s ⚠\033[0m\n", "Recon auth:", "PENDING — run 'doge approvals'")
	case "approved":
		fmt.Printf("  %-20s \033[32m%s\033[0m\n", "Recon auth:", "APPROVED")
	case "denied":
		fmt.Printf("  %-20s \033[31m%s\033[0m\n", "Recon auth:", "DENIED")
	default:
		fmt.Printf("  %-20s %s\n", "Recon auth:", "auto (no approval needed)")
	}
	fmt.Println()

	needsAction := state.PendingApproval > 0 || state.PendingConfirm > 0 || authStatus == "pending"
	if needsAction {
		if authStatus == "pending" {
			fmt.Println("🔐 Recon authorization required. Run: doge approvals")
		}
		if state.PendingApproval > 0 || state.PendingConfirm > 0 {
			fmt.Println("⚠  Human decisions needed. Run: doge approvals")
		}
	}

	fmt.Println("────────────────────────────────────")
	fmt.Println()

	// Research mode hints.
	if state.Mode == "research" {
		fmt.Println("📓 Research mode commands:")
		fmt.Println("   doge ingest <file>    Feed tool output")
		fmt.Println("   doge note '...'       Record observation")
		fmt.Println("   doge coverage         View coverage")
		fmt.Println("   doge gaps             View gaps")
		fmt.Println("   doge journal          View history")
		fmt.Println()
	}
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%02dh %02dm %02ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%02dm %02ds", minutes, seconds)
	}
	return fmt.Sprintf("%02ds", seconds)
}
