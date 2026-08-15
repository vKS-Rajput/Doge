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

func newApprovalsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approvals [workspace]",
		Short: "Human decision queue for investigation gates",
		Long: `Interactive approval queue for DOGE epistemic gates.

DOGE pauses at two human gates:

  1. HYPOTHESIS APPROVAL — AI has formed a hypothesis. A human must
     approve before controlled validation proceeds.

  2. FINDING CONFIRMATION — A validated hypothesis has been promoted
     to candidate finding. A human must confirm the evidence chain
     before the finding is recorded.

This command shows all pending approvals and lets you decide.`,
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

			return runApprovals(state, absPath)
		},
	}
	return cmd
}

func runApprovals(state *session.PersistedState, wsPath string) error {
	fmt.Println()
	fmt.Println("🐕 DOGE Approvals")
	fmt.Printf("Target: %s (%s)\n", state.Target, state.Environment)
	fmt.Println("────────────────────────────────────")
	fmt.Println()

	totalPending := state.PendingApproval + state.PendingConfirm

	if totalPending == 0 {
		fmt.Println("  ✅ No pending approvals.")
		fmt.Println()
		fmt.Println("  DOGE will pause here when:")
		fmt.Println("    • A hypothesis needs approval before validation")
		fmt.Println("    • A candidate finding needs human confirmation")
		fmt.Println()
		fmt.Println("  The investigation continues autonomously until")
		fmt.Println("  these epistemic gates are reached.")
		return nil
	}

	// Show pending hypotheses.
	if state.PendingApproval > 0 {
		fmt.Println("📋 Pending Hypothesis Approvals")
		fmt.Println("────────────────────────────────────")
		fmt.Printf("  %d hypotheses awaiting human review\n", state.PendingApproval)
		fmt.Println()
		fmt.Println("  Each hypothesis represents an AI-formed claim that")
		fmt.Println("  requires human judgment before controlled testing.")
		fmt.Println()
		fmt.Println("  Actions:")
		fmt.Println("    approve <id>  — Allow controlled validation")
		fmt.Println("    reject <id>   — Reject this hypothesis")
		fmt.Println("    inspect <id>  — View evidence chain")
		fmt.Println()
	}

	// Show pending findings.
	if state.PendingConfirm > 0 {
		fmt.Println("🏆 Candidate Findings")
		fmt.Println("────────────────────────────────────")
		fmt.Printf("  %d findings awaiting human confirmation\n", state.PendingConfirm)
		fmt.Println()
		fmt.Println("  Each candidate has passed controlled validation.")
		fmt.Println("  A human must confirm the evidence chain is complete")
		fmt.Println("  before the finding is formally recorded.")
		fmt.Println()
		fmt.Println("  Actions:")
		fmt.Println("    confirm <id>  — Confirm this is a real finding")
		fmt.Println("    reject <id>   — Reject this candidate")
		fmt.Println("    inspect <id>  — View complete evidence chain")
		fmt.Println()
	}

	// Interactive mode.
	fmt.Println("Type an action or 'exit' to quit.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("DOGE/approvals> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		action := strings.ToLower(parts[0])

		switch action {
		case "exit", "quit", "q":
			fmt.Println("👋 Approval queue detached.")
			return nil

		case "approve":
			if len(parts) < 2 {
				fmt.Println("Usage: approve <hypothesis-id>")
				continue
			}
			fmt.Printf("✅ Hypothesis %s approved for controlled validation.\n", parts[1])

		case "reject":
			if len(parts) < 2 {
				fmt.Println("Usage: reject <id>")
				continue
			}
			fmt.Printf("❌ Item %s rejected.\n", parts[1])

		case "confirm":
			if len(parts) < 2 {
				fmt.Println("Usage: confirm <finding-id>")
				continue
			}
			fmt.Printf("🏆 Finding %s confirmed and recorded.\n", parts[1])

		case "inspect":
			if len(parts) < 2 {
				fmt.Println("Usage: inspect <id>")
				continue
			}
			fmt.Printf("Inspecting item %s...\n", parts[1])
			fmt.Println("  (Evidence chain would be displayed here)")

		case "refresh":
			fresh, err := session.LoadState(wsPath)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			fmt.Printf("  Pending approvals: %d\n", fresh.PendingApproval)
			fmt.Printf("  Pending confirms:  %d\n", fresh.PendingConfirm)

		case "help", "?":
			fmt.Println("Commands: approve <id>, reject <id>, confirm <id>, inspect <id>, refresh, exit")

		default:
			fmt.Printf("Unknown: %s (type 'help')\n", action)
		}
		fmt.Println()
	}

	return nil
}
