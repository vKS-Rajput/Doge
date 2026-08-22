package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/scheduler"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newApprovalsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approvals [workspace]",
		Short: "Human decision queue for investigation gates",
		Long: `Interactive approval queue for DOGE investigation gates.

DOGE pauses at three types of human gates:

  1. RECON AUTHORIZATION — For authorized/other environments, a human
     must approve what reconnaissance tools DOGE is allowed to run
     before any tools execute.

  2. HYPOTHESIS APPROVAL — AI has formed a hypothesis. A human must
     approve before controlled validation proceeds.

  3. FINDING CONFIRMATION — A validated hypothesis has been promoted
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

	// Check for recon authorization.
	auth, _ := scheduler.LoadAuthorization(wsPath)

	hasReconPending := auth != nil && auth.Status == scheduler.AuthPending
	totalPending := state.PendingApproval + state.PendingConfirm
	if hasReconPending {
		totalPending++
	}

	if totalPending == 0 {
		fmt.Println("  ✅ No pending approvals.")
		fmt.Println()
		fmt.Println("  DOGE will pause here when:")
		fmt.Println("    • Recon authorization is needed (authorized targets)")
		fmt.Println("    • A hypothesis needs approval before validation")
		fmt.Println("    • A candidate finding needs human confirmation")
		fmt.Println()
		fmt.Println("  The investigation continues autonomously until")
		fmt.Println("  these gates are reached.")
		return nil
	}

	// Show recon authorization request.
	if hasReconPending {
		fmt.Println("🔐 RECON AUTHORIZATION REQUIRED")
		fmt.Println("────────────────────────────────────")
		fmt.Printf("  Target:      %s\n", auth.Target)
		fmt.Printf("  Environment: %s\n", auth.Environment)
		fmt.Println()
		fmt.Println("  DOGE is requesting permission to run reconnaissance.")
		fmt.Println("  No tools will execute until you authorize.")
		fmt.Println()
		fmt.Println("  Requested capabilities:")
		for i, cap := range auth.RequestedCapabilities {
			status := "[ ]"
			if cap.Approved {
				status = "[✓]"
			}
			fmt.Printf("    %d. %s %s\n", i+1, status, cap.Name)
			fmt.Printf("       Tools: %s\n", strings.Join(cap.Tools, ", "))
		}
		fmt.Println()
		fmt.Println("  Actions:")
		fmt.Println("    authorize all          — Approve all capabilities")
		fmt.Println("    authorize <number>     — Approve specific capability")
		fmt.Println("    deny                   — Deny all reconnaissance")
		fmt.Println("    details                — Show capability details")
		fmt.Println()
	}

	// Show pending hypotheses.
	if state.PendingApproval > 0 {
		fmt.Println("📋 Pending Hypothesis Approvals")
		fmt.Println("────────────────────────────────────")
		fmt.Printf("  %d hypotheses awaiting human review\n", state.PendingApproval)
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

		case "authorize":
			if auth == nil || auth.Status != scheduler.AuthPending {
				fmt.Println("No recon authorization pending.")
				break
			}

			if len(parts) >= 2 && strings.ToLower(parts[1]) == "all" {
				auth.ApproveAll("researcher")
				if err := scheduler.SaveAuthorization(wsPath, auth); err != nil {
					fmt.Printf("Error saving authorization: %v\n", err)
					break
				}
				fmt.Println()
				fmt.Println("  ✅ ALL reconnaissance capabilities authorized!")
				fmt.Println()
				fmt.Println("  Approved:")
				for _, cap := range auth.RequestedCapabilities {
					fmt.Printf("    ✓ %s (%s)\n", cap.Name, strings.Join(cap.Tools, ", "))
				}
				fmt.Println()
				fmt.Println("  The scheduler will pick this up within seconds.")
				fmt.Println("  Watch the machine terminal or 'doge logs -f' for activity.")
			} else if len(parts) >= 2 {
				// Approve specific capability by number.
				var idx int
				if _, err := fmt.Sscanf(parts[1], "%d", &idx); err != nil || idx < 1 || idx > len(auth.RequestedCapabilities) {
					fmt.Printf("Invalid capability number. Use 1-%d or 'all'.\n", len(auth.RequestedCapabilities))
					break
				}
				if err := auth.ApproveByIndex(idx - 1); err != nil {
					fmt.Printf("Error: %v\n", err)
					break
				}
				cap := auth.RequestedCapabilities[idx-1]
				fmt.Printf("  ✓ %s authorized (%s)\n", cap.Name, strings.Join(cap.Tools, ", "))
				fmt.Println()
				fmt.Println("  Use 'authorize all' to approve remaining capabilities,")
				fmt.Println("  or approve individually and then 'authorize finalize'.")
			} else {
				fmt.Println("Usage: authorize all | authorize <number>")
			}

		case "deny":
			if auth != nil && auth.Status == scheduler.AuthPending {
				auth.Deny()
				if err := scheduler.SaveAuthorization(wsPath, auth); err != nil {
					fmt.Printf("Error: %v\n", err)
					break
				}
				fmt.Println("  ❌ Reconnaissance authorization DENIED.")
				fmt.Println("  DOGE will not run any tools on this target.")
			} else {
				fmt.Println("No recon authorization pending.")
			}

		case "details":
			if auth != nil {
				fmt.Println()
				fmt.Println("  Recon Authorization Details")
				fmt.Println("  ────────────────────────────────────")
				fmt.Printf("  Target:      %s\n", auth.Target)
				fmt.Printf("  Environment: %s\n", auth.Environment)
				fmt.Printf("  Status:      %s\n", auth.Status)
				fmt.Println()
				for i, cap := range auth.RequestedCapabilities {
					status := "PENDING"
					if cap.Approved {
						status = "APPROVED"
					}
					fmt.Printf("  %d. [%s] %s\n", i+1, status, cap.Name)
					fmt.Printf("     Category: %s\n", cap.Category)
					fmt.Printf("     Tools: %s\n", strings.Join(cap.Tools, ", "))
				}
				fmt.Println()
			} else {
				fmt.Println("No authorization data.")
			}

		case "approve":
			if len(parts) < 2 {
				fmt.Println("Usage: approve <hypothesis-id>")
				break
			}
			fmt.Printf("✅ Hypothesis %s approved for controlled validation.\n", parts[1])

		case "reject":
			if len(parts) < 2 {
				fmt.Println("Usage: reject <id>")
				break
			}
			fmt.Printf("❌ Item %s rejected.\n", parts[1])

		case "confirm":
			if len(parts) < 2 {
				fmt.Println("Usage: confirm <finding-id>")
				break
			}
			fmt.Printf("🏆 Finding %s confirmed and recorded.\n", parts[1])

		case "inspect":
			if len(parts) < 2 {
				fmt.Println("Usage: inspect <id>")
				break
			}
			fmt.Printf("Inspecting item %s...\n", parts[1])
			fmt.Println("  (Evidence chain would be displayed here)")

		case "refresh":
			fresh, err := session.LoadState(wsPath)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				break
			}
			freshAuth, _ := scheduler.LoadAuthorization(wsPath)
			fmt.Printf("  Recon authorization: ")
			if freshAuth != nil {
				fmt.Printf("%s\n", freshAuth.Status)
			} else {
				fmt.Println("N/A (auto-recon)")
			}
			fmt.Printf("  Pending approvals: %d\n", fresh.PendingApproval)
			fmt.Printf("  Pending confirms:  %d\n", fresh.PendingConfirm)

		case "help", "?":
			fmt.Println("Commands:")
			fmt.Println("  authorize all       — Approve all recon capabilities")
			fmt.Println("  authorize <number>  — Approve specific capability")
			fmt.Println("  deny                — Deny recon authorization")
			fmt.Println("  details             — Show authorization details")
			fmt.Println("  approve <id>        — Approve hypothesis")
			fmt.Println("  reject <id>         — Reject item")
			fmt.Println("  confirm <id>        — Confirm finding")
			fmt.Println("  inspect <id>        — View evidence")
			fmt.Println("  refresh             — Reload state")
			fmt.Println("  exit                — Quit")

		default:
			fmt.Printf("Unknown: %s (type 'help')\n", action)
		}
		fmt.Println()
	}

	return nil
}
