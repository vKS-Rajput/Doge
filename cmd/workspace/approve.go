package main

import (
	"fmt"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/gates"
)

func newApproveCmd() *cobra.Command {
	var (
		workspaceDir string
		reason       string
	)

	cmd := &cobra.Command{
		Use:   "approve [gate-id]",
		Short: "Authorize a pending high-risk research experiment or human approval gate",
		Long: `Explicitly authorize a paused research action at a decision gate.
DOGE enforces fail-closed execution: high-risk or invasive experiments pause
until authorized with human rationale.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gateID := args[0]
			gateUUID, err := uuid.Parse(gateID)
			if err != nil {
				return fmt.Errorf("invalid gate ID %q: %w", gateID, err)
			}
			absPath, _ := filepath.Abs(workspaceDir)

			mgr := gates.NewManager(absPath)
			err = mgr.Approve(gateUUID, "operator", reason)
			if err != nil {
				return fmt.Errorf("failed to approve gate %s: %w", gateID, err)
			}

			fmt.Printf("✅ Gate %s APPROVED.\n", gateID)
			if reason != "" {
				fmt.Printf("   Rationale: %s\n", reason)
			}
			fmt.Println("   Autonomous research execution resumed.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspaceDir, "workspace", "w", ".", "Path to DOGE workspace directory")
	cmd.Flags().StringVarP(&reason, "reason", "r", "Operator authorized", "Rationale for authorization")

	return cmd
}

func newDenyCmd() *cobra.Command {
	var (
		workspaceDir string
		reason       string
	)

	cmd := &cobra.Command{
		Use:   "deny [gate-id]",
		Short: "Deny and cancel a pending high-risk research experiment",
		Long: `Explicitly deny a paused research action at a decision gate.
DOGE will immediately abort the requested experiment, mark the hypothesis,
and replan alternative non-invasive research paths.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gateID := args[0]
			gateUUID, err := uuid.Parse(gateID)
			if err != nil {
				return fmt.Errorf("invalid gate ID %q: %w", gateID, err)
			}
			absPath, _ := filepath.Abs(workspaceDir)

			mgr := gates.NewManager(absPath)
			err = mgr.Reject(gateUUID, "operator", reason)
			if err != nil {
				return fmt.Errorf("failed to deny gate %s: %w", gateID, err)
			}

			fmt.Printf("🛑 Gate %s DENIED.\n", gateID)
			if reason != "" {
				fmt.Printf("   Rationale: %s\n", reason)
			}
			fmt.Println("   Experiment cancelled; research director replanning alternative avenues.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&workspaceDir, "workspace", "w", ".", "Path to DOGE workspace directory")
	cmd.Flags().StringVarP(&reason, "reason", "r", "Operator denied", "Rationale for denial")

	return cmd
}
