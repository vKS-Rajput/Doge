package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/desktop"
)

func newDesktopCmd() *cobra.Command {
	var (
		workspaceRoot string
		targetURL     string
		requestBudget int
		ipcAddress    string
		headless      bool
	)

	cmd := &cobra.Command{
		Use:     "desktop",
		Aliases: []string{"ui", "cockpit"},
		Short:   "Launch the native DOGE desktop security research operating environment",
		Long: `DOGE Desktop — A dedicated Windows native operating environment for
autonomous security research.

Bridges the native desktop workstation cockpit to the WSL2 laboratory substrate
and the Go autonomous research engine.

Examples:
  doge desktop
  doge desktop --workspace ./acme-corp
  doge desktop --target https://api.staging.example --budget 10000
  doge desktop --headless`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetURL == "" {
				targetURL = "https://authorized.example"
			}
			if ipcAddress == "" {
				ipcAddress = "127.0.0.1:42424"
			}

			fmt.Println("◈ Launching DOGE Security Research Operating Environment...")

			cfg := desktop.DesktopConfig{
				WorkspaceRoot: workspaceRoot,
				TargetURL:     targetURL,
				RequestBudget: requestBudget,
				IPCAddress:    ipcAddress,
				Headless:      headless,
			}

			return desktop.Run(cfg)
		},
	}

	cmd.Flags().StringVarP(&workspaceRoot, "workspace", "w", ".", "Path to target project workspace")
	cmd.Flags().StringVarP(&targetURL, "target", "t", "", "Target URL or base scope")
	cmd.Flags().IntVarP(&requestBudget, "budget", "b", 5000, "Request budget ceiling for autonomous research")
	cmd.Flags().StringVarP(&ipcAddress, "ipc", "i", "127.0.0.1:42424", "Local loopback IPC address (REST & SSE)")
	cmd.Flags().BoolVar(&headless, "headless", false, "Run in background daemon mode without native window")

	return cmd
}
