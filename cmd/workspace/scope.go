package main

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newScopeCmd() *cobra.Command {
	var checkAsset string

	cmd := &cobra.Command{
		Use:   "scope [asset]",
		Short: "Inspect hard scope boundaries and validate targets",
		Long: `Inspect machine-enforced scope boundaries for the current workspace.
Pass a hostname, IP address, or URL to evaluate its classification (In-Scope, Out-of-Scope, Candidate, Third-Party).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			wsPath, _ := filepath.Abs(".")
			state, err := session.LoadState(wsPath)
			if err != nil {
				fmt.Println("🐕 DOGE — No active session found.")
				fmt.Println("  Start a session with: doge start --target <domain/IP>")
				return nil
			}

			// Initialize ScopeEngine from persisted config or session target
			cfg, err := scope.LoadConfig(wsPath)
			if err != nil {
				cfg = &scope.Config{
					Target:      state.Target,
					Environment: string(state.Environment),
					InScope:     []string{state.Target, "*." + state.Target},
					Rules:       scope.DefaultProgramRules(),
				}
			}
			scopeEngine, err := scope.NewEngine(*cfg)
			if err != nil {
				return fmt.Errorf("initializing scope engine: %w", err)
			}

			targetToCheck := state.Target
			if len(args) > 0 {
				targetToCheck = args[0]
			} else if checkAsset != "" {
				targetToCheck = checkAsset
			}

			cls, reason := scopeEngine.ClassifyAsset(targetToCheck)

			fmt.Println()
			fmt.Println("🐕 DOGE Hard Scope Validation")
			fmt.Println("──────────────────────────────────────────")
			fmt.Printf("Workspace Target:   %s\n", state.Target)
			fmt.Printf("Environment:        %s\n", state.Environment)
			fmt.Printf("Asset Evaluated:    %s\n", targetToCheck)
			fmt.Printf("Classification:     [%s]\n", cls)
			fmt.Printf("Reason:             %s\n", reason)
			fmt.Println("──────────────────────────────────────────")

			actionAllowed := cls == scope.AssetInScope
			if actionAllowed {
				fmt.Println("  ✅ Active testing PERMITTED within authorized boundary.")
			} else {
				fmt.Println("  🛑 Active testing PROHIBITED (fail-closed scope enforcement).")
			}
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVarP(&checkAsset, "check", "c", "", "Evaluate specific domain, IP, or URL")
	return cmd
}
