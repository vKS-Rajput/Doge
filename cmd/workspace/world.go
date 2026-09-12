package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/db"
	"github.com/vKS-Rajput/doge/internal/entity"
	"github.com/vKS-Rajput/doge/internal/session"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func newWorldCmd() *cobra.Command {
	var workspaceDir string

	cmd := &cobra.Command{
		Use:     "world",
		Aliases: []string{"wm", "worldmodel"},
		Short:   "Inspect the unified world model, entities, unknown space, and security properties",
		Long: `DOGE World Model — Query the persistent epistemic graph connecting Principals,
Tenants, Objects, Endpoints, State Transitions, and Active Research Gaps.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			absPath, _ := filepath.Abs(workspaceDir)
			dbPath := filepath.Join(absPath, ".doge", "workspace.db")

			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
			fmt.Println("║               🐕 DOGE UNIFIED WORLD MODEL GRAPH                  ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════════╝")

			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				fmt.Println("No world model database found in current workspace.")
				fmt.Println("Initialize research with: doge hunt <target>")
				return nil
			}

			dbConn, err := db.Open(dbPath, db.Options{WALMode: true})
			if err != nil {
				return fmt.Errorf("opening workspace database: %w", err)
			}
			defer dbConn.Close()

			store := entity.NewStore(dbConn.Conn(), nil, nil)
			entities, err := store.Query(cmd.Context(), domain.EntityFilter{})
			if err != nil {
				return fmt.Errorf("listing entities: %w", err)
			}

			state, _ := session.LoadState(absPath)
			target := "Authorized Target"
			if state != nil && state.Target != "" {
				target = state.Target
			}

			// Ingest into in-memory WorldModel to detect active research gaps
			wm := worldmodel.NewWorldModel(target)
			for _, e := range entities {
				switch e.Type {
				case domain.EntityEndpoint:
					_ = wm.RegisterEndpoint(&worldmodel.EndpointModel{
						ID:   e.ID,
						URL:  e.Value,
						Path: e.Value,
					})
				case domain.EntityPrincipal:
					_ = wm.RegisterPrincipal(&worldmodel.Principal{
						ID:    e.ID,
						Name:  e.Value,
						Type:  worldmodel.PrincipalUser,
						Roles: []string{"user"},
					})
				}
			}

			gapDetector := worldmodel.NewResearchGapDetector(wm)
			gaps := gapDetector.DetectGaps()

			fmt.Printf(" Target:         %s\n", target)
			fmt.Printf(" Modeled Nodes:  %d entities\n", len(entities))
			fmt.Printf(" Unknown Gaps:   %d active research uncertainties\n", len(gaps))
			fmt.Println("──────────────────────────────────────────────────────────────────")

			fmt.Println("\n📌 MODELED ATTACK SURFACE ENTITIES:")
			if len(entities) == 0 {
				fmt.Println("  (No entities discovered yet. Run 'doge hunt' to discover endpoints)")
			} else {
				for i, e := range entities {
					if i >= 15 {
						fmt.Printf("  ... and %d more entities\n", len(entities)-15)
						break
					}
					fmt.Printf("  • [%s] %s\n", e.Type, e.Value)
				}
			}

			fmt.Println("\n❓ ACTIVE UNKNOWN SPACE (RESEARCH GAPS):")
			if len(gaps) == 0 {
				fmt.Println("  ✓ All modeled boundaries currently have assigned hypotheses or tested properties.")
			} else {
				for i, g := range gaps {
					if i >= 5 {
						fmt.Printf("  ... and %d more research gaps\n", len(gaps)-5)
						break
					}
					fmt.Printf("  [%d] [%s] %s\n", i+1, g.Type, g.Description)
					fmt.Printf("      Uncertainty: %.2f | Expected Info Gain: %.2f\n", g.Uncertainty, g.ExpectedInfoGain)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&workspaceDir, "workspace", "w", ".", "Path to DOGE workspace directory")

	return cmd
}
