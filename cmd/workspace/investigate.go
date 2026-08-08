package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/investigation"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/internal/memory"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func newInvestigateCmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "investigate",
		Short: "Manage research investigations",
		Long: `Create, manage, and track research investigations.

An investigation is a focused line of research that connects
hypotheses, tasks, findings, and tested surfaces into a coherent
research journey.`,
	}

	cmd.PersistentFlags().StringVar(&wsPath, "path", "", "workspace directory")

	cmd.AddCommand(
		newInvestigateStartCmd(&wsPath),
		newInvestigateListCmd(&wsPath),
		newInvestigateStatusCmd(&wsPath),
		newInvestigateHypothesizeCmd(&wsPath),
		newInvestigateFindingCmd(&wsPath),
		newInvestigateSurfaceCmd(&wsPath),
		newInvestigateConcludeCmd(&wsPath),
	)

	return cmd
}

func newInvestigateStartCmd(wsPath *string) *cobra.Command {
	var objective string

	cmd := &cobra.Command{
		Use:   "start <title>",
		Short: "Start a new investigation",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			application, repo, _, cleanup, err := openWithInvestigation(cmd, *wsPath)
			if err != nil {
				return err
			}
			defer cleanup()

			title := strings.Join(args, " ")
			inv := &domain.Investigation{
				Title:     title,
				Objective: objective,
				ProjectID: application.DefaultProjectID,
			}

			if err := repo.Create(cmd.Context(), inv); err != nil {
				return err
			}

			fmt.Printf("Investigation started: %s\n", title)
			fmt.Printf("ID: %s\n", inv.ID)
			if objective != "" {
				fmt.Printf("Objective: %s\n", objective)
			}
			fmt.Println("\nNext steps:")
			fmt.Println("  doge investigate hypothesize \"Your hypothesis\"")
			fmt.Println("  doge investigate surface --category authentication")
			return nil
		},
	}

	cmd.Flags().StringVar(&objective, "objective", "", "research objective")
	return cmd
}

func newInvestigateListCmd(wsPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List investigations",
		RunE: func(cmd *cobra.Command, args []string) error {
			application, repo, _, cleanup, err := openWithInvestigation(cmd, *wsPath)
			if err != nil {
				return err
			}
			defer cleanup()

			investigations, err := repo.List(cmd.Context(), domain.InvestigationFilter{
				ProjectID: ptrUUID(application.DefaultProjectID),
			})
			if err != nil {
				return err
			}

			if len(investigations) == 0 {
				fmt.Println("No investigations found.")
				fmt.Println("Start one with: doge investigate start \"Your investigation\"")
				return nil
			}

			for _, inv := range investigations {
				icon := "🔬"
				if inv.Status == domain.InvestigationPaused {
					icon = "⏸"
				} else if inv.Status == domain.InvestigationConcluded {
					icon = "✅"
				}
				fmt.Printf("%s  [%s] %s\n", icon, inv.Status, inv.Title)
				if inv.Objective != "" {
					fmt.Printf("   Objective: %s\n", inv.Objective)
				}
				fmt.Printf("   Created: %s\n", inv.CreatedAt.Format("2006-01-02 15:04"))
			}
			return nil
		},
	}
}

func newInvestigateStatusCmd(wsPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current investigation status",
		RunE: func(cmd *cobra.Command, args []string) error {
			application, _, mem, cleanup, err := openWithInvestigation(cmd, *wsPath)
			if err != nil {
				return err
			}
			defer cleanup()

			inv, err := mem.ActiveInvestigation(cmd.Context(), application.DefaultProjectID)
			if err != nil {
				return err
			}
			if inv == nil {
				fmt.Println("No active investigation.")
				return nil
			}

			state, err := mem.GetInvestigationState(cmd.Context(), inv.ID)
			if err != nil {
				return err
			}

			displayInvestigationStatus(state)
			return nil
		},
	}
}

func newInvestigateHypothesizeCmd(wsPath *string) *cobra.Command {
	var hypType string

	cmd := &cobra.Command{
		Use:   "hypothesize <title>",
		Short: "Add a hypothesis to the active investigation",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			application, _, mem, cleanup, err := openWithInvestigation(cmd, *wsPath)
			if err != nil {
				return err
			}
			defer cleanup()

			inv, err := mem.ActiveInvestigation(cmd.Context(), application.DefaultProjectID)
			if err != nil || inv == nil {
				return fmt.Errorf("no active investigation: start one first")
			}

			title := strings.Join(args, " ")
			now := time.Now().UTC()

			_, err = application.DB.Conn().ExecContext(cmd.Context(),
				`INSERT INTO hypotheses (id, title, description, type, status, confidence, entity_ids, supporting_evidence, refuting_evidence, notes, project_id, proposed_by, created_at, updated_at, investigation_id)
				 VALUES (?, ?, '', ?, 'proposed', 0.0, '[]', '[]', '[]', '', ?, 'researcher', ?, ?, ?)`,
				uuid.New().String(), title, hypType,
				application.DefaultProjectID.String(),
				now.Format(time.RFC3339), now.Format(time.RFC3339),
				inv.ID.String())
			if err != nil {
				return fmt.Errorf("creating hypothesis: %w", err)
			}

			fmt.Printf("Hypothesis added: %s\n", title)
			fmt.Printf("Investigation: %s\n", inv.Title)
			return nil
		},
	}

	cmd.Flags().StringVar(&hypType, "type", "vulnerability", "hypothesis type")
	return cmd
}

func newInvestigateFindingCmd(wsPath *string) *cobra.Command {
	var evidenceID string
	var severity string

	cmd := &cobra.Command{
		Use:   "finding <title>",
		Short: "Record a finding (requires evidence)",
		Long: `Record a researcher-confirmed finding.

Findings require evidence. The AI can propose hypotheses, but only
the researcher can establish findings.

  AI can propose → Hypothesis
  Evidence + researcher → Finding ✓
  AI alone → Finding ✗`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if evidenceID == "" {
				return fmt.Errorf("findings require evidence: use --evidence <id>")
			}

			application, _, mem, cleanup, err := openWithInvestigation(cmd, *wsPath)
			if err != nil {
				return err
			}
			defer cleanup()

			inv, err := mem.ActiveInvestigation(cmd.Context(), application.DefaultProjectID)
			if err != nil || inv == nil {
				return fmt.Errorf("no active investigation: start one first")
			}

			title := strings.Join(args, " ")
			eid := uuid.MustParse(evidenceID)
			invID := inv.ID
			now := time.Now().UTC()

			finding := domain.Finding{
				Title:           title,
				Severity:        domain.Severity(severity),
				EvidenceIDs:     []uuid.UUID{eid},
				InvestigationID: &invID,
				ProjectID:       application.DefaultProjectID,
			}

			if err := domain.ValidateFinding(finding); err != nil {
				return err
			}


			eJSON := fmt.Sprintf(`["%s"]`, eid.String())

			_, err = application.DB.Conn().ExecContext(cmd.Context(),
				`INSERT INTO findings (id, title, description, severity, status, entity_ids, evidence_ids, hypothesis_id, notes, project_id, created_at, updated_at, investigation_id)
				 VALUES (?, ?, '', ?, 'confirmed', '[]', ?, NULL, '', ?, ?, ?, ?)`,
				uuid.New().String(), title, severity, eJSON,
				application.DefaultProjectID.String(),
				now.Format(time.RFC3339), now.Format(time.RFC3339),
				inv.ID.String())
			if err != nil {
				return fmt.Errorf("creating finding: %w", err)
			}

			fmt.Printf("Finding recorded: %s\n", title)
			fmt.Printf("Evidence: %s\n", evidenceID)
			fmt.Printf("Investigation: %s\n", inv.Title)
			return nil
		},
	}

	cmd.Flags().StringVar(&evidenceID, "evidence", "", "evidence ID (required)")
	cmd.Flags().StringVar(&severity, "severity", "info", "severity (critical/high/medium/low/info)")
	return cmd
}

func newInvestigateSurfaceCmd(wsPath *string) *cobra.Command {
	var category string

	cmd := &cobra.Command{
		Use:   "surface",
		Short: "Manage tested surfaces",
		Long: `Register and track tested attack surfaces.

This answers: "What remains unexplored?"

  doge investigate surface --category authentication
  doge investigate surface                              (list all)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			application, repo, mem, cleanup, err := openWithInvestigation(cmd, *wsPath)
			if err != nil {
				return err
			}
			defer cleanup()

			inv, err := mem.ActiveInvestigation(cmd.Context(), application.DefaultProjectID)
			if err != nil || inv == nil {
				return fmt.Errorf("no active investigation: start one first")
			}

			if category != "" {
				// Register a new surface.
				s := &domain.TestedSurface{
					InvestigationID: inv.ID,
					Category:        category,
					ProjectID:       application.DefaultProjectID,
				}
				if err := repo.CreateSurface(cmd.Context(), s); err != nil {
					return err
				}
				fmt.Printf("Surface registered: %s [UNTESTED]\n", category)
				return nil
			}

			// List surfaces.
			surfaces, err := repo.ListSurfaces(cmd.Context(), inv.ID)
			if err != nil {
				return err
			}
			if len(surfaces) == 0 {
				fmt.Println("No tested surfaces registered.")
				fmt.Println("Register one with: doge investigate surface --category authentication")
				return nil
			}

			fmt.Printf("Investigation: %s\n", inv.Title)
			fmt.Println("─────────────────────────────────────────────")

			var tested, untested, inconclusive []domain.TestedSurface
			for _, s := range surfaces {
				switch s.Status {
				case domain.SurfaceTested:
					tested = append(tested, s)
				case domain.SurfaceInconclusive:
					inconclusive = append(inconclusive, s)
				default:
					untested = append(untested, s)
				}
			}

			if len(tested) > 0 {
				fmt.Println("Tested")
				for _, s := range tested {
					fmt.Printf("  ✓ %s\n", s.Category)
				}
			}
			if len(inconclusive) > 0 {
				fmt.Println("Inconclusive")
				for _, s := range inconclusive {
					fmt.Printf("  ? %s\n", s.Category)
				}
			}
			if len(untested) > 0 {
				fmt.Println("Unexplored")
				for _, s := range untested {
					fmt.Printf("  ⚠ %s\n", s.Category)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&category, "category", "", "surface category to register")
	return cmd
}

func newInvestigateConcludeCmd(wsPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "conclude",
		Short: "Conclude the active investigation",
		RunE: func(cmd *cobra.Command, args []string) error {
			application, repo, mem, cleanup, err := openWithInvestigation(cmd, *wsPath)
			if err != nil {
				return err
			}
			defer cleanup()

			inv, err := mem.ActiveInvestigation(cmd.Context(), application.DefaultProjectID)
			if err != nil || inv == nil {
				return fmt.Errorf("no active investigation")
			}

			now := time.Now().UTC()
			status := domain.InvestigationConcluded
			if err := repo.Update(cmd.Context(), inv.ID, domain.InvestigationUpdate{
				Status:      &status,
				ConcludedAt: &now,
			}); err != nil {
				return err
			}

			fmt.Printf("Investigation concluded: %s\n", inv.Title)
			fmt.Println("This investigation is now immutable.")
			return nil
		},
	}
}

func displayInvestigationStatus(state *memory.InvestigationState) {
	inv := state.Investigation
	fmt.Printf("Investigation: %s\n", inv.Title)
	fmt.Printf("Status: %s\n", strings.ToUpper(string(inv.Status)))
	if inv.Objective != "" {
		fmt.Printf("Objective: %s\n", inv.Objective)
	}
	fmt.Println("═══════════════════════════════════════════")

	// Hypotheses
	if len(state.Hypotheses) > 0 {
		fmt.Println("\nHypotheses")
		fmt.Println("────────────────────────────────────────")
		for _, h := range state.Hypotheses {
			icon := "?"
			if h.Status == domain.HypothesisConfirmed {
				icon = "✓"
			} else if h.Status == domain.HypothesisRejected {
				icon = "✗"
			}
			fmt.Printf("  %s %s\n", icon, h.Title)
			fmt.Printf("    Status: %s | Confidence: %.0f%%\n", h.Status, h.Confidence*100)
		}
	}

	// Findings
	if len(state.Findings) > 0 {
		fmt.Println("\nFindings")
		fmt.Println("────────────────────────────────────────")
		for _, f := range state.Findings {
			fmt.Printf("  ✓ %s [%s]\n", f.Title, f.Severity)
		}
	}

	// Tested Surfaces
	if len(state.TestedSurfaces) > 0 {
		fmt.Println("\nTested Surfaces")
		fmt.Println("────────────────────────────────────────")
		for _, s := range state.TestedSurfaces {
			icon := "⚠"
			if s.Status == domain.SurfaceTested {
				icon = "✓"
			} else if s.Status == domain.SurfaceInconclusive {
				icon = "?"
			}
			fmt.Printf("  %s %s\n", icon, s.Category)
		}
	}

	// Tasks
	if state.Stats.TasksPending > 0 {
		fmt.Println("\nPending Tasks")
		fmt.Println("────────────────────────────────────────")
		for _, t := range state.Tasks {
			if t.Status == domain.TaskPending || t.Status == domain.TaskInProgress {
				fmt.Printf("  [%s] %s\n", strings.ToUpper(string(t.Priority)), t.Title)
			}
		}
	}

	// Sessions
	if len(state.RecentSessions) > 0 {
		fmt.Println("\nRecent AI Sessions")
		fmt.Println("────────────────────────────────────────")
		for _, s := range state.RecentSessions {
			status := "✓"
			if s.Rejected {
				status = "✗"
			}
			fmt.Printf("  %s %s (%s)\n", status, s.Question, s.CreatedAt.Format("Jan 02 15:04"))
		}
	}

	// Summary
	fmt.Println("\n═══════════════════════════════════════════")
	fmt.Printf("Hypotheses: %d active / %d total\n",
		state.Stats.HypothesesActive, state.Stats.HypothesesTotal)
	fmt.Printf("Tasks:      %d pending / %d total\n",
		state.Stats.TasksPending, state.Stats.TasksTotal)
	fmt.Printf("Findings:   %d\n", state.Stats.FindingsTotal)
	fmt.Printf("Surfaces:   %d tested / %d total\n",
		state.Stats.SurfacesTested, state.Stats.SurfacesTotal)
}

func openWithInvestigation(cmd *cobra.Command, wsPath string) (*app.App, *investigation.Repository, *memory.Service, func(), error) {
	if wsPath == "" {
		wsPath = "."
	}
	application, err := app.Open(cmd.Context(), wsPath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to open workspace: %w", err)
	}

	eventBus := bus.New(bus.Options{Logger: logging.WithModule(application.Logger, "bus")})
	repo := investigation.New(application.DB.Conn(), eventBus, logging.WithModule(application.Logger, "investigation"))
	mem := memory.NewService(application.DB.Conn(), repo, logging.WithModule(application.Logger, "memory"))

	cleanup := func() { application.Shutdown() }
	return application, repo, mem, cleanup, nil
}

func ptrUUID(id uuid.UUID) *uuid.UUID {
	return &id
}
