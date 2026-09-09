package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/explain"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newWhyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "why <hypothesis-id>",
		Short: "Display epistemic justification and evidence chain",
		Long: `Explains the reasoning, evidence chain, and falsifiability criteria
behind a research hypothesis or recommendation.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hypID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid UUID format for hypothesis ID: %s", args[0])
			}

			wsPath, _ := filepath.Abs(".")
			state, err := session.LoadState(wsPath)
			if err != nil {
				fmt.Println("🐕 DOGE — No active session found.")
				return nil
			}

			cfg, err := scope.LoadConfig(wsPath)
			if err != nil {
				cfg = &scope.Config{
					Target:      state.Target,
					Environment: string(state.Environment),
					InScope:     []string{state.Target, "*." + state.Target},
					Rules:       scope.DefaultProgramRules(),
				}
			}

			scopeEngine, _ := scope.NewEngine(*cfg)
			hypEngine := hypothesis.NewEngine()

			// Load persisted hypotheses from research session
			resSessPath := filepath.Join(wsPath, ".doge", "research_session.json")
			if data, err := os.ReadFile(resSessPath); err == nil {
				var snap struct {
					Hypotheses []*hypothesis.ResearchHypothesis `json:"hypotheses"`
				}
				if err := json.Unmarshal(data, &snap); err == nil {
					for _, h := range snap.Hypotheses {
						hypEngine.AddHypothesis(h)
					}
				}
			}

			explainer := explain.New(scopeEngine, hypEngine, nil)

			expl, err := explainer.ExplainHypothesis(hypID)
			if err != nil {
				fmt.Printf("🐕 DOGE: %v\n", err)
				return nil
			}

			fmt.Println(expl.SummaryMarkdown)
			return nil
		},
	}
	return cmd
}
