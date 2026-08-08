package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
)

// newAskCmd creates the 'ask' command.
func newAskCmd() *cobra.Command {
	var wsPath string
	var showPrompt bool
	var maxEvidence int

	cmd := &cobra.Command{
		Use:   "ask <question>",
		Short: "Ask a question about the workspace",
		Long: `Ask a question and see what evidence the workspace contains.

This command retrieves relevant evidence from all workspace sources
(entities, relationships, observations, insights, tasks, timeline)
and shows the structured context that would be sent to an AI.

Currently runs in evidence-only mode (no LLM). When AI is enabled,
this will invoke the reasoning engine with the retrieved evidence.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			question := strings.Join(args, " ")

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			// Step 1: Retrieve evidence.
			bundle, err := application.RetrieveEvidence(cmd.Context(), question, maxEvidence)
			if err != nil {
				return fmt.Errorf("evidence retrieval failed: %w", err)
			}

			fmt.Printf("Question: %s\n", question)
			fmt.Println("─────────────────────────────────────────────")
			fmt.Printf("Evidence: %s\n\n", bundle.Summary())

			if len(bundle.Evidence) == 0 {
				fmt.Println("No relevant evidence found in the workspace.")
				return nil
			}

			// Display evidence grouped by type.
			typeOrder := []string{"insight", "task", "entity", "relationship", "observation", "timeline"}
			grouped := map[string]int{}
			for _, e := range bundle.Evidence {
				grouped[string(e.Type)]++
			}

			for _, t := range typeOrder {
				count, ok := grouped[t]
				if !ok {
					continue
				}

				fmt.Printf("  %s (%d)\n", strings.Title(t+"s"), count)
				for _, e := range bundle.Evidence {
					if string(e.Type) != t {
						continue
					}
					icon := evidenceIcon(t)
					fmt.Printf("    %s  %.0f%%  %s\n", icon, e.Relevance*100, e.Summary)
				}
				fmt.Println()
			}

			if bundle.Truncated {
				fmt.Printf("  ... %d additional items not shown\n\n", bundle.TotalFound-len(bundle.Evidence))
			}

			// Step 2: Build prompt (optional).
			if showPrompt {
				prompt := application.BuildPrompt(question, bundle)
				fmt.Println("═══════════════════════════════════════════")
				fmt.Println("AI Prompt Preview")
				fmt.Println("═══════════════════════════════════════════")
				fmt.Printf("Estimated tokens: ~%d\n", prompt.TokenEstimate)
				fmt.Printf("Evidence items: %d\n\n", prompt.EvidenceCount)
				fmt.Println("--- System Message ---")
				fmt.Println(prompt.SystemMessage)
				fmt.Println("\n--- User Message ---")
				fmt.Println(prompt.UserMessage)
			}

			// AI note.
			if !showPrompt {
				fmt.Println("─────────────────────────────────────────────")
				fmt.Println("AI is disabled. Use --prompt to preview the AI prompt.")
				fmt.Println("When AI is enabled, this evidence will be sent to the reasoning engine.")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	cmd.Flags().BoolVar(&showPrompt, "prompt", false, "show the AI prompt that would be generated")
	cmd.Flags().IntVar(&maxEvidence, "max-evidence", 30, "maximum evidence items to retrieve")
	return cmd
}

func evidenceIcon(t string) string {
	switch t {
	case "insight":
		return "💡"
	case "task":
		return "📋"
	case "entity":
		return "◆"
	case "relationship":
		return "→"
	case "observation":
		return "●"
	case "timeline":
		return "⏱"
	default:
		return "•"
	}
}
