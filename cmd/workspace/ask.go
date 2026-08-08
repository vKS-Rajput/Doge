package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/reasoning"
	"github.com/vKS-Rajput/doge/pkg/ai"
)

// newAskCmd creates the 'ask' command.
func newAskCmd() *cobra.Command {
	var wsPath string
	var showPrompt bool
	var maxEvidence int
	var model string
	var useAI bool

	cmd := &cobra.Command{
		Use:   "ask <question>",
		Short: "Ask a question about the workspace",
		Long: `Ask a question and retrieve evidence from the workspace.

Without --ai: shows retrieved evidence only (default).
With --ai: invokes the reasoning engine via Ollama.

Evidence is retrieved from all workspace sources
(entities, relationships, observations, insights, tasks, timeline).`,
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

			// Display evidence summary.
			displayEvidence(bundle)

			// Step 2: AI mode or prompt preview.
			if useAI {
				return runAI(cmd.Context(), application, question, bundle, model)
			}

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
			} else {
				fmt.Println("─────────────────────────────────────────────")
				fmt.Println("AI is disabled. Use --ai to invoke the reasoning engine.")
				fmt.Println("Use --prompt to preview what the AI would receive.")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	cmd.Flags().BoolVar(&showPrompt, "prompt", false, "show the AI prompt that would be generated")
	cmd.Flags().IntVar(&maxEvidence, "max-evidence", 30, "maximum evidence items to retrieve")
	cmd.Flags().StringVar(&model, "model", "qwen3:4b", "Ollama model to use")
	cmd.Flags().BoolVar(&useAI, "ai", false, "invoke AI reasoning engine via Ollama")
	return cmd
}

func displayEvidence(bundle *app.EvidenceBundle) {
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

		fmt.Printf("  %s (%d)\n", strings.ToUpper(t[:1])+t[1:]+"s", count)
		for _, e := range bundle.Evidence {
			if string(e.Type) != t {
				continue
			}
			icon := evidenceIcon(t)
			groupNote := ""
			if e.GroupedCount > 1 {
				groupNote = fmt.Sprintf(" (%d related)", e.GroupedCount)
			}
			fmt.Printf("    %s  %.0f%%  %s%s\n", icon, e.Relevance*100, e.Summary, groupNote)
		}
		fmt.Println()
	}

	if bundle.Truncated {
		fmt.Printf("  ... %d additional items not shown\n\n", bundle.TotalFound-len(bundle.Evidence))
	}
}

func runAI(ctx context.Context, application *app.App, question string, bundle *app.EvidenceBundle, model string) error {
	config := reasoning.DefaultOllamaConfig()
	config.Model = model

	engine := reasoning.NewEngine(config, application.Logger)

	// Check Ollama is reachable.
	if err := engine.Ping(ctx); err != nil {
		return fmt.Errorf("Ollama not available: %v\n\nMake sure Ollama is running:\n  ollama serve\n\nThen pull the model:\n  ollama pull %s", err, model)
	}

	fmt.Println("═══════════════════════════════════════════")
	fmt.Printf("Reasoning with %s...\n", model)
	fmt.Println("═══════════════════════════════════════════")

	result, err := engine.Ask(ctx, question, bundle)
	if err != nil {
		if re, ok := err.(*ai.ReasoningError); ok {
			fmt.Printf("\n⚠ AI response could not be verified.\n")
			fmt.Printf("Stage: %s\n", re.Stage)
			fmt.Printf("Error: %s\n", re.Message)
			if re.Retried {
				fmt.Println("(Retry was attempted but also failed.)")
			}
			return nil // Don't propagate as CLI error.
		}
		return err
	}

	// Display verified answer.
	fmt.Printf("\nAnswer\n")
	fmt.Println("─────────────────────────────────────────────")
	fmt.Println(result.Answer)

	// Display supported claims.
	if len(result.SupportedClaims) > 0 {
		fmt.Printf("\n✅ Supported Claims (%d)\n", len(result.SupportedClaims))
		for _, c := range result.SupportedClaims {
			fmt.Printf("  • %s\n", c.Text)
			fmt.Printf("    Evidence: %s | Confidence: %.0f%% | %s\n",
				strings.Join(c.EvidenceIDs, ", "), c.Confidence*100, c.Category)
		}
	}

	// Display rejected claims.
	if len(result.RejectedClaims) > 0 {
		fmt.Printf("\n⚠ Rejected Claims (%d)\n", len(result.RejectedClaims))
		for _, c := range result.RejectedClaims {
			fmt.Printf("  ✗ %s\n", c.Text)
			fmt.Printf("    Reason: %s\n", c.VerificationReason)
		}
	}

	// Display limitations.
	if len(result.Limitations) > 0 {
		fmt.Println("\nLimitations")
		for _, l := range result.Limitations {
			fmt.Printf("  • %s\n", l)
		}
	}

	// Display metrics.
	fmt.Printf("\n─────────────────────────────────────────────\n")
	fmt.Printf("Model: %s | Tokens: %d | Time: %dms\n",
		result.ModelUsed, result.TotalTokens, result.DurationMs)

	return nil
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
