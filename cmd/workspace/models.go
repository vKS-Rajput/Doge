package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/pkg/ai"
)

func newModelsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "models",
		Aliases: []string{"model", "ai"},
		Short:   "Inspect and configure provider-neutral reasoning models and routing rules",
		Long: `DOGE Model Router — Inspect reasoning model backends (Deterministic local engine,
Ollama, OpenRouter, OpenAI-compatible), latency, and task routing configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			router := ai.NewModelRouter("deterministic_brain")
			detModel := ai.NewDeterministicModel()
			router.RegisterProvider(detModel)

			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
			fmt.Println("║               🐕 DOGE REASONING MODEL ROUTER                     ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
			fmt.Println(" Default Provider: deterministic_brain (LLM-Free Mode)")
			fmt.Println("──────────────────────────────────────────────────────────────────")

			fmt.Println("\n🤖 REGISTERED MODEL PROVIDERS:")
			fmt.Println("  1. [deterministic_brain] Internal Algorithmic Engine")
			fmt.Println("     Type: Deterministic / Symbolic Core (Zero Token Cost, Offline)")
			fmt.Println("     Status: ✅ ONLINE & ACTIVE")
			fmt.Println("  2. [ollama] Local GGUF / Llama-3 / DeepSeek Backend")
			fmt.Println("     Type: Local API (http://127.0.0.1:11434)")
			fmt.Println("     Status: ⚪ CONFIGURABLE")
			fmt.Println("  3. [openrouter] Multi-Provider Gateway (Claude-3.5, GPT-4o, Gemini)")
			fmt.Println("     Type: Remote API")
			fmt.Println("     Status: ⚪ CONFIGURABLE")

			fmt.Println("\n🧭 REASONING TASK ROUTING TABLE:")
			tasks := []struct {
				Task        ai.TaskType
				DefaultProv string
				Description string
			}{
				{ai.TaskClassification, "deterministic_brain", "Fast heuristic and regex-based response categorization"},
				{ai.TaskSemanticInterpretation, "deterministic_brain", "Response body and error interpretation"},
				{ai.TaskConceptNaming, "deterministic_brain", "MDL anomaly labeling and security concept naming"},
				{ai.TaskHypothesisGeneration, "deterministic_brain", "Competing hypothesis tree generation"},
				{ai.TaskCodeAnalysis, "deterministic_brain", "AST taint flow and source sink matching"},
				{ai.TaskFindingSynthesis, "deterministic_brain", "Proven finding synthesis and report generation"},
			}

			for _, t := range tasks {
				fmt.Printf("  • %-26s → %-20s (%s)\n", t.Task, t.DefaultProv, t.Description)
			}

			// Test deterministic provider responsiveness
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Second)
			defer cancel()
			start := time.Now()
			resp, err := router.Dispatch(ctx, ai.ReasoningRequest{
				TaskType: ai.TaskConceptNaming,
				Prompt:   "Test ping",
			})
			latency := time.Since(start)

			fmt.Println("\n⚡ LATENCY CHECK:")
			if err == nil {
				fmt.Printf("  • Default Provider Latency: %v | Generated: %s\n", latency, resp.Content)
			} else {
				fmt.Printf("  • Error: %v\n", err)
			}

			return nil
		},
	}

	return cmd
}
