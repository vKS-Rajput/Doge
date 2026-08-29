package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/journal"
)

// newIngestCmd creates the 'ingest' command — the primary workflow for research mode.
//
// Usage:
//
//	doge ingest scan.xml
//	doge ingest httpx_output.jsonl --tool httpx
//	doge ingest results.json --tool nmap --command "nmap -sCV -p- target"
//	doge ingest response.txt --tool curl --auth-role anonymous
func newIngestCmd() *cobra.Command {
	var wsPath string
	var toolFlag string
	var commandFlag string
	var targetFlag string
	var authRole string
	var notes string

	cmd := &cobra.Command{
		Use:   "ingest <file>",
		Short: "Feed tool output into DOGE",
		Long: `Ingest a security tool's output into the DOGE knowledge graph.

This is the primary workflow for research mode:
  1. YOU run the tool (nmap, httpx, katana, etc.)
  2. YOU feed the output to DOGE
  3. DOGE parses, correlates, and remembers everything

The file flows through the full pipeline:
  • Artifact Store (content-addressable, deduplication)
  • Parser Registry (automatic tool detection or --tool override)
  • Observation Engine (normalization, deduplication)
  • Knowledge Graph (entities, correlations, surface)
  • Journal (permanent execution history)

Examples:
  doge ingest scan.xml
  doge ingest httpx.jsonl --tool httpx
  doge ingest results.json --command "nmap -sCV target"
  doge ingest response.txt --auth-role anonymous
  doge ingest crawl.jsonl --tool katana --notes "focused on /api"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			startTime := time.Now()

			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			// Import through the existing pipeline.
			result, err := application.Import(cmd.Context(), filePath, application.DefaultProjectID)
			if err != nil {
				return fmt.Errorf("ingest failed: %w", err)
			}

			completedAt := time.Now()

			if !result.ArtifactIsNew {
				fmt.Printf("⚠  File already ingested (duplicate): %s\n", result.ArtifactFileName)
				return nil
			}

			// Determine tool name.
			tool := toolFlag
			if tool == "" && result.ParserUsed != "" {
				tool = result.ParserUsed
			}
			if tool == "" {
				tool = "unknown"
			}

			// Determine target from flag or artifact.
			ingestTarget := targetFlag
			if ingestTarget == "" {
				ingestTarget = filepath.Base(filePath)
			}

			// Print results.
			fmt.Println()
			fmt.Println("🐕 DOGE — Ingested")
			fmt.Println()
			fmt.Printf("  File:          %s\n", result.ArtifactFileName)
			fmt.Printf("  Tool:          %s\n", tool)
			if result.ParserUsed != "" {
				fmt.Printf("  Parser:        %s\n", result.ParserUsed)
				fmt.Printf("  Observations:  %d new, %d duplicates, %d rejected\n",
					result.Observations, result.Duplicates, result.Rejected)
			} else {
				fmt.Println("  Parser:        none (stored as raw artifact)")
			}
			if commandFlag != "" {
				fmt.Printf("  Command:       %s\n", commandFlag)
			}
			if authRole != "" {
				fmt.Printf("  Auth context:  %s\n", authRole)
			}
			if notes != "" {
				fmt.Printf("  Notes:         %s\n", notes)
			}
			fmt.Printf("  Duration:      %v\n", completedAt.Sub(startTime).Round(time.Millisecond))
			fmt.Println()

			// Record in journal.
			absPath, _ := filepath.Abs(wsPath)
			journalDB, err := openJournalDB(absPath)
			if err == nil {
				defer journalDB.Close()
				store := journal.NewStore(journalDB)
				if err := store.EnsureTable(); err == nil {
					exec := &journal.Execution{
						ID:           uuid.New(),
						Tool:         tool,
						Command:      commandFlag,
						Target:       ingestTarget,
						ArtifactPath: filePath,
						ArtifactID:   uuid.Nil,
						Observations: result.Observations,
						ExitCode:     0,
						Notes:        notes,
						ProjectID:    application.DefaultProjectID,
						StartedAt:    startTime,
						CompletedAt:  completedAt,
						IngestedAt:   time.Now(),
					}
					if err := store.Record(exec); err != nil {
						fmt.Printf("  ⚠ Journal: %v\n", err)
					} else {
						count, _ := store.Count(application.DefaultProjectID)
						totalObs, _ := store.TotalObservations(application.DefaultProjectID)
						fmt.Printf("  📓 Journal: entry #%d recorded (%d total observations)\n", count, totalObs)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory (defaults to current directory)")
	cmd.Flags().StringVar(&toolFlag, "tool", "", "tool name (auto-detected if not specified)")
	cmd.Flags().StringVar(&commandFlag, "command", "", "the command that was run")
	cmd.Flags().StringVar(&targetFlag, "target", "", "what was targeted")
	cmd.Flags().StringVar(&authRole, "auth-role", "", "authentication context (anonymous, user, admin)")
	cmd.Flags().StringVar(&notes, "notes", "", "researcher annotation")

	return cmd
}

// openJournalDB opens the workspace database for journal entries.
func openJournalDB(workspacePath string) (*sql.DB, error) {
	dbPath := filepath.Join(workspacePath, ".doge", "workspace.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	return db, nil
}
