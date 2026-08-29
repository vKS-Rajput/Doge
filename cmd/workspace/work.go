package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/coverage"
	"github.com/vKS-Rajput/doge/internal/journal"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/runner"
	"github.com/vKS-Rajput/doge/internal/session"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// newWorkCmd creates the 'work' command — the primary research shell.
//
// Usage:
//
//	doge work                              # open existing workspace
//	doge work --target veeza.ai --env authorized  # create + open
//
// You work normally inside this shell. DOGE auto-captures everything.
func newWorkCmd() *cobra.Command {
	var targetFlag string
	var envFlag string

	cmd := &cobra.Command{
		Use:   "work [workspace]",
		Short: "Research workspace — work normally, DOGE captures everything",
		Long: `Open the DOGE research shell.

You run commands normally. DOGE automatically:
  • Records the command in the journal
  • Captures stdout/stderr
  • Detects new output files
  • Parses supported formats (nmap, httpx, katana, etc.)
  • Creates observations
  • Updates the knowledge graph
  • Recalculates coverage and gaps
  • Learns research patterns

Built-in commands:
  note <text>     Record a researcher observation
  status          Show investigation summary
  coverage        Show coverage bars
  gaps            Show investigation gaps
  journal         Show recent commands
  exit            Leave the shell

Examples:
  doge work
  doge work --target veeza.ai --env authorized`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wsPath := "."
			if len(args) > 0 {
				wsPath = args[0]
			}

			// Open or create workspace.
			var application *app.App
			var err error

			if targetFlag != "" {
				application, err = openOrInit(cmd.Context(), wsPath, targetFlag)
			} else {
				application, err = app.Open(cmd.Context(), wsPath)
			}
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			absPath, _ := filepath.Abs(wsPath)

			// Determine target for display.
			target := targetFlag
			if target == "" {
				state, _ := session.LoadState(absPath)
				if state != nil {
					target = state.Target
				} else {
					target = filepath.Base(absPath)
				}
			}

			env := envFlag
			if env == "" {
				env = "research"
			}

			// Write initial session state so doge monitor discovers us.
			writeWorkSessionState(absPath, target, env, application.DefaultProjectID)
			defer session.ClearState(absPath) // Clean up on exit.

			// Open journal + learning DB.
			journalDB, err := openJournalDB(absPath)
			if err != nil {
				return fmt.Errorf("failed to open database: %w", err)
			}
			defer journalDB.Close()

			journalStore := journal.NewStore(journalDB)
			journalStore.EnsureTable()

			learningMem := learning.NewMemory(journalDB)
			learningMem.EnsureTable()
			learner := learning.NewLearner(learningMem)

			// Print banner.
			printWorkBanner(target, env, absPath)

			// Run the research shell.
			return runWorkShell(application, absPath, target, env, journalStore, learner, learningMem)
		},
	}

	cmd.Flags().StringVar(&targetFlag, "target", "", "primary target")
	cmd.Flags().StringVar(&envFlag, "env", "", "environment (htb, lab, authorized)")

	return cmd
}

func printWorkBanner(target, env, wsPath string) {
	fmt.Println()
	fmt.Println("🐕 DOGE Research Workspace")
	fmt.Println("────────────────────────────────────")
	fmt.Printf("  Target: %s\n", target)
	fmt.Printf("  Scope:  %s\n", env)
	fmt.Printf("  Mode:   RESEARCH\n")
	fmt.Printf("  Path:   %s\n", wsPath)
	fmt.Println()
	fmt.Println("  Commands auto-captured. Type 'help' for built-in commands.")
	fmt.Println("────────────────────────────────────")
	fmt.Println()
}

func runWorkShell(application *app.App, wsPath, target, env string, journalStore *journal.Store, learner *learning.Learner, learningMem *learning.Memory) error {
	reader := bufio.NewReader(os.Stdin)
	commandNum := 0

	for {
		fmt.Printf("DOGE:%s $ ", target)

		line, err := reader.ReadString('\n')
		if err != nil {
			// EOF = Ctrl+D or terminal closed. This is the ONLY
			// legitimate way to exit the loop besides "exit".
			if err == io.EOF {
				fmt.Println("\n  EOF received — exiting.")
			} else {
				fmt.Fprintf(os.Stderr, "\n  ⚠ stdin read error: %v\n", err)
			}
			break
		}

		input := strings.TrimSpace(line)
		if input == "" {
			continue
		}

		// Handle built-in commands.
		if handled := handleBuiltinCommand(input, application, wsPath, journalStore, learningMem); handled {
			if input == "exit" || input == "quit" {
				break
			}
			continue
		}

		// Execute the command and auto-capture.
		commandNum++
		result := runner.Run(input, wsPath, os.Stdout, os.Stderr)

		// Auto-ingest results.
		obsCount := autoIngest(application, result, wsPath, journalStore, learner, target, commandNum)

		// Print summary.
		tool := runner.DetectTool(input)
		fmt.Println()
		if result.ExitCode == 0 {
			fmt.Printf("  ✓ %s recorded", tool)
		} else {
			fmt.Printf("  ⚠ %s (exit %d)", tool, result.ExitCode)
		}
		if obsCount > 0 {
			fmt.Printf(" → %d observations", obsCount)
		}
		if len(result.NewFiles) > 0 {
			fmt.Printf(" | %d new files", len(result.NewFiles))
		}
		fmt.Println()
		fmt.Println()

		// Refresh session state so monitor sees updates.
		writeWorkSessionState(wsPath, target, env, application.DefaultProjectID)
	}

	// Print exit summary.
	count, _ := journalStore.Count(application.DefaultProjectID)
	totalObs, _ := journalStore.TotalObservations(application.DefaultProjectID)
	patternCount := learningMem.PatternCount()

	fmt.Println()
	fmt.Println("🐕 DOGE — Session complete")
	fmt.Printf("  Commands: %d | Observations: %d | Patterns: %d\n", count, totalObs, patternCount)
	fmt.Println()

	return nil
}

func handleBuiltinCommand(input string, application *app.App, wsPath string, journalStore *journal.Store, learningMem *learning.Memory) bool {
	parts := strings.SplitN(input, " ", 2)
	cmd := strings.ToLower(parts[0])

	switch cmd {
	case "exit", "quit":
		return true

	case "help":
		fmt.Println()
		fmt.Println("  Built-in commands:")
		fmt.Println("    note <text>     Record a researcher observation")
		fmt.Println("    status          Show investigation summary")
		fmt.Println("    coverage        Show coverage bars")
		fmt.Println("    gaps            Show investigation gaps")
		fmt.Println("    journal         Show recent commands")
		fmt.Println("    patterns        Show learned patterns")
		fmt.Println("    help            Show this help")
		fmt.Println("    exit            Leave the shell")
		fmt.Println()
		fmt.Println("  Everything else is executed as a shell command and auto-captured.")
		fmt.Println()
		return true

	case "note":
		if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
			fmt.Println("  Usage: note <text>")
			return true
		}
		noteText := strings.TrimSpace(parts[1])
		storeResearchNote(application, wsPath, noteText)
		return true

	case "status":
		printWorkStatus(application, wsPath, journalStore, learningMem)
		return true

	case "journal", "history":
		printWorkJournal(application, journalStore)
		return true

	case "patterns":
		printWorkPatterns(learningMem)
		return true

	case "coverage":
		printWorkCoverage(application)
		return true

	case "gaps":
		printWorkGaps(application)
		return true
	}

	return false
}

func autoIngest(application *app.App, result *runner.RunResult, wsPath string, journalStore *journal.Store, learner *learning.Learner, target string, num int) int {
	totalObs := 0
	now := time.Now()
	tool := runner.DetectTool(result.Command)

	// 1. Try to ingest any new files.
	for _, newFile := range result.NewFiles {
		filePath := filepath.Join(wsPath, newFile)
		importResult, err := application.Import(context.Background(), filePath, application.DefaultProjectID)
		if err != nil {
			continue
		}
		if importResult != nil {
			totalObs += importResult.Observations
		}
	}

	// 2. If stdout has content and no files were created, store stdout as artifact.
	if len(result.NewFiles) == 0 && len(result.Stdout) > 100 {
		// Save stdout to a temp file for ingestion.
		stdoutFile := filepath.Join(wsPath, ".doge", "captured",
			fmt.Sprintf("%s_%d_%s.txt", tool, num, time.Now().Format("150405")))
		os.MkdirAll(filepath.Dir(stdoutFile), 0755)
		if err := os.WriteFile(stdoutFile, []byte(result.Stdout), 0644); err == nil {
			importResult, err := application.Import(context.Background(), stdoutFile, application.DefaultProjectID)
			if err == nil && importResult != nil {
				totalObs += importResult.Observations
			}
		}
	}

	// 3. Record journal entry.
	exec := &journal.Execution{
		ID:           uuid.New(),
		Tool:         tool,
		Command:      result.Command,
		Target:       target,
		Observations: totalObs,
		ExitCode:     result.ExitCode,
		ProjectID:    application.DefaultProjectID,
		StartedAt:    result.StartedAt,
		CompletedAt:  result.CompletedAt,
		IngestedAt:   now,
	}
	journalStore.Record(exec)

	// 4. Feed learning engine (async-safe, errors ignored).
	if totalObs > 0 {
		// Query recent observations to feed to the learner.
		obs := queryRecentObservations(application, 50)
		if len(obs) > 0 {
			learner.LearnFromObservations(obs)
		}
	}

	return totalObs
}

func storeResearchNote(application *app.App, wsPath, noteText string) {
	absPath, _ := filepath.Abs(wsPath)
	dbPath := filepath.Join(absPath, ".doge", "workspace.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		fmt.Printf("  ⚠ Failed: %v\n", err)
		return
	}
	defer db.Close()

	obsID := uuid.New()
	now := time.Now()

	_, err = db.Exec(`
		INSERT OR IGNORE INTO observations
			(id, type, artifact_id, source_tool, project_id, data, raw_value,
			 checksum, observed_at, ingested_at, parser_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		obsID.String(),
		string(domain.ObservationResearcherNote),
		uuid.Nil.String(),
		"researcher",
		application.DefaultProjectID.String(),
		fmt.Sprintf(`{"note":"%s","author":"researcher"}`, strings.ReplaceAll(noteText, `"`, `\"`)),
		noteText,
		fmt.Sprintf("%x", time.Now().UnixNano()),
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
		"manual",
	)
	if err != nil {
		fmt.Printf("  ⚠ Failed: %v\n", err)
		return
	}

	fmt.Printf("\n  📝 Note recorded: %s\n\n", noteText)
}

func printWorkStatus(application *app.App, wsPath string, journalStore *journal.Store, learningMem *learning.Memory) {
	absPath, _ := filepath.Abs(wsPath)
	state, _ := session.LoadState(absPath)

	count, _ := journalStore.Count(application.DefaultProjectID)
	totalObs, _ := journalStore.TotalObservations(application.DefaultProjectID)

	fmt.Println()
	fmt.Println("  🐕 Investigation Status")
	fmt.Println()
	if state != nil {
		fmt.Printf("  Target:       %s\n", state.Target)
		fmt.Printf("  Environment:  %s\n", state.Environment)
	}
	fmt.Printf("  Commands:     %d\n", count)
	fmt.Printf("  Observations: %d\n", totalObs)
	fmt.Printf("  Patterns:     %d\n", learningMem.PatternCount())
	fmt.Printf("  Outcomes:     %d\n", learningMem.OutcomeCount())
	fmt.Println()
}

func printWorkJournal(application *app.App, journalStore *journal.Store) {
	entries, err := journalStore.Recent(application.DefaultProjectID, 10)
	if err != nil || len(entries) == 0 {
		fmt.Println()
		fmt.Println("  No commands recorded yet.")
		fmt.Println()
		return
	}

	fmt.Println()
	for _, e := range entries {
		ago := time.Since(e.IngestedAt).Round(time.Second)
		cmd := e.Command
		if cmd == "" {
			cmd = e.Tool
		}
		fmt.Printf("  %s  %s → %d obs  (%v ago)\n", e.Tool, cmd, e.Observations, ago)
	}
	fmt.Println()
}

func printWorkPatterns(learningMem *learning.Memory) {
	patterns, err := learningMem.AllPatterns()
	if err != nil || len(patterns) == 0 {
		fmt.Println()
		fmt.Println("  No patterns learned yet.")
		fmt.Println()
		return
	}

	fmt.Println()
	fmt.Println("  🧠 Learned Patterns")
	fmt.Println()
	for _, p := range patterns {
		fmt.Printf("  • %s (%.0f%% confidence, %d occurrences)\n",
			p.Description, p.Confidence*100, p.Occurrences)
	}
	fmt.Println()
}

func printWorkCoverage(application *app.App) {
	// Delegate to the coverage engine.
	engine := newCoverageEngineFromApp(application)
	if engine == nil {
		fmt.Println()
		fmt.Println("  Coverage unavailable.")
		fmt.Println()
		return
	}

	report, err := engine.Analyze(application.DefaultProjectID)
	if err != nil {
		fmt.Println()
		fmt.Println("  Coverage analysis failed.")
		fmt.Println()
		return
	}

	fmt.Println()
	for _, c := range report.Categories {
		name := categoryDisplayName(c.Category)
		pct := int(c.Score * 100)
		bar := progressBar(c.Score, 15)
		fmt.Printf("  %s %s %3d%%\n", bar, name, pct)
	}
	fmt.Println()
}

func printWorkGaps(application *app.App) {
	engine := newCoverageEngineFromApp(application)
	if engine == nil {
		fmt.Println()
		fmt.Println("  Gaps unavailable.")
		fmt.Println()
		return
	}

	report, err := engine.Analyze(application.DefaultProjectID)
	if err != nil {
		fmt.Println()
		fmt.Println("  Gap analysis failed.")
		fmt.Println()
		return
	}

	fmt.Println()
	hasGaps := false
	for _, c := range report.Categories {
		if c.Score >= 0.8 {
			continue
		}
		hasGaps = true
		name := categoryDisplayName(c.Category)
		pct := int(c.Score * 100)
		fmt.Printf("  ⚠ %s (%d%%) — needs investigation\n", name, pct)
	}
	if !hasGaps {
		fmt.Println("  ✅ No significant gaps.")
	}
	fmt.Println()
}

func newCoverageEngineFromApp(application *app.App) *coverage.Engine {
	return coverage.NewEngine(application.DB.Conn())
}

func queryRecentObservations(application *app.App, limit int) []domain.Observation {
	db := application.DB.Conn()
	rows, err := db.Query(`
		SELECT id, type, source_tool, data
		FROM observations
		WHERE project_id = ?
		ORDER BY ingested_at DESC
		LIMIT ?
	`, application.DefaultProjectID.String(), limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var observations []domain.Observation
	for rows.Next() {
		var obs domain.Observation
		var id, dataStr string
		err := rows.Scan(&id, (*string)(&obs.Type), &obs.SourceTool, &dataStr)
		if err != nil {
			continue
		}
		obs.ID, _ = uuid.Parse(id)
		if dataStr != "" {
			var data map[string]any
			if json.Unmarshal([]byte(dataStr), &data) == nil {
				obs.Data = data
			}
		}
		observations = append(observations, obs)
	}
	return observations
}

// writeWorkSessionState persists session state for doge monitor to discover.
func writeWorkSessionState(wsPath, target, env string, projectID uuid.UUID) {
	absPath, _ := filepath.Abs(wsPath)

	state := &session.PersistedState{
		InvestigationID: projectID,
		Target:          target,
		Environment:     domain.TargetEnvironment(env),
		ProjectID:       projectID,
		Status:          session.StatusActive,
		Mode:            "research",
		StartedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		PID:             os.Getpid(),
		WorkspacePath:   absPath,
		DatabasePath:    filepath.Join(absPath, ".doge", "workspace.db"),
	}

	// If existing state has a StartedAt, preserve it (session resume).
	existing, err := session.LoadState(absPath)
	if err == nil && existing != nil && !existing.StartedAt.IsZero() {
		state.StartedAt = existing.StartedAt
	}

	dogeDir := filepath.Join(absPath, ".doge")
	os.MkdirAll(dogeDir, 0755)

	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(filepath.Join(dogeDir, session.SessionFile), data, 0644)
}
