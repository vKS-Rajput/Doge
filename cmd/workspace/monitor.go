package main

import (
	"database/sql"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/coverage"
	"github.com/vKS-Rajput/doge/internal/journal"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/session"
)

// newMonitorCmd creates the 'monitor' command — the unified live dashboard.
func newMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor [workspace]",
		Short: "Live investigation dashboard — coverage, gaps, activity, approvals",
		Long: `Open the unified DOGE monitor.

Combines everything you need into one screen:
  • Live command activity
  • Coverage bars
  • Investigation gaps and priorities
  • Learned research patterns
  • Session health
  • Pending approvals (interactive)

Refreshes automatically. Leave it open while you work in 'doge work'.

No separate approvals, logs, runtime, or coverage terminals needed.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wsPath := "."
			if len(args) > 0 {
				wsPath = args[0]
			}
			absPath, _ := filepath.Abs(wsPath)

			return runMonitor(absPath)
		},
	}
	return cmd
}

func runMonitor(wsPath string) error {
	// Initial render.
	if err := renderMonitor(wsPath); err != nil {
		return err
	}

	// Refresh loop.
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Clear screen (ANSI escape).
		fmt.Print("\033[2J\033[H")
		if err := renderMonitor(wsPath); err != nil {
			// If workspace disappears, keep trying.
			fmt.Println("🐕 DOGE Monitor — Waiting for workspace...")
		}
	}

	return nil
}

func renderMonitor(wsPath string) error {
	state, err := session.LoadState(wsPath)

	// Open DB for queries.
	dbPath := filepath.Join(wsPath, ".doge", "workspace.db")
	db, _ := sql.Open("sqlite", dbPath)
	if db != nil {
		defer db.Close()
	}

	// ──── Header ────
	fmt.Println()
	fmt.Println("🐕 DOGE MONITOR")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// ──── Target ────
	fmt.Println("TARGET")
	if state != nil && err == nil {
		fmt.Printf("  %s\n", state.Target)
		fmt.Printf("  Scope: %s\n", strings.ToUpper(string(state.Environment)))
		if state.Mode != "" {
			fmt.Printf("  Mode:  %s\n", strings.ToUpper(state.Mode))
		}
		alive := session.IsSessionRunning(wsPath)
		if alive {
			fmt.Printf("  Session: \033[32mACTIVE\033[0m\n")
		} else {
			fmt.Printf("  Session: \033[33mIDLE\033[0m\n")
		}
		if !state.StartedAt.IsZero() {
			fmt.Printf("  Runtime: %s\n", formatDuration(time.Since(state.StartedAt)))
		}
	} else {
		fmt.Println("  No active session")
		fmt.Println("  Start with: doge work --target <target> --env authorized")
	}
	fmt.Println()

	if db == nil {
		return nil
	}

	// ──── Live Activity ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("LIVE ACTIVITY")
	fmt.Println()

	journalStore := journal.NewStore(db)
	journalStore.EnsureTable()

	projectID := getProjectID(state, db)
	entries, _ := journalStore.Recent(projectID, 8)

	if len(entries) == 0 {
		fmt.Println("  No commands recorded yet.")
		fmt.Println("  Use 'doge work' to start investigating.")
	} else {
		for _, e := range entries {
			ts := e.IngestedAt.Format("15:04:05")
			cmd := e.Command
			if cmd == "" {
				cmd = e.Tool
			}
			if len(cmd) > 50 {
				cmd = cmd[:47] + "..."
			}
			if e.ExitCode == 0 {
				fmt.Printf("  %s  ✓ %s", ts, cmd)
			} else {
				fmt.Printf("  %s  ⚠ %s (exit %d)", ts, cmd, e.ExitCode)
			}
			if e.Observations > 0 {
				fmt.Printf(" → %d obs", e.Observations)
			}
			fmt.Println()
		}
	}
	fmt.Println()

	// ──── Coverage ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("COVERAGE")
	fmt.Println()

	covEngine := coverage.NewEngine(db)
	report, covErr := covEngine.Analyze(projectID)

	if covErr == nil && report != nil {
		for _, c := range report.Categories {
			name := categoryDisplayName(c.Category)
			pct := int(math.Round(c.Score * 100))
			bar := progressBar(c.Score, 15)
			padding := strings.Repeat(" ", 16-len(name))
			fmt.Printf("  %s%s %s %3d%%\n", name, padding, bar, pct)
		}
		fmt.Println()
		totalPct := int(math.Round(report.TotalScore * 100))
		fmt.Printf("  Overall: %d%% | Observations: %d | Entities: %d\n",
			totalPct, report.TotalObservations, report.TotalEntities)
	} else {
		fmt.Println("  No coverage data yet.")
	}
	fmt.Println()

	// ──── Investigation Gaps ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("🔥 INVESTIGATE NEXT")
	fmt.Println()

	if covErr == nil && report != nil {
		gapNum := 0
		for _, c := range report.Categories {
			if c.Score >= 0.8 || gapNum >= 5 {
				continue
			}
			gapNum++
			name := categoryDisplayName(c.Category)
			pct := int(math.Round(c.Score * 100))

			var priority string
			if c.Score < 0.2 {
				priority = "🔴 CRITICAL"
			} else if c.Score < 0.5 {
				priority = "🟡 HIGH"
			} else {
				priority = "🟢 MEDIUM"
			}

			fmt.Printf("  #%d  %s (%d%%)\n", gapNum, name, pct)
			fmt.Printf("      %s\n", priority)

			suggestions := categorySuggestions(c.Category, c.Score)
			if len(suggestions) > 0 {
				fmt.Printf("      → %s\n", suggestions[0])
			}
			fmt.Println()
		}
		if gapNum == 0 {
			fmt.Println("  ✅ All categories above 80%.")
		}
	} else {
		fmt.Println("  Start investigating to see gaps.")
	}
	fmt.Println()

	// ──── Learning ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("🧠 RESEARCH MEMORY")
	fmt.Println()

	learningMem := learning.NewMemory(db)
	learningMem.EnsureTable()

	patternCount := learningMem.PatternCount()
	outcomeCount := learningMem.OutcomeCount()
	eventCount := learningMem.EventCount()

	fmt.Printf("  Patterns:     %d\n", patternCount)
	fmt.Printf("  Outcomes:     %d\n", outcomeCount)
	fmt.Printf("  Events:       %d\n", eventCount)

	if patternCount > 0 {
		patterns, _ := learningMem.AllPatterns()
		if len(patterns) > 0 {
			fmt.Println()
			shown := 0
			for _, p := range patterns {
				if shown >= 3 {
					break
				}
				if p.Confidence < 0.2 {
					continue
				}
				shown++
				fmt.Printf("  • %s\n", p.Description)
				fmt.Printf("    Confidence: %.0f%% | Seen: %d times\n",
					p.Confidence*100, p.Occurrences)
			}
		}
	}
	fmt.Println()

	// ──── Approvals ────
	if state != nil && (state.PendingApproval > 0 || state.PendingConfirm > 0) {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()
		fmt.Println("⚠ APPROVAL REQUIRED")
		fmt.Println()
		if state.PendingApproval > 0 {
			fmt.Printf("  %d hypotheses need approval\n", state.PendingApproval)
		}
		if state.PendingConfirm > 0 {
			fmt.Printf("  %d findings need confirmation\n", state.PendingConfirm)
		}
		fmt.Println("  Run: doge approvals")
		fmt.Println()
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Updated: %s\n", time.Now().Format("15:04:05"))
	fmt.Println()

	return nil
}

func getProjectID(state *session.PersistedState, db *sql.DB) uuid.UUID {
	// Try to get the default project ID from the database.
	var id string
	err := db.QueryRow(`SELECT id FROM projects LIMIT 1`).Scan(&id)
	if err == nil {
		parsed, _ := uuid.Parse(id)
		return parsed
	}
	return uuid.Nil
}
