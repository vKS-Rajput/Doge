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

// newNotebookCmd creates the 'notebook' command — the investigation browser.
func newNotebookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notebook [workspace]",
		Short: "View complete investigation state — history, evidence, coverage, patterns",
		Long: `Print the complete DOGE investigation notebook.

Shows everything DOGE knows about the investigation:
  • Session summary
  • Command history
  • Discovered entities (hosts, endpoints, parameters, technologies)
  • Coverage assessment
  • Investigation gaps
  • Learned research patterns
  • Researcher notes
  • Research priorities

This is the single investigation browser.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wsPath := "."
			if len(args) > 0 {
				wsPath = args[0]
			}
			absPath, _ := filepath.Abs(wsPath)

			return renderNotebook(absPath)
		},
	}
	return cmd
}

func renderNotebook(wsPath string) error {
	state, _ := session.LoadState(wsPath)

	dbPath := filepath.Join(wsPath, ".doge", "workspace.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	projectID := getProjectID(state, db)

	// ──── Header ────
	fmt.Println()
	fmt.Println("🐕 DOGE NOTEBOOK")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// ──── Target ────
	fmt.Println("TARGET")
	if state != nil {
		fmt.Printf("  %s\n", state.Target)
		fmt.Printf("  Environment: %s\n", state.Environment)
		if state.Mode != "" {
			fmt.Printf("  Mode: %s\n", state.Mode)
		}
	}
	fmt.Println()

	// ──── Session Summary ────
	journalStore := journal.NewStore(db)
	journalStore.EnsureTable()

	commandCount, _ := journalStore.Count(projectID)
	totalObs, _ := journalStore.TotalObservations(projectID)

	var artifactCount, entityCount, endpointCount, paramCount, techCount, noteCount int
	db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE project_id = ?`, projectID.String()).Scan(&artifactCount)
	db.QueryRow(`SELECT COUNT(*) FROM entities WHERE project_id = ?`, projectID.String()).Scan(&entityCount)
	db.QueryRow(`SELECT COUNT(*) FROM entities WHERE project_id = ? AND type = 'endpoint'`, projectID.String()).Scan(&endpointCount)
	db.QueryRow(`SELECT COUNT(*) FROM entities WHERE project_id = ? AND type = 'parameter'`, projectID.String()).Scan(&paramCount)
	db.QueryRow(`SELECT COUNT(*) FROM entities WHERE project_id = ? AND type = 'technology'`, projectID.String()).Scan(&techCount)
	db.QueryRow(`SELECT COUNT(*) FROM observations WHERE project_id = ? AND type = 'researcher_note'`, projectID.String()).Scan(&noteCount)

	fmt.Println("SESSION")
	if state != nil && !state.StartedAt.IsZero() {
		fmt.Printf("  Started:       %s\n", state.StartedAt.Format("15:04 Jan 02"))
	}
	fmt.Printf("  Commands:      %d\n", commandCount)
	fmt.Printf("  Artifacts:     %d\n", artifactCount)
	fmt.Printf("  Observations:  %d\n", totalObs)
	fmt.Println()

	// ──── Discovered ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("DISCOVERED")
	fmt.Println()

	// Count entity types.
	entityTypes := map[string]string{
		"domain":    "Domains",
		"subdomain": "Subdomains",
		"ip_address": "IP Addresses",
		"port":      "Ports",
		"service":   "Services",
		"endpoint":  "Endpoints",
		"url":       "URLs",
		"parameter": "Parameters",
		"technology": "Technologies",
		"header":    "Headers",
		"cookie":    "Cookies",
	}

	for entType, displayName := range entityTypes {
		var count int
		db.QueryRow(`SELECT COUNT(*) FROM entities WHERE project_id = ? AND type = ?`,
			projectID.String(), entType).Scan(&count)
		if count > 0 {
			padding := strings.Repeat(" ", 16-len(displayName))
			fmt.Printf("  %s%s %d\n", displayName, padding, count)
		}
	}
	if entityCount == 0 {
		fmt.Println("  No entities discovered yet.")
	}
	fmt.Println()

	// ──── Command History ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("COMMAND HISTORY")
	fmt.Println()

	entries, _ := journalStore.Recent(projectID, 20)
	if len(entries) == 0 {
		fmt.Println("  No commands recorded.")
	} else {
		for _, e := range entries {
			ts := e.IngestedAt.Format("15:04")
			cmd := e.Command
			if cmd == "" {
				cmd = e.Tool
			}
			if len(cmd) > 60 {
				cmd = cmd[:57] + "..."
			}

			if e.ExitCode == 0 {
				fmt.Printf("  %s  ✓ %s", ts, cmd)
			} else {
				fmt.Printf("  %s  ⚠ %s", ts, cmd)
			}
			if e.Observations > 0 {
				fmt.Printf(" (%d obs)", e.Observations)
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
		fmt.Printf("  Overall: %d%%\n", totalPct)
	} else {
		fmt.Println("  No coverage data.")
	}
	fmt.Println()

	// ──── Investigation Gaps ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("INVESTIGATION GAPS")
	fmt.Println()

	if covErr == nil && report != nil {
		hasGaps := false
		for _, c := range report.Categories {
			if c.Score >= 0.8 {
				continue
			}
			hasGaps = true
			name := categoryDisplayName(c.Category)
			pct := int(math.Round(c.Score * 100))

			var marker string
			if c.Score < 0.2 {
				marker = "✗"
			} else if c.Score < 0.5 {
				marker = "◐"
			} else {
				marker = "◑"
			}

			fmt.Printf("  %s %s (%d%%)\n", marker, name, pct)

			suggestions := categorySuggestions(c.Category, c.Score)
			for _, s := range suggestions {
				fmt.Printf("    → %s\n", s)
			}
		}
		if !hasGaps {
			fmt.Println("  ✅ No significant gaps.")
		}
	}
	fmt.Println()

	// ──── Researcher Notes ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("RESEARCHER NOTES")
	fmt.Println()

	if noteCount == 0 {
		fmt.Println("  No notes recorded.")
		fmt.Println("  Use 'note ...' inside 'doge work' or 'doge note ...'")
	} else {
		rows, err := db.Query(`
			SELECT raw_value, observed_at FROM observations
			WHERE project_id = ? AND type = 'researcher_note'
			ORDER BY observed_at DESC LIMIT 15
		`, projectID.String())
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var rawValue, observedAt string
				rows.Scan(&rawValue, &observedAt)
				if rawValue != "" {
					fmt.Printf("  • %s\n", rawValue)
				}
			}
		}
	}
	fmt.Println()

	// ──── Learned Patterns ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("🧠 LEARNED PATTERNS")
	fmt.Println()

	learningMem := learning.NewMemory(db)
	learningMem.EnsureTable()

	patterns, _ := learningMem.AllPatterns()
	if len(patterns) == 0 {
		fmt.Println("  No patterns learned yet.")
	} else {
		for _, p := range patterns {
			if p.Confidence < 0.1 {
				continue
			}
			fmt.Printf("  • %s\n", p.Description)
			fmt.Printf("    Confidence: %.0f%% | Seen: %d times | Boost: +%.0f%%\n",
				p.Confidence*100, p.Occurrences, p.PriorityBoost*100)
		}

		fmt.Println()
		fmt.Printf("  Total patterns: %d | Outcomes: %d | Events: %d\n",
			learningMem.PatternCount(),
			learningMem.OutcomeCount(),
			learningMem.EventCount())
	}
	fmt.Println()

	// ──── Unexplored ────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("UNEXPLORED")
	fmt.Println()

	if covErr == nil && report != nil {
		unexploredCount := 0
		for _, c := range report.Categories {
			if c.Score < 0.2 {
				unexploredCount++
			}
		}
		if unexploredCount > 0 {
			fmt.Printf("  %d investigation categories largely unexplored\n", unexploredCount)
		}

		// Count untested endpoints (endpoints with no corresponding observations).
		var untestedEndpoints int
		db.QueryRow(`
			SELECT COUNT(*) FROM entities e
			WHERE e.project_id = ? AND e.type = 'endpoint'
			AND NOT EXISTS (
				SELECT 1 FROM observations o
				WHERE o.project_id = e.project_id
				AND o.raw_value LIKE '%' || e.value || '%'
				AND o.type != 'endpoint_discovery'
			)
		`, projectID.String()).Scan(&untestedEndpoints)

		if untestedEndpoints > 0 {
			fmt.Printf("  %d endpoints discovered but not investigated\n", untestedEndpoints)
		}
		if endpointCount > 0 {
			fmt.Printf("  %d endpoints total | %d parameters | %d technologies\n",
				endpointCount, paramCount, techCount)
		}
	} else {
		fmt.Println("  No data yet.")
	}
	fmt.Println()

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Generated: %s\n", time.Now().Format("15:04:05 Jan 02 2006"))
	fmt.Println()

	// Suppress unused import warning.
	_ = uuid.Nil

	return nil
}
