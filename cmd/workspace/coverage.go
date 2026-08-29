package main

import (
	"fmt"
	"math"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/coverage"
)

// newCoverageCmd creates the 'coverage' command.
func newCoverageCmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show investigation coverage",
		Long: `Show evidence-derived coverage across investigation dimensions.

Every percentage comes from actual evidence:
  No observations about authorization → 0%
  5 endpoints with auth evidence out of 20 → 25%

Examples:
  doge coverage`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			engine := coverage.NewEngine(application.DB.Conn())
			report, err := engine.Analyze(application.DefaultProjectID)
			if err != nil {
				return fmt.Errorf("coverage analysis failed: %w", err)
			}

			fmt.Println()
			fmt.Println("🐕 DOGE Coverage Report")
			fmt.Println("────────────────────────────────────")
			fmt.Println()

			maxNameLen := 0
			for _, c := range report.Categories {
				name := categoryDisplayName(c.Category)
				if len(name) > maxNameLen {
					maxNameLen = len(name)
				}
			}

			for _, c := range report.Categories {
				name := categoryDisplayName(c.Category)
				pct := int(math.Round(c.Score * 100))
				bar := progressBar(c.Score, 20)

				padding := strings.Repeat(" ", maxNameLen-len(name))
				evidenceStr := ""
				if c.Evidence > 0 {
					evidenceStr = fmt.Sprintf("  (%d evidence)", c.Evidence)
				}

				fmt.Printf("  %s%s %s %3d%%%s\n", name, padding, bar, pct, evidenceStr)
			}

			fmt.Println()
			totalPct := int(math.Round(report.TotalScore * 100))
			fmt.Printf("  Overall: %d%%\n", totalPct)
			fmt.Printf("  Observations: %d | Entities: %d\n",
				report.TotalObservations, report.TotalEntities)
			fmt.Println()

			// Show biggest gaps.
			var weakest []coverage.CategoryCoverage
			for _, c := range report.Categories {
				if c.Score < 0.5 {
					weakest = append(weakest, c)
				}
			}
			if len(weakest) > 0 {
				fmt.Println("  ⚠  Low coverage areas:")
				for _, c := range weakest {
					name := categoryDisplayName(c.Category)
					fmt.Printf("     • %s — needs more investigation\n", name)
				}
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	return cmd
}

// newGapsCmd creates the 'gaps' command.
func newGapsCmd() *cobra.Command {
	var wsPath string

	cmd := &cobra.Command{
		Use:   "gaps",
		Short: "Show investigation gaps",
		Long: `Show what's unexplored, partially explored, or needs attention.

DOGE identifies coverage gaps based on the evidence it has:
  • Untested: entity exists but has no investigation evidence
  • Partial: some aspects tested, others unknown
  • Stale: evidence exists but is old
  • Contradictory: conflicting observations

Examples:
  doge gaps`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			engine := coverage.NewEngine(application.DB.Conn())
			report, err := engine.Analyze(application.DefaultProjectID)
			if err != nil {
				return fmt.Errorf("gap analysis failed: %w", err)
			}

			fmt.Println()
			fmt.Println("🐕 DOGE Investigation Gaps")
			fmt.Println("────────────────────────────────────")
			fmt.Println()

			hasGaps := false
			for _, c := range report.Categories {
				if c.Score >= 0.8 {
					continue // well covered
				}
				hasGaps = true

				pct := int(math.Round(c.Score * 100))
				name := categoryDisplayName(c.Category)

				var priority string
				if c.Score < 0.2 {
					priority = "🔴 CRITICAL"
				} else if c.Score < 0.5 {
					priority = "🟡 HIGH"
				} else {
					priority = "🟢 MEDIUM"
				}

				fmt.Printf("  %s  %s (%d%%)\n", priority, name, pct)

				// Generate suggestions based on category.
				suggestions := categorySuggestions(c.Category, c.Score)
				for _, s := range suggestions {
					fmt.Printf("     → %s\n", s)
				}
				fmt.Println()
			}

			if !hasGaps {
				fmt.Println("  ✅ No significant gaps detected.")
				fmt.Println("  All coverage categories are above 80%.")
				fmt.Println()
			} else {
				// Summary.
				var lowCount int
				for _, c := range report.Categories {
					if c.Score < 0.5 {
						lowCount++
					}
				}
				if lowCount > 0 {
					fmt.Printf("  📊 %d categories below 50%% coverage\n", lowCount)
					fmt.Println("  Use 'doge coverage' for the full breakdown.")
					fmt.Println()
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	return cmd
}

func categoryDisplayName(cat coverage.Category) string {
	switch cat {
	case coverage.CategoryDiscovery:
		return "Discovery"
	case coverage.CategoryWebMapping:
		return "Web mapping"
	case coverage.CategoryAuthentication:
		return "Authentication"
	case coverage.CategoryAuthorization:
		return "Authorization"
	case coverage.CategoryAPISurface:
		return "API surface"
	case coverage.CategoryBusinessLogic:
		return "Business logic"
	case coverage.CategoryFileHandling:
		return "File handling"
	case coverage.CategoryTechnology:
		return "Technology"
	default:
		return string(cat)
	}
}

func categorySuggestions(cat coverage.Category, score float64) []string {
	if score >= 0.8 {
		return nil
	}

	switch cat {
	case coverage.CategoryDiscovery:
		if score == 0 {
			return []string{"Run nmap or similar service discovery", "Run subfinder for subdomain enumeration"}
		}
		return []string{"Consider DNS enumeration (dnsx)", "Check for additional ports"}
	case coverage.CategoryWebMapping:
		if score < 0.3 {
			return []string{"Run httpx to probe HTTP services", "Run katana to crawl web surfaces"}
		}
		return []string{"Run ffuf for directory discovery", "Check for hidden endpoints"}
	case coverage.CategoryAuthentication:
		return []string{
			"Note authentication mechanisms: doge note --category auth '...'",
			"Probe login endpoints with different credentials",
		}
	case coverage.CategoryAuthorization:
		return []string{
			"Test access control with different roles",
			"Note authorization boundaries: doge note --category authorization '...'",
			"Compare responses between anonymous/user/admin",
		}
	case coverage.CategoryAPISurface:
		return []string{"Enumerate API parameters", "Check for API documentation endpoints (/swagger, /api-docs)"}
	case coverage.CategoryBusinessLogic:
		return []string{
			"Map application workflows",
			"Note business logic: doge note --category business '...'",
		}
	case coverage.CategoryFileHandling:
		return []string{"Test upload endpoints", "Check file type restrictions"}
	case coverage.CategoryTechnology:
		return []string{"Run technology detection (httpx with tech-detect)", "Note observed technologies"}
	default:
		return nil
	}
}

func progressBar(score float64, width int) string {
	filled := int(math.Round(score * float64(width)))
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}
