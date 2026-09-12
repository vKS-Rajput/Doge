package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/db"
)

type findingEntry struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

func newFindingsCmd() *cobra.Command {
	var (
		workspaceDir string
		provenOnly   bool
		jsonOutput   bool
		severity     string
	)

	cmd := &cobra.Command{
		Use:     "findings",
		Aliases: []string{"finding", "vulns"},
		Short:   "List candidate, validated, and proven security findings",
		Long: `DOGE Findings Registry — Query all discovered security findings across their
epistemic lifecycle: Candidate Finding → Validated Finding → Proven Finding.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			absPath, _ := filepath.Abs(workspaceDir)
			dbPath := filepath.Join(absPath, ".doge", "workspace.db")

			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				fmt.Println("🐕 DOGE — No findings database found in workspace.")
				fmt.Println("  Run: doge hunt <target> to discover and prove findings.")
				return nil
			}

			dbConn, err := db.Open(dbPath, db.Options{WALMode: true})
			if err != nil {
				return fmt.Errorf("opening workspace database: %w", err)
			}
			defer dbConn.Close()

			query := "SELECT id, title, description, severity, status, created_at FROM findings WHERE 1=1"
			var queryArgs []any
			if severity != "" {
				query += " AND severity = ?"
				queryArgs = append(queryArgs, severity)
			}
			if provenOnly {
				query += " AND (status = 'confirmed' OR status = 'reported')"
			}
			query += " ORDER BY created_at DESC"

			rows, err := dbConn.Conn().QueryContext(cmd.Context(), query, queryArgs...)
			if err != nil {
				// Table might be empty or uninitialized
				fmt.Println("🐕 DOGE Verified Findings Registry (0 findings)")
				return nil
			}
			defer rows.Close()

			var findings []findingEntry
			for rows.Next() {
				var f findingEntry
				if err := rows.Scan(&f.ID, &f.Title, &f.Description, &f.Severity, &f.Status, &f.CreatedAt); err == nil {
					findings = append(findings, f)
				}
			}

			if jsonOutput {
				data, _ := json.MarshalIndent(findings, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Println()
			fmt.Printf("🐕 DOGE Verified Findings Registry (%d findings)\n", len(findings))
			fmt.Println("══════════════════════════════════════════════════════════════════")

			if len(findings) == 0 {
				fmt.Println("No findings match the specified criteria.")
				return nil
			}

			for i, f := range findings {
				statusIcon := "🔍 CANDIDATE"
				if f.Status == "confirmed" || f.Status == "reported" {
					statusIcon = "🛡️ PROVEN"
				}

				fmt.Printf("[%d] %s [%s] %s\n", i+1, statusIcon, f.Severity, f.Title)
				fmt.Printf("    ID:          %s\n", f.ID)
				fmt.Printf("    Status:      %s\n", f.Status)
				fmt.Printf("    Discovered:  %s\n", f.CreatedAt)
				fmt.Printf("    Description: %s\n", f.Description)
				fmt.Println("──────────────────────────────────────────────────────────────────")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&workspaceDir, "workspace", "w", ".", "Path to DOGE workspace directory")
	cmd.Flags().BoolVarP(&provenOnly, "proven", "p", false, "Display only proven/confirmed findings")
	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output findings in raw JSON format")
	cmd.Flags().StringVarP(&severity, "severity", "s", "", "Filter by severity (critical, high, medium, low, info)")

	return cmd
}
