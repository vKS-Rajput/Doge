package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// newNoteCmd creates the 'note' command for researcher observations.
func newNoteCmd() *cobra.Command {
	var wsPath string
	var targetFlag string
	var category string

	cmd := &cobra.Command{
		Use:   "note <text>",
		Short: "Add a researcher note to the investigation",
		Long: `Record a manual observation as first-class evidence.

Your notes enter the same pipeline as tool output:
  → Observation store → Entity resolution → Correlation → Surface

Examples:
  doge note "login requires email + OTP"
  doge note --target /api/export "id parameter appears sequential"
  doge note --category auth "test account A owns object 123"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			noteText := strings.Join(args, " ")

			if wsPath == "" {
				wsPath = "."
			}

			application, err := app.Open(cmd.Context(), wsPath)
			if err != nil {
				return fmt.Errorf("failed to open workspace: %w", err)
			}
			defer application.Shutdown()

			// Create a researcher note observation.
			data := map[string]any{
				"note":     noteText,
				"author":   "researcher",
				"category": category,
			}
			if targetFlag != "" {
				data["target"] = targetFlag
			}

			// Compute checksum for deduplication.
			dataBytes, _ := json.Marshal(data)
			hash := sha256.Sum256(dataBytes)
			checksum := hex.EncodeToString(hash[:])

			obsID := uuid.New()
			now := time.Now()

			// Insert directly into observations table.
			absPath, _ := filepath.Abs(wsPath)
			dbPath := filepath.Join(absPath, ".doge", "workspace.db")
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				return fmt.Errorf("failed to open database: %w", err)
			}
			defer db.Close()

			dataJSON, _ := json.Marshal(data)

			_, err = db.Exec(`
				INSERT OR IGNORE INTO observations
					(id, type, artifact_id, source_tool, project_id, data, raw_value,
					 checksum, observed_at, ingested_at, parser_version)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`,
				obsID.String(),
				string(domain.ObservationResearcherNote),
				uuid.Nil.String(), // no artifact for manual notes
				"researcher",
				application.DefaultProjectID.String(),
				string(dataJSON),
				noteText,
				checksum,
				now.Format(time.RFC3339),
				now.Format(time.RFC3339),
				"manual",
			)
			if err != nil {
				return fmt.Errorf("failed to store note: %w", err)
			}

			fmt.Println()
			fmt.Println("🐕 DOGE — Note recorded")
			fmt.Println()
			fmt.Printf("  📝 %s\n", noteText)
			if targetFlag != "" {
				fmt.Printf("  Target:   %s\n", targetFlag)
			}
			if category != "" {
				fmt.Printf("  Category: %s\n", category)
			}
			fmt.Printf("  ID:       %s\n", obsID.String()[:8])
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVar(&wsPath, "path", "", "workspace directory")
	cmd.Flags().StringVar(&targetFlag, "target", "", "specific target (endpoint, host, etc.)")
	cmd.Flags().StringVar(&category, "category", "", "note category (auth, api, business, etc.)")

	return cmd
}
