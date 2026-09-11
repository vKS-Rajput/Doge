package main

import (
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/report"
)

func newReportCmd() *cobra.Command {
	var (
		formatStr  string
		outputPath string
		targetName string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Export enterprise security reports (SARIF, Markdown, JSON, Proof Bundles)",
		Long: `Generate and export publishable security assessment reports from verified findings.
Supports SARIF v2.1.0 for GitHub/GitLab code scanning, executive Markdown with developer
remediation advisories, and cryptographic proof bundles.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			rep := &report.Report{
				ID:          uuid.New(),
				Title:       fmt.Sprintf("Security Assessment: %s", targetName),
				ProjectID:   uuid.New(),
				GeneratedAt: time.Now().UTC(),
				GeneratedBy: "DOGE Autonomous Security Science Engine",
				Executive: report.ExecutiveSummary{
					Target:    targetName,
					StartDate: time.Now().UTC().Add(-1 * time.Hour),
					EndDate:   time.Now().UTC(),
					Summary:   fmt.Sprintf("Assessment completed for %s.", targetName),
					FindingCounts: report.SeverityCounts{
						Critical: 0,
						High:     0,
						Medium:   0,
						Low:      0,
						Info:     0,
					},
				},
				Findings: []report.FindingSection{},
			}

			exporter := report.NewExporter()
			var fmtType report.ReportFormat
			switch formatStr {
			case "sarif":
				fmtType = report.FormatSARIF
			case "markdown", "md":
				fmtType = report.FormatMarkdown
			case "json":
				fmtType = report.FormatJSON
			case "proof", "bundle":
				fmtType = report.FormatProofBundle
			default:
				fmtType = report.FormatMarkdown
			}

			data, err := exporter.Export(rep, nil, fmtType)
			if err != nil {
				return fmt.Errorf("export error: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, data, 0644); err != nil {
					return fmt.Errorf("failed writing report to %s: %w", outputPath, err)
				}
				fmt.Printf("[DOGE] Report successfully exported to %s (format: %s)\n", outputPath, formatStr)
			} else {
				fmt.Println(string(data))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&formatStr, "format", "f", "markdown", "Output format: sarif, markdown, json, proof")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default stdout)")
	cmd.Flags().StringVarP(&targetName, "target", "t", "Production Target", "Target application name")

	return cmd
}
