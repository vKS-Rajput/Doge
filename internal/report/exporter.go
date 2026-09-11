package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ReportFormat represents an output export format.
type ReportFormat string

const (
	FormatSARIF       ReportFormat = "sarif"
	FormatMarkdown    ReportFormat = "markdown"
	FormatJSON        ReportFormat = "json"
	FormatProofBundle ReportFormat = "proof"
)

// ExportOptions configures report generation and serialization.
type ExportOptions struct {
	Format     ReportFormat
	OutputPath string
	SecretKey  []byte
}

// MultiFormatExporter produces formatted security artifacts across standard formats.
type MultiFormatExporter struct{}

// NewExporter creates a new MultiFormatExporter.
func NewExporter() *MultiFormatExporter {
	return &MultiFormatExporter{}
}

// Export serializes the report and associated proof bundles into the requested format.
func (e *MultiFormatExporter) Export(rep *Report, bundles []*ProofBundle, format ReportFormat) ([]byte, error) {
	switch format {
	case FormatSARIF:
		return ExportSARIF(rep, bundles)
	case FormatMarkdown:
		md := GenerateExecutiveMarkdownReport(rep, bundles)
		return []byte(md), nil
	case FormatJSON:
		payload := map[string]any{
			"report":  rep,
			"proofs":  bundles,
			"version": DogeEngineVersion,
		}
		return json.MarshalIndent(payload, "", "  ")
	case FormatProofBundle:
		return json.MarshalIndent(bundles, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

// ExportToFile writes the formatted report directly to a file on disk.
func (e *MultiFormatExporter) ExportToFile(rep *Report, bundles []*ProofBundle, opts ExportOptions) error {
	data, err := e.Export(rep, bundles, opts.Format)
	if err != nil {
		return err
	}

	if opts.OutputPath != "" {
		dir := filepath.Dir(opts.OutputPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed creating output directory: %w", err)
		}
		if err := os.WriteFile(opts.OutputPath, data, 0644); err != nil {
			return fmt.Errorf("failed writing export file: %w", err)
		}
	}

	return nil
}
