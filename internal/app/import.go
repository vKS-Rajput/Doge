package app

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/artifacts"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/internal/observation"
	"github.com/vKS-Rajput/doge/internal/parser"
)

// ImportResult describes the outcome of importing a file.
type ImportResult struct {
	ArtifactIsNew    bool
	ArtifactFileName string
	ParserUsed       string
	Observations     int
	Duplicates       int
	Rejected         int
}

// Import imports a file into the workspace. This is the full pipeline:
//
//	File → Artifact Store → Parser → Observation Validation → Observation Store
//
// This is the entry point for `workspace import <file>`.
func (a *App) Import(ctx context.Context, filePath string, projectID uuid.UUID) (*ImportResult, error) {
	logger := logging.WithOperation(a.Logger, "import")
	logger.Info("importing file", "path", filePath)

	// Step 1: Store the artifact.
	artifactStore := artifacts.NewStore(
		a.artifactsPath(),
		a.DB.Conn(),
		a.Bus,
		logging.WithModule(logger, "artifacts"),
	)

	artResult, err := artifactStore.Import(ctx, filePath, projectID)
	if err != nil {
		return nil, fmt.Errorf("storing artifact: %w", err)
	}

	result := &ImportResult{
		ArtifactIsNew:    artResult.IsNew,
		ArtifactFileName: artResult.Artifact.FileName,
	}

	if !artResult.IsNew {
		logger.Info("artifact already exists (duplicate)")
		return result, nil
	}

	// Step 2: Find a parser.
	registry := a.buildParserRegistry()
	header, _ := readHeader(artResult.Artifact.StoredPath)
	p := registry.FindParser(artResult.Artifact, header)

	if p == nil {
		logger.Info("no parser found for artifact", "file", artResult.Artifact.FileName)
		return result, nil
	}

	result.ParserUsed = p.Name()

	// Step 3: Parse the artifact.
	content, err := artifactStore.ReadContent(artResult.Artifact)
	if err != nil {
		return nil, fmt.Errorf("reading artifact content: %w", err)
	}
	defer content.Close()

	rawObs, err := p.Parse(ctx, artResult.Artifact, content)
	if err != nil {
		return nil, fmt.Errorf("parsing artifact: %w", err)
	}

	// Mark the artifact as parsed.
	if err := artifactStore.MarkParsed(ctx, artResult.Artifact.ID, p.Name()); err != nil {
		logger.Warn("failed to mark artifact as parsed", "error", err)
	}

	if len(rawObs) == 0 {
		logger.Info("parser produced no observations")
		return result, nil
	}

	// Step 4: Validate and store observations.
	obsStore := observation.NewStore(
		a.DB.Conn(),
		a.Bus,
		logging.WithModule(logger, "observation"),
	)

	ingestResult, err := obsStore.IngestBatch(ctx, rawObs, artResult.Artifact.ID, projectID, p.Version())
	if err != nil {
		return nil, fmt.Errorf("ingesting observations: %w", err)
	}

	result.Observations = ingestResult.Created
	result.Duplicates = ingestResult.Duplicates
	result.Rejected = ingestResult.Rejected

	logger.Info("import complete",
		"file", artResult.Artifact.FileName,
		"parser", p.Name(),
		"observations", ingestResult.Created,
		"duplicates", ingestResult.Duplicates,
		"rejected", ingestResult.Rejected,
	)

	return result, nil
}

// buildParserRegistry creates and populates the parser registry.
func (a *App) buildParserRegistry() *parser.Registry {
	registry := parser.NewRegistry(logging.WithModule(a.Logger, "parser"))

	// Register all available parsers.
	// More specific parsers go first (first-match wins).
	registerAllParsers(registry)

	return registry
}

// readHeader reads the first 512 bytes of a file for content detection.
func readHeader(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return header[:n], nil
}
