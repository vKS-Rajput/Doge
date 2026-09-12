package researcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/whitebox"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// SourceResearcher correlates static code analysis (AST parsing and taint analysis)
// with runtime observations and endpoints in the shared world model.
type SourceResearcher struct {
	sourceDir   string
	astParser   *whitebox.ASTParser
	taintTracer *whitebox.TaintTracer
}

// NewSourceResearcher creates a new source researcher.
func NewSourceResearcher(sourceDir string) *SourceResearcher {
	return &SourceResearcher{
		sourceDir:   sourceDir,
		astParser:   whitebox.NewASTParser(),
		taintTracer: whitebox.NewTaintTracer(),
	}
}

// Type returns domain.ResearcherSource.
func (r *SourceResearcher) Type() domain.ResearcherType {
	return domain.ResearcherSource
}

// Execute parses source files in the configured directory and matches routes/taint paths against runtime endpoints.
func (r *SourceResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherSource,
		Status:         domain.MissionActive,
	}

	if r.sourceDir == "" {
		result.Status = domain.MissionCompleted
		result.Summary = "Source Research: No source directory provided; skipped."
		return result, nil
	}

	filesParsed := 0
	taintPathsFound := 0

	_ = filepath.Walk(r.sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".go" && ext != ".js" && ext != ".ts" && ext != ".py" && ext != ".java" {
			return nil
		}

		routes, sources, err := r.astParser.ParseFile(path)
		if err == nil && (len(routes) > 0 || len(sources) > 0) {
			filesParsed++
			content, _ := os.ReadFile(path)
			paths := r.taintTracer.TraceTaint(string(content), path, sources)

			for _, route := range routes {
				fullRoute := strings.TrimRight(brief.TargetBaseURL, "/") + route.Path
				result.Endpoints = append(result.Endpoints, fullRoute)
				result.Observations = append(result.Observations, domain.MissionObservation{
					Type:        "source_route_discovered",
					Description: fmt.Sprintf("Source Route Discovered: %s %s in %s:%d", route.Method, route.Path, path, route.LineNumber),
					Endpoint:    fullRoute,
					Method:      route.Method,
					Details:     map[string]any{"source_file": path, "line": route.LineNumber},
					ObservedAt:  time.Now().UTC(),
				})
			}

			for _, tp := range paths {
				taintPathsFound++
				cand := domain.CandidateVulnerability{
					ID:          uuid.New(),
					Type:        fmt.Sprintf("SOURCE_TAINT_SINK_%s", tp.Sink.Type),
					Title:       fmt.Sprintf("Static Taint Flow: %s -> %s in %s:%d", tp.SourceParam, tp.Sink.Type, filepath.Base(path), tp.SourceLine),
					Description: fmt.Sprintf("Untrusted input '%s' flows directly into sink '%s' without sanitization in %s.", tp.SourceParam, tp.Sink.Type, path),
					Severity:    string(domain.SeverityHigh),
					Endpoint:    brief.TargetBaseURL,
					DiscoveredAt: time.Now().UTC(),
				}
				result.CandidateFindings = append(result.CandidateFindings, cand)
			}
		}
		return nil
	})

	result.Duration = time.Since(start)
	result.Status = domain.MissionCompleted
	result.Summary = fmt.Sprintf("Source Code Research: %d source files analyzed, %d routes discovered, %d unmitigated taint paths identified",
		filesParsed, len(result.Endpoints), taintPathsFound)

	return result, nil
}
