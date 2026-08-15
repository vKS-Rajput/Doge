package ingest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/app"
)

// IngestJob represents one piece of tool output to ingest.
type IngestJob struct {
	// ID uniquely identifies this job.
	ID uuid.UUID

	// FilePath is the path to the raw output file.
	FilePath string

	// ToolHint is set when the executor knows which tool produced the output.
	// Empty when the watcher delivers an unknown file.
	ToolHint string

	// ProjectID is the project to ingest into.
	ProjectID uuid.UUID

	// SchedulerJobID links back to the scheduler job that produced this output.
	SchedulerJobID *uuid.UUID
}

// IngestResult tracks what happened during ingestion.
type IngestResult struct {
	JobID        uuid.UUID
	Tool         string
	Observations int
	Duplicates   int
	ParseErrors  int
	Error        error
}

// Dispatcher is a bounded ingestion queue that processes tool output
// through the existing import pipeline.
//
// Architecture:
//
//	Executor → Dispatcher.Submit() → workers → app.Import → observations
//	Watcher  → Dispatcher.Submit() → workers → app.Import → observations
//
// Features:
//   - Bounded queue with backpressure
//   - Configurable worker count
//   - Content-hash deduplication
//   - Parser failure preserves raw artifact
//   - Unknown tool output preserved and reported
type Dispatcher struct {
	application *app.App
	logger      *slog.Logger

	queue   chan IngestJob
	workers int

	// Deduplication: content hash → already processed.
	seen   map[string]bool
	seenMu sync.Mutex

	// Results tracking.
	results   []IngestResult
	resultsMu sync.Mutex

	// Lifecycle.
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// DispatcherConfig configures the ingestion dispatcher.
type DispatcherConfig struct {
	Application *app.App
	Logger      *slog.Logger
	QueueSize   int
	Workers     int
}

// NewDispatcher creates a new ingestion dispatcher.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 100
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Dispatcher{
		application: cfg.Application,
		logger:      cfg.Logger,
		queue:       make(chan IngestJob, cfg.QueueSize),
		workers:     cfg.Workers,
		seen:        make(map[string]bool),
	}
}

// Start begins the ingestion workers.
func (d *Dispatcher) Start(ctx context.Context) {
	ctx, d.cancel = context.WithCancel(ctx)

	for i := 0; i < d.workers; i++ {
		d.wg.Add(1)
		go d.worker(ctx, i)
	}

	d.logger.Info("ingestion dispatcher started",
		"workers", d.workers,
		"queue_size", cap(d.queue))
}

// Stop gracefully stops the dispatcher.
func (d *Dispatcher) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
	d.logger.Info("ingestion dispatcher stopped")
}

// Submit adds a file to the ingestion queue.
// Returns error if the queue is full (backpressure) or content is a duplicate.
func (d *Dispatcher) Submit(job IngestJob) error {
	// Content-hash deduplication.
	hash, err := d.contentHash(job.FilePath)
	if err != nil {
		// Can't read the file — still submit, let worker handle the error.
		d.logger.Warn("cannot hash file for dedup", "path", job.FilePath, "error", err)
	} else {
		d.seenMu.Lock()
		if d.seen[hash] {
			d.seenMu.Unlock()
			d.logger.Debug("duplicate content skipped", "path", job.FilePath, "hash", hash[:16])
			return fmt.Errorf("duplicate content: %s", filepath.Base(job.FilePath))
		}
		d.seen[hash] = true
		d.seenMu.Unlock()
	}

	// Submit with backpressure.
	select {
	case d.queue <- job:
		d.logger.Info("ingestion job submitted",
			"path", filepath.Base(job.FilePath),
			"tool_hint", job.ToolHint)
		return nil
	default:
		return fmt.Errorf("ingestion queue full (%d/%d)", len(d.queue), cap(d.queue))
	}
}

// Results returns all ingestion results.
func (d *Dispatcher) Results() []IngestResult {
	d.resultsMu.Lock()
	defer d.resultsMu.Unlock()
	out := make([]IngestResult, len(d.results))
	copy(out, d.results)
	return out
}

// QueueLen returns the current queue length.
func (d *Dispatcher) QueueLen() int {
	return len(d.queue)
}

// worker processes ingestion jobs.
func (d *Dispatcher) worker(ctx context.Context, id int) {
	defer d.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-d.queue:
			if !ok {
				return
			}
			d.processJob(ctx, job, id)
		}
	}
}

// processJob runs the import pipeline for a single file.
func (d *Dispatcher) processJob(ctx context.Context, job IngestJob, workerID int) {
	result := IngestResult{JobID: job.ID}

	d.logger.Info("processing ingestion job",
		"worker", workerID,
		"path", filepath.Base(job.FilePath),
		"tool_hint", job.ToolHint)

	// Check file exists.
	if _, err := os.Stat(job.FilePath); err != nil {
		result.Error = fmt.Errorf("file not found: %w", err)
		d.recordResult(result)
		return
	}

	// Detect tool if no hint provided.
	if job.ToolHint == "" {
		content, err := os.ReadFile(job.FilePath)
		if err == nil {
			detected := DetectTool(content, filepath.Base(job.FilePath))
			if detected != nil {
				job.ToolHint = detected.Tool
				d.logger.Info("tool detected",
					"tool", detected.Tool,
					"confidence", detected.Confidence,
					"reason", detected.Reason)
			} else {
				d.logger.Info("unknown tool output — preserving as artifact",
					"path", filepath.Base(job.FilePath))
			}
		}
	}

	result.Tool = job.ToolHint

	// Import through the existing pipeline.
	// app.Import handles: artifact store → parser → observations → events.
	importResult, err := d.application.Import(ctx, job.FilePath, job.ProjectID)
	if err != nil {
		result.Error = err
		result.ParseErrors = 1
		d.logger.Error("ingestion import failed",
			"path", filepath.Base(job.FilePath),
			"error", err)
		// Raw artifact is ALREADY preserved by app.Import's artifact step.
		// Parser failure does not lose evidence.
	} else if importResult != nil {
		result.Observations = importResult.Observations
		result.Duplicates = importResult.Duplicates
		if importResult.ParserUsed != "" {
			result.Tool = importResult.ParserUsed
		}
		d.logger.Info("ingestion complete",
			"path", filepath.Base(job.FilePath),
			"parser", importResult.ParserUsed,
			"observations", importResult.Observations,
			"duplicates", importResult.Duplicates)
	}

	d.recordResult(result)
}

// recordResult stores a result for later inspection.
func (d *Dispatcher) recordResult(result IngestResult) {
	d.resultsMu.Lock()
	d.results = append(d.results, result)
	d.resultsMu.Unlock()
}

// contentHash computes a SHA256 hash of a file for deduplication.
func (d *Dispatcher) contentHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h), nil
}
