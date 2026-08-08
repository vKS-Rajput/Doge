// Package watch provides the live research mode orchestrator.
//
// The Watch Orchestrator connects the File Watcher to the full
// import pipeline and presents semantic change summaries.
//
// Architecture:
//
//	File Watcher → Stability Check → Import → Event Bus → Aggregator → Display
//
// Key safety rules:
//   - Watched content is always UNTRUSTED DATA, never instructions
//   - One bad file cannot kill the watch loop (fault-isolated)
//   - Deleted source files never erase historical evidence
//   - AI trigger only suggests, never auto-invokes
//   - .doge/ is always ignored (no feedback loops)
package watch

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/watcher"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Orchestrator coordinates the live watch pipeline.
type Orchestrator struct {
	app        *app.App
	watcher    *watcher.Watcher
	aggregator *Aggregator
	display    *Display
	trigger    *TriggerPolicy
	logger     *slog.Logger

	// stabilityWindow is how long a file must be unchanged
	// before we consider it stable for processing.
	stabilityWindow time.Duration

	// processMu serializes state-changing pipeline operations.
	// This prevents concurrent imports from creating race conditions
	// in snapshots/diffs.
	processMu sync.Mutex

	done chan struct{}
}

// OrchestratorOptions configures the watch orchestrator.
type OrchestratorOptions struct {
	// WatchPaths are directories to watch (relative to workspace root).
	// Default: ["scans"]
	WatchPaths []string

	// IgnorePatterns are glob patterns to skip.
	// .doge/ is ALWAYS ignored regardless of this setting.
	IgnorePatterns []string

	// StabilityWindow is how long a file must be unchanged before processing.
	// Default: 500ms.
	StabilityWindow time.Duration

	// AggregationWindow is how long to batch rapid events.
	// Default: 500ms.
	AggregationWindow time.Duration

	// Quiet suppresses low-priority output.
	Quiet bool
}

// NewOrchestrator creates a new watch orchestrator.
func NewOrchestrator(application *app.App, opts OrchestratorOptions, logger *slog.Logger) *Orchestrator {
	if len(opts.WatchPaths) == 0 {
		opts.WatchPaths = []string{"scans"}
	}
	if opts.StabilityWindow <= 0 {
		opts.StabilityWindow = 500 * time.Millisecond
	}
	if opts.AggregationWindow <= 0 {
		opts.AggregationWindow = 500 * time.Millisecond
	}

	// Always ignore .doge/ to prevent feedback loops.
	opts.IgnorePatterns = append(opts.IgnorePatterns, ".doge/*", ".doge/**", "*.db", "*.db-wal", "*.db-shm")

	display := NewDisplay(opts.Quiet)
	trigger := NewTriggerPolicy(logger)
	aggregator := NewAggregator(opts.AggregationWindow, display, trigger)

	return &Orchestrator{
		app:             application,
		aggregator:      aggregator,
		display:         display,
		trigger:         trigger,
		logger:          logger,
		stabilityWindow: opts.StabilityWindow,
		done:            make(chan struct{}),
	}
}

// Start begins watching and processing. Blocks until ctx is cancelled.
func (o *Orchestrator) Start(ctx context.Context) error {
	// Resolve watch directory.
	watchDir := o.app.Workspace.RootPath
	if _, err := os.Stat(watchDir); err != nil {
		return fmt.Errorf("watch directory does not exist: %s", watchDir)
	}

	// Ensure scans/ directory exists.
	scansDir := filepath.Join(watchDir, "scans")
	os.MkdirAll(scansDir, 0755)

	// Create file watcher.
	o.watcher = watcher.New(watcher.Options{
		Dir:            watchDir,
		ProjectID:      o.app.DefaultProjectID,
		PollInterval:   300 * time.Millisecond,
		IgnorePatterns: []string{".doge/*", "*.db", "*.db-wal", "*.db-shm", "config.toml"},
		Bus:            o.app.Bus,
		Logger:         o.logger,
	})

	// Subscribe to file events.
	o.app.Bus.Subscribe(events.TopicFileCreated, o.onFileEvent)
	o.app.Bus.Subscribe(events.TopicFileModified, o.onFileEvent)
	o.app.Bus.Subscribe(events.TopicFileDeleted, o.onFileDeleted)

	// Start aggregator.
	o.aggregator.Start(ctx)

	// Start watcher.
	o.watcher.Start()
	o.display.Banner(watchDir)

	// Wait for cancellation.
	<-ctx.Done()

	// Graceful shutdown.
	o.display.Info("Shutting down...")
	o.watcher.Stop()
	o.aggregator.Flush()
	close(o.done)

	return nil
}

// onFileEvent handles file.created and file.modified events.
// Each file is processed in its own error boundary.
func (o *Orchestrator) onFileEvent(ctx context.Context, event events.Event) error {
	var path string
	var projectID uuid.UUID

	switch e := event.(type) {
	case events.FileCreated:
		path = e.Path
		projectID = e.ProjectID
	case events.FileModified:
		path = e.Path
		projectID = e.ProjectID
	default:
		return nil
	}

	// Skip .doge/ files (double safety).
	if isDogeInternal(path) {
		return nil
	}

	// Wait for file stability before processing.
	go o.processFileWithStability(ctx, path, projectID)
	return nil
}

// onFileDeleted records the filesystem change but preserves evidence.
// Historical evidence is NEVER erased by file deletion.
func (o *Orchestrator) onFileDeleted(ctx context.Context, event events.Event) error {
	e, ok := event.(events.FileDeleted)
	if !ok {
		return nil
	}
	if isDogeInternal(e.Path) {
		return nil
	}

	o.display.FileDeleted(e.Path)
	o.logger.Info("file deleted (evidence preserved)", "path", e.Path)
	return nil
}

// processFileWithStability waits for the file to be stable, then processes it.
// This prevents importing partially-written files.
func (o *Orchestrator) processFileWithStability(ctx context.Context, path string, projectID uuid.UUID) {
	// Stability check: wait until file size/mtime hasn't changed.
	stable := false
	var lastSize int64
	var lastMod time.Time

	for i := 0; i < 10; i++ { // Max 5 seconds of waiting.
		select {
		case <-ctx.Done():
			return
		case <-time.After(o.stabilityWindow):
		}

		info, err := os.Stat(path)
		if err != nil {
			// File disappeared during stability check.
			return
		}

		if info.Size() == lastSize && info.ModTime().Equal(lastMod) && lastSize > 0 {
			stable = true
			break
		}
		lastSize = info.Size()
		lastMod = info.ModTime()
	}

	if !stable {
		o.display.Warn(fmt.Sprintf("File not stable after 5s, processing anyway: %s", filepath.Base(path)))
	}

	// Process with error boundary and serialized access.
	o.processFile(ctx, path, projectID)
}

// processFile runs the import pipeline with full fault isolation.
// One bad file cannot kill the watch loop.
func (o *Orchestrator) processFile(ctx context.Context, path string, projectID uuid.UUID) {
	o.processMu.Lock()
	defer o.processMu.Unlock()

	start := time.Now()
	baseName := filepath.Base(path)

	// Fault-isolated processing with timeout.
	processCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	o.display.FileDetected(baseName)

	result, err := o.safeImport(processCtx, path, projectID)
	if err != nil {
		o.display.ImportFailed(baseName, err)
		o.logger.Error("import failed", "path", path, "error", err)
		return
	}

	// Build change event for aggregator.
	change := ChangeEvent{
		FilePath:     path,
		FileName:     baseName,
		Observations: result.Observations,
		Duplicates:   result.Duplicates,
		ParserUsed:   result.ParserUsed,
		Duration:     time.Since(start),
		Timestamp:    time.Now(),
	}

	if !result.ArtifactIsNew {
		change.IsDuplicate = true
	}

	o.aggregator.Add(change)
}

// safeImport wraps app.Import with panic recovery.
func (o *Orchestrator) safeImport(ctx context.Context, path string, projectID uuid.UUID) (result *app.ImportResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during import: %v", r)
		}
	}()

	return o.app.Import(ctx, path, projectID)
}

// isDogeInternal returns true for paths inside .doge/.
func isDogeInternal(path string) bool {
	abs, _ := filepath.Abs(path)
	return filepath.Base(filepath.Dir(abs)) == ".doge" ||
		containsPathComponent(abs, ".doge")
}

func containsPathComponent(path, component string) bool {
	dir := path
	for {
		base := filepath.Base(dir)
		if base == component {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}
