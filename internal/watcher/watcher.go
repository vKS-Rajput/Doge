// Package watcher monitors directories for filesystem changes and emits
// events through the Event Bus.
//
// The File Watcher does exactly three things:
//   - Detects file.created
//   - Detects file.modified
//   - Detects file.deleted
//
// Nothing else. No parsing. No database. No AI. No retries. Only events.
//
// The watcher uses a polling strategy with debouncing rather than OS-level
// file notifications (fsnotify). This is intentional:
//   - Simpler, fewer platform-specific bugs
//   - Works on all platforms including network drives
//   - Debouncing handles tools that write files in multiple steps
//
// For the expected workload (tens of files per session), polling every
// few hundred milliseconds is more than sufficient.
package watcher

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// fileState tracks the last known state of a file.
type fileState struct {
	modTime time.Time
	size    int64
}

// Watcher monitors a directory for file changes.
type Watcher struct {
	dir            string
	projectID      uuid.UUID
	bus            *bus.Bus
	logger         *slog.Logger
	pollInterval   time.Duration
	ignorePatterns []string

	mu    sync.Mutex
	known map[string]fileState // path → last known state

	cancel context.CancelFunc
	done   chan struct{}
}

// Options configures the file watcher.
type Options struct {
	// Dir is the directory to watch (recursively).
	Dir string

	// ProjectID is the project that owns files in this directory.
	ProjectID uuid.UUID

	// PollInterval is the time between directory scans.
	// Default: 300ms.
	PollInterval time.Duration

	// IgnorePatterns are glob patterns for files to skip.
	IgnorePatterns []string

	// Bus is the event bus to publish file events to.
	Bus *bus.Bus

	// Logger for operational messages.
	Logger *slog.Logger
}

// New creates a new file watcher. Call [Start] to begin watching.
func New(opts Options) *Watcher {
	if opts.PollInterval <= 0 {
		opts.PollInterval = 300 * time.Millisecond
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	return &Watcher{
		dir:            opts.Dir,
		projectID:      opts.ProjectID,
		bus:            opts.Bus,
		logger:         opts.Logger,
		pollInterval:   opts.PollInterval,
		ignorePatterns: opts.IgnorePatterns,
		known:          make(map[string]fileState),
		done:           make(chan struct{}),
	}
}

// Start begins watching the directory. Non-blocking.
func (w *Watcher) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel

	// Do an initial scan to populate known files (don't emit events).
	w.initialScan()

	go w.poll(ctx)
	w.logger.Info("file watcher started", "dir", w.dir)
}

// Stop stops the watcher and waits for the polling goroutine to exit.
func (w *Watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	<-w.done
	w.logger.Info("file watcher stopped", "dir", w.dir)
}

// initialScan records the current state of all files without emitting events.
func (w *Watcher) initialScan() {
	w.mu.Lock()
	defer w.mu.Unlock()

	filepath.Walk(w.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if w.shouldIgnore(path) {
			return nil
		}
		w.known[path] = fileState{
			modTime: info.ModTime(),
			size:    info.Size(),
		}
		return nil
	})
}

// poll runs the directory scan loop.
func (w *Watcher) poll(ctx context.Context) {
	defer close(w.done)

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.scan(ctx)
		}
	}
}

// scan performs a single directory scan, detecting changes.
func (w *Watcher) scan(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Track which files we see in this scan.
	seen := make(map[string]bool)

	filepath.Walk(w.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if w.shouldIgnore(path) {
			return nil
		}

		seen[path] = true
		current := fileState{modTime: info.ModTime(), size: info.Size()}

		prev, exists := w.known[path]
		if !exists {
			// New file.
			w.known[path] = current
			w.bus.Publish(ctx, events.FileCreated{
				BaseEvent: events.NewBaseEvent(),
				Path:      path,
				ProjectID: w.projectID,
			})
			w.logger.Debug("file created", "path", path)
		} else if current.modTime != prev.modTime || current.size != prev.size {
			// Modified file.
			w.known[path] = current
			w.bus.Publish(ctx, events.FileChanged{
				BaseEvent: events.NewBaseEvent(),
				Path:      path,
				ProjectID: w.projectID,
			})
			w.logger.Debug("file changed", "path", path)
		}

		return nil
	})

	// Detect deleted files.
	for path := range w.known {
		if !seen[path] {
			delete(w.known, path)
			w.bus.Publish(ctx, events.FileDeleted{
				BaseEvent: events.NewBaseEvent(),
				Path:      path,
				ProjectID: w.projectID,
			})
			w.logger.Debug("file deleted", "path", path)
		}
	}
}

// shouldIgnore returns true if the file path matches any ignore pattern.
func (w *Watcher) shouldIgnore(path string) bool {
	rel, err := filepath.Rel(w.dir, path)
	if err != nil {
		return false
	}
	// Normalize to forward slashes for pattern matching.
	rel = filepath.ToSlash(rel)

	for _, pattern := range w.ignorePatterns {
		// Check against the relative path.
		matched, _ := filepath.Match(pattern, rel)
		if matched {
			return true
		}
		// Also check against just the filename.
		matched, _ = filepath.Match(pattern, filepath.Base(path))
		if matched {
			return true
		}
		// Check if path contains a directory pattern component.
		if strings.Contains(pattern, "/") || strings.Contains(pattern, "**") {
			clean := strings.ReplaceAll(pattern, "**", "*")
			matched, _ = filepath.Match(clean, rel)
			if matched {
				return true
			}
		}
	}
	return false
}
