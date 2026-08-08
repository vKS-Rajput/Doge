package watcher

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/pkg/events"
	"context"
)

func newTestWatcher(t *testing.T, dir string) (*Watcher, *bus.Bus) {
	t.Helper()

	eventBus := bus.New(bus.Options{
		QueueSize: 64,
		Logger:    logging.NewNop(),
	})
	eventBus.Start()

	w := New(Options{
		Dir:          dir,
		ProjectID:    uuid.New(),
		PollInterval: 50 * time.Millisecond,
		Bus:          eventBus,
		Logger:       logging.NewNop(),
	})

	return w, eventBus
}

func TestWatcher_DetectsNewFile(t *testing.T) {
	dir := t.TempDir()
	w, eventBus := newTestWatcher(t, dir)

	var created atomic.Int32
	eventBus.Subscribe(events.TopicFileCreated, func(ctx context.Context, e events.Event) error {
		created.Add(1)
		return nil
	})

	w.Start()
	defer func() {
		w.Stop()
		eventBus.Drain()
	}()

	// Create a file after watcher started.
	os.WriteFile(filepath.Join(dir, "new_file.json"), []byte(`{"test":true}`), 0644)

	// Wait for detection.
	time.Sleep(200 * time.Millisecond)

	if got := created.Load(); got != 1 {
		t.Errorf("expected 1 file.created event, got %d", got)
	}
}

func TestWatcher_DetectsModifiedFile(t *testing.T) {
	dir := t.TempDir()

	// Create file before watcher starts.
	path := filepath.Join(dir, "existing.json")
	os.WriteFile(path, []byte(`{"v":1}`), 0644)

	w, eventBus := newTestWatcher(t, dir)

	var changed atomic.Int32
	eventBus.Subscribe(events.TopicFileModified, func(ctx context.Context, e events.Event) error {
		changed.Add(1)
		return nil
	})

	w.Start()
	defer func() {
		w.Stop()
		eventBus.Drain()
	}()

	// Wait for initial scan to complete.
	time.Sleep(100 * time.Millisecond)

	// Modify the file.
	time.Sleep(10 * time.Millisecond) // Ensure modtime changes.
	os.WriteFile(path, []byte(`{"v":2,"extra":"data"}`), 0644)

	// Wait for detection.
	time.Sleep(200 * time.Millisecond)

	if got := changed.Load(); got < 1 {
		t.Errorf("expected at least 1 file.changed event, got %d", got)
	}
}

func TestWatcher_DetectsDeletedFile(t *testing.T) {
	dir := t.TempDir()

	// Create file before watcher starts.
	path := filepath.Join(dir, "to_delete.json")
	os.WriteFile(path, []byte(`{}`), 0644)

	w, eventBus := newTestWatcher(t, dir)

	var deleted atomic.Int32
	eventBus.Subscribe(events.TopicFileDeleted, func(ctx context.Context, e events.Event) error {
		deleted.Add(1)
		return nil
	})

	w.Start()
	defer func() {
		w.Stop()
		eventBus.Drain()
	}()

	// Wait for initial scan.
	time.Sleep(100 * time.Millisecond)

	// Delete the file.
	os.Remove(path)

	// Wait for detection.
	time.Sleep(200 * time.Millisecond)

	if got := deleted.Load(); got != 1 {
		t.Errorf("expected 1 file.deleted event, got %d", got)
	}
}

func TestWatcher_IgnoresPatterns(t *testing.T) {
	dir := t.TempDir()

	eventBus := bus.New(bus.Options{QueueSize: 64, Logger: logging.NewNop()})
	eventBus.Start()

	w := New(Options{
		Dir:            dir,
		ProjectID:      uuid.New(),
		PollInterval:   50 * time.Millisecond,
		IgnorePatterns: []string{"*.tmp", "*.swp"},
		Bus:            eventBus,
		Logger:         logging.NewNop(),
	})

	var created atomic.Int32
	eventBus.Subscribe(events.TopicFileCreated, func(ctx context.Context, e events.Event) error {
		created.Add(1)
		return nil
	})

	w.Start()
	defer func() {
		w.Stop()
		eventBus.Drain()
	}()

	// Create ignored files.
	os.WriteFile(filepath.Join(dir, "file.tmp"), []byte("temp"), 0644)
	os.WriteFile(filepath.Join(dir, "file.swp"), []byte("swap"), 0644)
	// Create non-ignored file.
	os.WriteFile(filepath.Join(dir, "file.json"), []byte("json"), 0644)

	time.Sleep(200 * time.Millisecond)

	// Only the .json file should trigger an event.
	if got := created.Load(); got != 1 {
		t.Errorf("expected 1 file.created event (ignored .tmp/.swp), got %d", got)
	}
}

func TestWatcher_DoesNotEmitOnInitialScan(t *testing.T) {
	dir := t.TempDir()

	// Create files before watcher starts.
	os.WriteFile(filepath.Join(dir, "pre_existing.json"), []byte("{}"), 0644)

	w, eventBus := newTestWatcher(t, dir)

	var created atomic.Int32
	eventBus.Subscribe(events.TopicFileCreated, func(ctx context.Context, e events.Event) error {
		created.Add(1)
		return nil
	})

	w.Start()
	defer func() {
		w.Stop()
		eventBus.Drain()
	}()

	// Wait for several poll cycles.
	time.Sleep(200 * time.Millisecond)

	// Pre-existing files should NOT trigger created events.
	if got := created.Load(); got != 0 {
		t.Errorf("expected 0 events for pre-existing files, got %d", got)
	}
}
