// Package app provides the Application Service layer.
//
// Application Services are the orchestration layer between the CLI
// (or any other interface) and the domain modules. They coordinate
// multiple modules to fulfill a use case, without containing domain
// logic themselves.
//
// The key principle: the CLI parses flags, validates input, and
// delegates to an Application Service. The Application Service
// orchestrates modules via the Event Bus and direct calls.
// Domain modules contain the actual business logic.
//
//	CLI (thin)
//	    ↓
//	Application Service (orchestration)
//	    ↓
//	Domain Modules + Event Bus
//
// The App struct is the central application instance. It owns all
// infrastructure (database, event bus, cache, logger) and exposes
// service methods grouped by use case.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/internal/cache"
	"github.com/vKS-Rajput/doge/internal/config"
	"github.com/vKS-Rajput/doge/internal/db"
	"github.com/vKS-Rajput/doge/internal/entity"
	"github.com/vKS-Rajput/doge/internal/insight"
	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/internal/task"
	"github.com/vKS-Rajput/doge/internal/timeline"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// App is the central application instance. It owns all infrastructure
// and coordinates modules via application services.
//
// Lifecycle:
//  1. Create via [Init] (new workspace) or [Open] (existing workspace)
//  2. Use service methods (Import, Ask, Timeline, etc.)
//  3. Call [Shutdown] to drain events and close the database
type App struct {
	Workspace        domain.Workspace
	Config           config.Config
	Logger           *slog.Logger
	DB               *db.DB
	Bus              *bus.Bus
	Cache            *cache.Cache
	DefaultProjectID uuid.UUID
}

// Init creates a new workspace at the given path. It creates the
// directory structure, default configuration, database, and runs
// initial migrations.
//
// This is the entry point for `workspace init <name>`.
func Init(ctx context.Context, rootPath string, name string) (*App, error) {
	// Resolve absolute path.
	absPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("resolving workspace path: %w", err)
	}

	// Create workspace directory structure.
	dirs := []string{
		absPath,
		filepath.Join(absPath, "projects"),
		filepath.Join(absPath, ".doge"),
		filepath.Join(absPath, ".doge", "artifacts"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	// Write default configuration.
	defaultCfg := config.DefaultConfig()
	defaultCfg.Workspace.Name = name

	cfgPath := filepath.Join(absPath, "workspace.toml")
	if err := writeDefaultConfig(cfgPath, name); err != nil {
		return nil, fmt.Errorf("writing default config: %w", err)
	}

	// Load the config we just wrote (validates it).
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Initialize logger.
	logger := logging.New(logging.Config{
		Level:           cfg.Logging.Level,
		Format:          cfg.Logging.Format,
		RedactSensitive: cfg.Logging.RedactSensitive,
	}, os.Stderr)
	logger = logging.WithWorkspace(logger, name)

	logger.Info("initializing workspace",
		"path", absPath,
		"name", name,
	)

	// Initialize database.
	dbPath := filepath.Join(absPath, ".doge", "workspace.db")
	database, err := db.Open(dbPath, db.Options{
		WALMode:       cfg.Database.WALMode,
		BusyTimeoutMs: cfg.Database.BusyTimeoutMs,
		Logger:        logging.WithModule(logger, "db"),
	})
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Run migrations.
	if err := database.Migrate(); err != nil {
		database.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	// Initialize event bus.
	eventBus := bus.New(bus.Options{
		QueueSize: 256,
		Logger:    logging.WithModule(logger, "bus"),
	})
	eventBus.Start()

	// Initialize cache.
	c := cache.New(cache.Options{
		MaxEntries: cfg.Cache.MaxEntries,
		DefaultTTL: time.Duration(cfg.Cache.TTLMinutes) * time.Minute,
	})

	workspace := domain.Workspace{
		ID:        uuid.New(),
		Name:      name,
		RootPath:  absPath,
		CreatedAt: time.Now().UTC(),
	}

	// Create default project.
	defaultProjectID := uuid.New()
	now := time.Now().UTC()
	_, err = database.Conn().Exec(
		`INSERT INTO projects (id, workspace_id, slug, name, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'active', ?, ?)`,
		defaultProjectID.String(), workspace.ID.String(), "default", name, now.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("creating default project: %w", err)
	}

	app := &App{
		Workspace:        workspace,
		Config:           cfg,
		Logger:           logger,
		DB:               database,
		Bus:              eventBus,
		Cache:            c,
		DefaultProjectID: defaultProjectID,
	}

	// Start the entity materializer.
	app.startMaterializer()

	logger.Info("workspace initialized",
		"workspace_id", workspace.ID.String(),
		"default_project_id", defaultProjectID.String(),
	)

	return app, nil
}

// Open loads an existing workspace from the given path.
//
// This is the entry point for `workspace open <path>`.
func Open(ctx context.Context, rootPath string) (*App, error) {
	absPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("resolving workspace path: %w", err)
	}

	// Verify the workspace exists.
	cfgPath := filepath.Join(absPath, "workspace.toml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("not a workspace: %s (workspace.toml not found)", absPath)
	}

	// Load configuration.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Initialize logger.
	logger := logging.New(logging.Config{
		Level:           cfg.Logging.Level,
		Format:          cfg.Logging.Format,
		RedactSensitive: cfg.Logging.RedactSensitive,
	}, os.Stderr)
	logger = logging.WithWorkspace(logger, cfg.Workspace.Name)

	logger.Info("opening workspace",
		"path", absPath,
		"name", cfg.Workspace.Name,
	)

	// Open database.
	dbPath := filepath.Join(absPath, ".doge", "workspace.db")
	database, err := db.Open(dbPath, db.Options{
		WALMode:       cfg.Database.WALMode,
		BusyTimeoutMs: cfg.Database.BusyTimeoutMs,
		Logger:        logging.WithModule(logger, "db"),
	})
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Run any pending migrations.
	if err := database.Migrate(); err != nil {
		database.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	// Initialize event bus.
	eventBus := bus.New(bus.Options{
		QueueSize: 256,
		Logger:    logging.WithModule(logger, "bus"),
	})
	eventBus.Start()

	// Initialize cache.
	c := cache.New(cache.Options{
		MaxEntries: cfg.Cache.MaxEntries,
		DefaultTTL: time.Duration(cfg.Cache.TTLMinutes) * time.Minute,
	})

	workspace := domain.Workspace{
		ID:        uuid.New(), // TODO: persist workspace ID in DB.
		Name:      cfg.Workspace.Name,
		RootPath:  absPath,
		CreatedAt: time.Now().UTC(), // TODO: load from DB.
	}

	// Load default project.
	var defaultProjectID string
	err = database.Conn().QueryRow(
		`SELECT id FROM projects WHERE slug = 'default' LIMIT 1`).Scan(&defaultProjectID)
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("loading default project: %w", err)
	}

	app := &App{
		Workspace:        workspace,
		Config:           cfg,
		Logger:           logger,
		DB:               database,
		Bus:              eventBus,
		Cache:            c,
		DefaultProjectID: uuid.MustParse(defaultProjectID),
	}

	// Start the entity materializer.
	app.startMaterializer()

	logger.Info("workspace opened")
	return app, nil
}

// startSubscribers initializes and subscribes all event-driven
// components. This connects:
//   - observation.batch → Materializer → entities + relationships
//   - entity.created → Insight Engine → insights
//   - insight.detected → Task Engine → tasks
//   - all events → Timeline
func (a *App) startMaterializer() {
	// Knowledge Graph materialization.
	entityStore := entity.NewStore(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "entity"))
	materializer := entity.NewMaterializer(entityStore, a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "materializer"))
	materializer.Subscribe()

	// Timeline — records all significant events.
	tl := timeline.New(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "timeline"))
	tl.Subscribe()

	// Insight Engine — deterministic rule-based pattern detection.
	insightEngine := insight.NewEngine(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "insight"))
	insightEngine.Subscribe()

	// Task Engine — generates actionable tasks from insights.
	taskEngine := task.NewEngine(a.DB.Conn(), a.Bus, logging.WithModule(a.Logger, "task"))
	taskEngine.Subscribe()
}

// Shutdown gracefully stops the application. Drains the event bus,
// flushes the database, and releases all resources.
//
// Must be called before the process exits.
func (a *App) Shutdown() error {
	a.Logger.Info("shutting down workspace")

	// Drain the event bus first — let all pending events finish.
	a.Bus.Drain()

	// Close the database (checkpoints WAL).
	if err := a.DB.Close(); err != nil {
		a.Logger.Error("database close error", "error", err)
		return fmt.Errorf("closing database: %w", err)
	}

	a.Logger.Info("workspace shut down cleanly")
	return nil
}

// Status returns a summary of the workspace state.
func (a *App) Status(ctx context.Context) (*WorkspaceStatus, error) {
	// Check database health.
	dbHealthy := a.DB.Health(ctx) == nil

	// Get event bus stats.
	published, delivered, errors := a.Bus.Stats()

	return &WorkspaceStatus{
		WorkspaceName: a.Workspace.Name,
		RootPath:      a.Workspace.RootPath,
		DatabaseOK:    dbHealthy,
		CacheEntries:  a.Cache.Len(),
		BusPublished:  published,
		BusDelivered:  delivered,
		BusErrors:     errors,
		AIEnabled:     a.Config.AI.Enabled,
	}, nil
}

// WorkspaceStatus is the summary returned by [Status].
type WorkspaceStatus struct {
	WorkspaceName string `json:"workspace_name"`
	RootPath      string `json:"root_path"`
	DatabaseOK    bool   `json:"database_ok"`
	CacheEntries  int    `json:"cache_entries"`
	BusPublished  int64  `json:"bus_published"`
	BusDelivered  int64  `json:"bus_delivered"`
	BusErrors     int64  `json:"bus_errors"`
	AIEnabled     bool   `json:"ai_enabled"`
}

// writeDefaultConfig writes the initial workspace.toml.
func writeDefaultConfig(path string, name string) error {
	content := fmt.Sprintf(`# Doge Workspace Configuration
# Generated by 'workspace init'

[workspace]
name = %q

[watcher]
debounce_ms = 300
ignore_patterns = [
    "*.tmp", "*.swp", "*.swo", "*~",
    ".git/**", ".doge/**", "node_modules/**",
]

[parser]
max_file_size_mb = 50

[database]
wal_mode = true
busy_timeout_ms = 5000

[cache]
max_entries = 1000
ttl_minutes = 60

[ai]
enabled = false
provider = "openai_compatible"
base_url = "http://localhost:11434/v1"
model = ""
context_window = 8192
max_response_tokens = 2048
temperature = 0.1
timeout_seconds = 120

[ai.verification]
require_evidence = true
max_speculation_ratio = 0.1

[logging]
level = "info"
format = "text"
redact_sensitive = true

[snapshot]
auto_interval_minutes = 60

[rules]
enabled = true
`, name)

	return os.WriteFile(path, []byte(content), 0644)
}
