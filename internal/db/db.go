// Package db provides SQLite database access, connection management,
// and embedded schema migrations for the workspace.
//
// The database layer is an infrastructure module. It provides:
//   - Connection lifecycle (open, close, health check)
//   - WAL mode configuration for concurrent reads
//   - Embedded migration execution (versioned SQL files)
//   - Busy timeout configuration
//
// It does NOT contain business queries — those belong in each
// domain module's repository implementation. This package provides
// the [*sql.DB] connection that repositories use.
//
// Usage:
//
//	db, err := db.Open("workspace.db", db.Options{WALMode: true, BusyTimeoutMs: 5000})
//	if err != nil { ... }
//	defer db.Close()
//
//	if err := db.Migrate(); err != nil { ... }
package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // Pure-Go SQLite driver, no CGO required.
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Options configures database behavior.
type Options struct {
	// WALMode enables Write-Ahead Logging for concurrent read support.
	// Strongly recommended for production use.
	WALMode bool

	// BusyTimeoutMs is the SQLite busy timeout in milliseconds.
	// When another connection holds a lock, queries wait up to this
	// duration before returning SQLITE_BUSY. Default: 5000ms.
	BusyTimeoutMs int

	// Logger is used for database operation logging.
	// If nil, a no-op logger is used.
	Logger *slog.Logger
}

// DB wraps a [*sql.DB] connection with workspace-specific configuration
// and migration support.
type DB struct {
	conn   *sql.DB
	path   string
	logger *slog.Logger
}

// Open creates a new database connection to the SQLite file at the given path.
// If the file doesn't exist, SQLite creates it automatically.
//
// The connection is configured with:
//   - Foreign keys enabled
//   - WAL mode (if opts.WALMode is true)
//   - Busy timeout
//   - Journal size limit (to prevent unbounded WAL growth)
func Open(path string, opts Options) (*DB, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Build DSN with pragmas.
	dsn := path + "?_pragma=foreign_keys(1)"
	if opts.BusyTimeoutMs > 0 {
		dsn += fmt.Sprintf("&_pragma=busy_timeout(%d)", opts.BusyTimeoutMs)
	} else {
		dsn += "&_pragma=busy_timeout(5000)"
	}

	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database %s: %w", path, err)
	}

	// Verify the connection works.
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pinging database %s: %w", path, err)
	}

	db := &DB{
		conn:   conn,
		path:   path,
		logger: logger,
	}

	// Enable WAL mode if requested.
	if opts.WALMode {
		if err := db.enableWAL(); err != nil {
			conn.Close()
			return nil, err
		}
	}

	logger.Info("database opened",
		"path", path,
		"wal_mode", opts.WALMode,
		"busy_timeout_ms", opts.BusyTimeoutMs,
	)

	return db, nil
}

// Conn returns the underlying [*sql.DB] connection for use by
// repository implementations.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

// Close closes the database connection. In WAL mode, this ensures
// the WAL is checkpointed before closing.
func (db *DB) Close() error {
	db.logger.Info("closing database", "path", db.path)

	// Checkpoint WAL before closing to ensure data is flushed.
	if _, err := db.conn.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		db.logger.Warn("WAL checkpoint failed", "error", err)
	}

	return db.conn.Close()
}

// Health checks if the database connection is alive and responsive.
func (db *DB) Health(ctx context.Context) error {
	return db.conn.PingContext(ctx)
}

// Migrate runs all pending database migrations in version order.
// Migrations are embedded SQL files in the migrations/ directory.
// Each migration runs in a transaction. Already-applied migrations
// are skipped based on the migrations table.
func (db *DB) Migrate() error {
	db.logger.Info("running database migrations")

	// Ensure the migrations tracking table exists.
	// This is the one piece of schema not managed by migrations themselves.
	if _, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		)
	`); err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	// Find the current schema version.
	var currentVersion int
	err := db.conn.QueryRow("SELECT COALESCE(MAX(version), 0) FROM migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("querying current migration version: %w", err)
	}

	// Read and sort migration files.
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	applied := 0
	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}

		db.logger.Info("applying migration",
			"version", m.version,
			"name", m.name,
		)

		tx, err := db.conn.Begin()
		if err != nil {
			return fmt.Errorf("beginning transaction for migration %d: %w", m.version, err)
		}

		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("executing migration %d (%s): %w", m.version, m.name, err)
		}

		if _, err := tx.Exec(
			"INSERT INTO migrations (version, name, applied_at) VALUES (?, ?, ?)",
			m.version, m.name, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", m.version, err)
		}

		applied++
	}

	db.logger.Info("migrations complete",
		"applied", applied,
		"current_version", currentVersion+applied,
	)

	return nil
}

// enableWAL switches the database to Write-Ahead Logging mode.
func (db *DB) enableWAL() error {
	var mode string
	if err := db.conn.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return fmt.Errorf("enabling WAL mode: %w", err)
	}
	if strings.ToLower(mode) != "wal" {
		return fmt.Errorf("expected WAL mode, got %q", mode)
	}

	// Limit WAL size to prevent unbounded growth (64 MB).
	if _, err := db.conn.Exec("PRAGMA journal_size_limit = 67108864"); err != nil {
		return fmt.Errorf("setting journal size limit: %w", err)
	}

	return nil
}

// migration represents a single migration file.
type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads and parses all .sql files from the embedded
// migrations directory, sorted by version number.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("reading migrations directory: %w", err)
	}

	var migrations []migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		// Parse version from filename: "001_initial_schema.sql" → version=1
		var version int
		name := strings.TrimSuffix(entry.Name(), ".sql")
		if _, err := fmt.Sscanf(entry.Name(), "%d_", &version); err != nil {
			return nil, fmt.Errorf("parsing migration version from %q: %w", entry.Name(), err)
		}

		content, err := fs.ReadFile(migrationsFS, "migrations/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading migration file %s: %w", entry.Name(), err)
		}

		migrations = append(migrations, migration{
			version: version,
			name:    name,
			sql:     string(content),
		})
	}

	// Sort by version.
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	return migrations, nil
}
