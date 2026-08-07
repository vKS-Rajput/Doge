package domain

import (
	"time"

	"github.com/google/uuid"
)

// ProjectStatus tracks the lifecycle of a project.
type ProjectStatus string

const (
	ProjectActive   ProjectStatus = "active"
	ProjectPaused   ProjectStatus = "paused"
	ProjectArchived ProjectStatus = "archived"
)

// Workspace is the top-level container for the security research
// environment. A workspace contains one or more projects and holds
// global configuration.
type Workspace struct {
	// ID is the unique identifier for this workspace.
	ID uuid.UUID `json:"id"`

	// Name is the display name for the workspace.
	Name string `json:"name"`

	// RootPath is the filesystem path to the workspace root directory.
	RootPath string `json:"root_path"`

	// CreatedAt is when this workspace was initialized.
	CreatedAt time.Time `json:"created_at"`
}

// Project is a scoped engagement within a workspace. Each project
// represents a single target or assessment, with its own observations,
// entities, and configuration.
//
// Projects provide isolation: an entity in project A has no relationship
// to an entity in project B, even if they have the same value. This
// prevents data leakage between engagements.
type Project struct {
	// ID is the unique identifier for this project.
	ID uuid.UUID `json:"id"`

	// WorkspaceID links to the parent workspace.
	WorkspaceID uuid.UUID `json:"workspace_id"`

	// Slug is the URL-safe directory name for this project.
	Slug string `json:"slug"`

	// Name is the human-readable display name.
	Name string `json:"name"`

	// Description provides context about the engagement.
	Description string `json:"description"`

	// Status tracks the lifecycle of the project.
	Status ProjectStatus `json:"status"`

	// TargetScope lists the in-scope domains, IPs, and URL patterns.
	// Used by parsers and the Rule Engine to filter relevant data.
	TargetScope []string `json:"target_scope"`

	// CreatedAt is when this project was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this project was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// ArchivedAt is when this project was archived. Nil if active.
	ArchivedAt *time.Time `json:"archived_at,omitempty"`
}
