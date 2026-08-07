package domain

import (
	"time"

	"github.com/google/uuid"
)

// Artifact represents a content-addressable record of a file imported
// into the workspace. Every file that enters the system is registered
// in the Artifact Store before being sent to a parser.
//
// Artifacts provide provenance: every Observation links back to the
// Artifact it was extracted from, and every Artifact records its
// content hash, original path, and import metadata.
type Artifact struct {
	// ID is the unique identifier for this artifact.
	ID uuid.UUID `json:"id"`

	// SHA256 is the content hash of the file. Used for deduplication
	// and content-addressable lookup.
	SHA256 string `json:"sha256"`

	// OriginalPath is the filesystem path where the file was located
	// at import time. Preserved for provenance, not used for access.
	OriginalPath string `json:"original_path"`

	// StoredPath is the path within the artifact store where the file
	// content is persisted.
	StoredPath string `json:"stored_path"`

	// FileName is the original filename (basename only).
	FileName string `json:"file_name"`

	// FileSize is the file size in bytes.
	FileSize int64 `json:"file_size"`

	// MIMEType is the detected content type of the file.
	MIMEType string `json:"mime_type"`

	// ParserUsed is the name of the parser that processed this artifact.
	// Empty string if the artifact has not yet been parsed.
	ParserUsed string `json:"parser_used"`

	// ImportedAt is the timestamp when this file was ingested into the workspace.
	ImportedAt time.Time `json:"imported_at"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// Version increments when the same original path is re-imported.
	// Enables tracking changes to files that are updated in place.
	Version int `json:"version"`

	// Metadata holds extensible key-value pairs for artifact-specific
	// information not covered by the fixed fields.
	Metadata map[string]string `json:"metadata,omitempty"`
}
