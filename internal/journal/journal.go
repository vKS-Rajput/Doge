// Package journal records every tool execution as permanent
// research history. Each command becomes a journal entry with
// full context: command, target, timestamps, exit code, artifact,
// observations generated, and researcher annotations.
//
// The journal enables DOGE to answer questions like:
//   - "You already scanned this host 2 hours ago"
//   - "4 commands produced 127 observations"
//   - "httpx was last run against this target at 14:31"
//
// Journal entries are stored in SQLite and linked to the
// observation pipeline via artifact IDs.
package journal

import (
	"time"

	"github.com/google/uuid"
)

// Execution records a single tool invocation.
type Execution struct {
	// ID uniquely identifies this execution.
	ID uuid.UUID `json:"id"`

	// Tool is the name of the tool (e.g., "nmap", "httpx", "curl", "manual").
	Tool string `json:"tool"`

	// Command is the full command line that was run.
	// May be empty if the user only imports a file.
	Command string `json:"command,omitempty"`

	// Target is what was targeted by this command.
	Target string `json:"target"`

	// ArtifactPath is the path to the stored output file.
	ArtifactPath string `json:"artifact_path,omitempty"`

	// ArtifactID links to the artifact in the artifact store.
	ArtifactID uuid.UUID `json:"artifact_id,omitempty"`

	// Observations is how many observations were created from this execution.
	Observations int `json:"observations"`

	// ExitCode is the process exit code (-1 if not applicable).
	ExitCode int `json:"exit_code"`

	// Notes is a researcher annotation about this execution.
	Notes string `json:"notes,omitempty"`

	// ProjectID is the owning project.
	ProjectID uuid.UUID `json:"project_id"`

	// Timestamps.
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	IngestedAt  time.Time `json:"ingested_at"`
}

// Summary returns a one-line summary of this execution.
func (e *Execution) Summary() string {
	if e.Observations > 0 {
		return e.Tool + " → " + e.Target + " (" + itoa(e.Observations) + " observations)"
	}
	return e.Tool + " → " + e.Target
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
