package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/scheduler"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// SessionFile is the path to the session state file.
const SessionFile = "session.json"

// PersistedState is the session state written to disk for
// multi-terminal access. Any terminal can read this file
// to understand the current investigation state.
//
// The session.json file lives in .doge/session.json.
// It is updated periodically by the running session.
//
// This enables:
//   - doge status (reads this file)
//   - doge console (reads this file + database)
//   - doge logs (tails the log file referenced here)
//   - doge approvals (queries database using project ID)
type PersistedState struct {
	// Session identity.
	InvestigationID uuid.UUID              `json:"investigation_id"`
	Target          string                 `json:"target"`
	TargetType      domain.TargetType      `json:"target_type"`
	Environment     domain.TargetEnvironment `json:"environment"`
	ProjectID       uuid.UUID              `json:"project_id"`

	// Runtime state.
	Status      SessionStatus      `json:"status"`
	Phase       InvestigationPhase `json:"phase"`
	PhaseSummary string            `json:"phase_summary"`
	StartedAt   time.Time          `json:"started_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	PID         int                `json:"pid"`

	// Counters.
	Observations    int `json:"observations"`
	Entities        int `json:"entities"`
	Correlations    int `json:"correlations"`
	NoveltySignals  int `json:"novelty_signals"`
	Opportunities   int `json:"opportunities"`
	Hypotheses      int `json:"hypotheses"`
	PendingApproval int `json:"pending_approval"`
	Validations     int `json:"validations"`
	Candidates      int `json:"candidates"`
	PendingConfirm  int `json:"pending_confirm"`
	Findings        int `json:"findings"`
	JobsQueued      int `json:"jobs_queued"`
	JobsRunning     int `json:"jobs_running"`
	JobsCompleted   int `json:"jobs_completed"`
	JobsFailed      int `json:"jobs_failed"`

	// Policy.
	AutoRecon       bool   `json:"auto_recon"`
	ReconAuthStatus string `json:"recon_auth_status"`
	Mode            string `json:"mode"`

	// Paths.
	WorkspacePath string `json:"workspace_path"`
	LogFile       string `json:"log_file"`
	DatabasePath  string `json:"database_path"`
}

// SaveState writes the current session state to disk.
func (s *Session) SaveState(workspacePath string) error {
	snap := s.Snapshot()

	state := PersistedState{
		InvestigationID: s.InvestigationID,
		Target:          s.Target.Primary,
		TargetType:      s.Target.TargetType,
		Environment:     s.Target.Environment,
		ProjectID:       s.InvestigationID, // Use investigation ID as project reference.
		Status:          snap.Status,
		Phase:           snap.Phase,
		PhaseSummary:    snap.PhaseSummary,
		StartedAt:       snap.StartedAt,
		UpdatedAt:       time.Now().UTC(),
		PID:             os.Getpid(),
		Observations:    snap.Observations,
		Entities:        snap.Entities,
		Correlations:    snap.Correlations,
		NoveltySignals:  snap.NoveltySignals,
		Opportunities:   snap.Opportunities,
		Hypotheses:      snap.Hypotheses,
		PendingApproval: snap.PendingApproval,
		Validations:     snap.Validations,
		Candidates:      snap.Candidates,
		PendingConfirm:  snap.PendingConfirm,
		Findings:        snap.Findings,
		JobsQueued:      snap.JobsQueued,
		JobsRunning:     snap.JobsRunning,
		JobsCompleted:   snap.JobsCompleted,
		JobsFailed:      snap.JobsFailed,
		AutoRecon:       s.Policy.AutoRecon,
		Mode:            string(s.Mode),
		WorkspacePath:   workspacePath,
		DatabasePath:    filepath.Join(workspacePath, ".doge", "workspace.db"),
	}

	// Check for authorization status.
	if !s.Policy.AutoRecon {
		auth, _ := scheduler.LoadAuthorization(workspacePath)
		if auth != nil {
			state.ReconAuthStatus = string(auth.Status)
		} else {
			state.ReconAuthStatus = "pending"
		}
	} else {
		state.ReconAuthStatus = "auto"
	}

	dogeDir := filepath.Join(workspacePath, ".doge")
	if err := os.MkdirAll(dogeDir, 0755); err != nil {
		return fmt.Errorf("creating .doge dir: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	path := filepath.Join(dogeDir, SessionFile)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing session state: %w", err)
	}

	return nil
}

// LoadState reads a persisted session state from disk.
func LoadState(workspacePath string) (*PersistedState, error) {
	path := filepath.Join(workspacePath, ".doge", SessionFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no active session (session.json not found)")
		}
		return nil, fmt.Errorf("reading session state: %w", err)
	}

	var state PersistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing session state: %w", err)
	}

	return &state, nil
}

// ClearState removes the session state file.
func ClearState(workspacePath string) error {
	path := filepath.Join(workspacePath, ".doge", SessionFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing session state: %w", err)
	}
	return nil
}

// IsSessionRunning checks if a session is currently active.
func IsSessionRunning(workspacePath string) bool {
	state, err := LoadState(workspacePath)
	if err != nil {
		return false
	}
	// Check if the process is still alive.
	if state.PID > 0 {
		proc, err := os.FindProcess(state.PID)
		if err != nil {
			return false
		}
		// On Windows, FindProcess always succeeds. We rely on
		// the status field and UpdatedAt freshness instead.
		_ = proc
	}

	// Consider stale if not updated in 30 seconds.
	if time.Since(state.UpdatedAt) > 30*time.Second {
		return false
	}

	return state.Status == SessionStatus("active")
}
