package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
)

// HypothesisDelta tracks an epistemic status and confidence transition during an iteration.
type HypothesisDelta struct {
	HypothesisID    uuid.UUID                  `json:"hypothesis_id"`
	HypothesisTitle string                     `json:"hypothesis_title"`
	OldStatus       hypothesis.EpistemicStatus `json:"old_status"`
	NewStatus       hypothesis.EpistemicStatus `json:"new_status"`
	OldConfidence   float64                    `json:"old_confidence"`
	NewConfidence   float64                    `json:"new_confidence"`
	Reason          string                     `json:"reason"`
}

// IterationTraceEntry captures the complete state and execution record of a single cognitive loop step.
type IterationTraceEntry struct {
	IterationNumber           int               `json:"iteration_number"`
	ActionTitle               string            `json:"action_title"`
	Tool                      string            `json:"tool"`
	TargetEndpoint            string            `json:"target_endpoint"`
	InformationGainScore      float64           `json:"information_gain_score"`
	PriorityReason            string            `json:"priority_reason"`
	RequiresApproval          bool              `json:"requires_approval"`
	GateApproved              bool              `json:"gate_approved"`
	ExecutionStdout           string            `json:"execution_stdout"`
	ExecutionStderr           string            `json:"execution_stderr"`
	ExitCode                  int               `json:"exit_code"`
	ObservedEntitiesCount     int               `json:"observed_entities_count"`
	ObservedObservationsCount int               `json:"observed_observations_count"`
	HypothesisDeltas          []HypothesisDelta `json:"hypothesis_deltas"`
	LearningBoostDelta        float64           `json:"learning_boost_delta"`
	RecordedAt                time.Time         `json:"recorded_at"`
}

// SessionTrace is the complete, deterministic, exportable execution trace of an entire research session.
type SessionTrace struct {
	ID               uuid.UUID              `json:"id"`
	InvestigationID  uuid.UUID              `json:"investigation_id"`
	Target           string                 `json:"target"`
	OperatingProfile OperatingProfile       `json:"operating_profile"`
	StartedAt        time.Time              `json:"started_at"`
	EndedAt          *time.Time             `json:"ended_at,omitempty"`
	Iterations       []*IterationTraceEntry `json:"iterations"`
	TotalFindings    int                    `json:"total_findings"`
	FinalSummary     string                 `json:"final_summary"`
}

// TraceRecorder safely records iterations in real-time during agent execution.
type TraceRecorder struct {
	mu    sync.RWMutex
	trace *SessionTrace
}

// NewTraceRecorder instantiates a new session trace recorder.
func NewTraceRecorder(investigationID uuid.UUID, target string, profile OperatingProfile) *TraceRecorder {
	return &TraceRecorder{
		trace: &SessionTrace{
			ID:               uuid.New(),
			InvestigationID:  investigationID,
			Target:           target,
			OperatingProfile: profile,
			StartedAt:        time.Now().UTC(),
			Iterations:       make([]*IterationTraceEntry, 0),
		},
	}
}

// RecordIteration appends an iteration trace entry.
func (tr *TraceRecorder) RecordIteration(entry *IterationTraceEntry) {
	if entry == nil {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()

	if entry.RecordedAt.IsZero() {
		entry.RecordedAt = time.Now().UTC()
	}
	tr.trace.Iterations = append(tr.trace.Iterations, entry)
}

// Finalize marks the session trace as completed and produces the final trace snapshot.
func (tr *TraceRecorder) Finalize(totalFindings int, summary string) *SessionTrace {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	now := time.Now().UTC()
	tr.trace.EndedAt = &now
	tr.trace.TotalFindings = totalFindings
	tr.trace.FinalSummary = summary
	return tr.trace
}

// ExportJSON serializes the session trace to formatted JSON.
func (tr *TraceRecorder) ExportJSON() ([]byte, error) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return json.MarshalIndent(tr.trace, "", "  ")
}

// ReplayEngine allows deterministic playback and inspection of recorded session traces.
type ReplayEngine struct{}

// NewReplayEngine instantiates a replay engine.
func NewReplayEngine() *ReplayEngine {
	return &ReplayEngine{}
}

// LoadTrace decodes a JSON session trace.
func (re *ReplayEngine) LoadTrace(data []byte) (*SessionTrace, error) {
	var trace SessionTrace
	if err := json.Unmarshal(data, &trace); err != nil {
		return nil, fmt.Errorf("failed decoding session trace: %w", err)
	}
	return &trace, nil
}

// ReplayStepByStep replays recorded iterations deterministically through a step handler.
func (re *ReplayEngine) ReplayStepByStep(trace *SessionTrace, handler func(step *IterationTraceEntry) error) error {
	if trace == nil {
		return fmt.Errorf("cannot replay nil trace")
	}

	for _, step := range trace.Iterations {
		if err := handler(step); err != nil {
			return fmt.Errorf("error during replay of iteration %d: %w", step.IterationNumber, err)
		}
	}

	return nil
}

// SaveTrace writes a completed session trace to .doge/traces/<session-id>.json.
func SaveTrace(wsPath string, trace *SessionTrace) error {
	if trace == nil {
		return fmt.Errorf("cannot save nil trace")
	}
	dir := filepath.Join(wsPath, ".doge", "traces")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, trace.ID.String()+".json")
	return os.WriteFile(path, data, 0644)
}

// ListTraces retrieves all saved session traces in .doge/traces/*.json.
func ListTraces(wsPath string) ([]*SessionTrace, error) {
	dir := filepath.Join(wsPath, ".doge", "traces")
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	re := NewReplayEngine()
	var traces []*SessionTrace
	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			continue
		}
		t, err := re.LoadTrace(data)
		if err == nil && t != nil {
			traces = append(traces, t)
		}
	}
	return traces, nil
}

