package benchmark

import (
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/session"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// SimulatedResponse defines a mock execution output for a specific command or URL pattern.
type SimulatedResponse struct {
	StatusCode int    `json:"status_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
}

// DistractorSpec defines a decoy attack surface designed to test agent resilience against false positives.
type DistractorSpec struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // e.g. "honeypot", "rate_limit_trap", "dead_end_param", "hardened_boundary"
	Endpoint    string `json:"endpoint"`
	Description string `json:"description"`
}

// GroundTruthVulnerability defines the real vulnerability embedded in the benchmark target.
type GroundTruthVulnerability struct {
	Category    hypothesis.Category `json:"category"`
	Endpoint    string              `json:"endpoint"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
}

// BenchmarkScenario defines an adversarial synthetic security research challenge.
type BenchmarkScenario struct {
	ID                  string                               `json:"id"`
	Title               string                               `json:"title"`
	Description         string                               `json:"description"`
	Target              string                               `json:"target"`
	InitialEntities     []domain.Entity                      `json:"initial_entities"`
	InitialObservations []domain.Observation                 `json:"initial_observations"`
	GroundTruth         GroundTruthVulnerability             `json:"ground_truth"`
	Distractors         []DistractorSpec                     `json:"distractors"`
	SimulatedResponses  map[string]SimulatedResponse         `json:"simulated_responses"`
	MaxAllowedIter      int                                  `json:"max_allowed_iter"`
}

// ScenarioResult summarizes performance on a single benchmark scenario.
type ScenarioResult struct {
	ScenarioID           string                `json:"scenario_id"`
	Title                string                `json:"title"`
	Passed               bool                  `json:"passed"`
	GroundTruthFound     bool                  `json:"ground_truth_found"`
	DistractorsFalsified int                   `json:"distractors_falsified"`
	TotalDistractors     int                   `json:"total_distractors"`
	IterationsUsed       int                   `json:"iterations_used"`
	MaxAllowedIter       int                   `json:"max_allowed_iter"`
	Duration             time.Duration         `json:"duration"`
	Trace                *session.SessionTrace `json:"trace,omitempty"`
	Notes                string                `json:"notes"`
}

// BenchmarkScorecard summarizes aggregate agent performance across the entire benchmark suite.
type BenchmarkScorecard struct {
	SuiteID             uuid.UUID         `json:"suite_id"`
	TotalScenarios      int               `json:"total_scenarios"`
	PassedScenarios     int               `json:"passed_scenarios"`
	FailedScenarios     int               `json:"failed_scenarios"`
	PassRatePercent     float64           `json:"pass_rate_percent"`
	TotalDistractors    int               `json:"total_distractors"`
	FalsifiedDistractors int              `json:"falsified_distractors"`
	FalsificationRate   float64           `json:"falsification_rate_percent"`
	AverageIterations   float64           `json:"average_iterations"`
	ScenarioResults     []*ScenarioResult `json:"scenario_results"`
	EvaluatedAt         time.Time         `json:"evaluated_at"`
}
