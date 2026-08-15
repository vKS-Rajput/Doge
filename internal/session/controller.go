// Package session provides the persistent DOGE runtime.
//
// The session is INDEPENDENT OF THE TUI. The TUI, console, logs,
// and approvals are attachable interfaces into the same running
// investigation.
//
//	doge start
//	    │
//	    ▼
//	DOGE Runtime (this package)
//	    │
//	    ├── Investigation
//	    ├── Scheduler
//	    ├── Ingestion
//	    ├── Orchestrator
//	    ├── Research Brain
//	    ├── Memory
//	    └── Event Bus
//	          │
//	          ├── TUI attachment
//	          ├── Console attachment
//	          ├── Logs attachment
//	          └── Approval attachment
package session

import (
	"time"

	"github.com/google/uuid"
)

// InvestigationPhase tracks what phase the investigation is in.
//
// DOGE shouldn't endlessly throw tools at a target. It should
// know where it is in the investigation lifecycle.
type InvestigationPhase string

const (
	PhaseInitializing  InvestigationPhase = "initializing"
	PhaseDiscovering   InvestigationPhase = "discovering"
	PhaseEnumerating   InvestigationPhase = "enumerating"
	PhaseAnalyzing     InvestigationPhase = "analyzing"
	PhaseInvestigating InvestigationPhase = "investigating"
	PhaseValidating    InvestigationPhase = "validating"
	PhaseReporting     InvestigationPhase = "reporting"
	PhaseIdle          InvestigationPhase = "idle"
	PhaseComplete      InvestigationPhase = "complete"
)

// InvestigationController tracks the health and phase of an investigation.
//
// It sits above the scheduler, brain, and orchestrator:
//
//	InvestigationController
//	         │
//	   ┌─────┼─────┐
//	   ▼     ▼     ▼
//	Sched  Brain  Orch
type InvestigationController struct {
	InvestigationID uuid.UUID          `json:"investigation_id"`
	Phase           InvestigationPhase `json:"phase"`

	// Completed milestones.
	PortDiscoveryDone    bool `json:"port_discovery_done"`
	HTTPDiscoveryDone    bool `json:"http_discovery_done"`
	DNSDiscoveryDone     bool `json:"dns_discovery_done"`
	WebCrawlingDone      bool `json:"web_crawling_done"`
	DirectoryEnumDone    bool `json:"directory_enum_done"`
	VulnScanningDone     bool `json:"vuln_scanning_done"`
	CorrelationCompleted bool `json:"correlation_completed"`
	NoveltyAnalyzed      bool `json:"novelty_analyzed"`

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
	JobsCompleted   int `json:"jobs_completed"`
	JobsQueued      int `json:"jobs_queued"`
	JobsRunning     int `json:"jobs_running"`
	JobsFailed      int `json:"jobs_failed"`

	// Timing.
	StartedAt   time.Time  `json:"started_at"`
	LastEventAt *time.Time `json:"last_event_at,omitempty"`
}

// NewController creates a new investigation controller.
func NewController(investigationID uuid.UUID) *InvestigationController {
	return &InvestigationController{
		InvestigationID: investigationID,
		Phase:           PhaseInitializing,
		StartedAt:       time.Now().UTC(),
	}
}

// UpdatePhase recalculates the investigation phase from milestones.
func (c *InvestigationController) UpdatePhase() {
	now := time.Now().UTC()
	c.LastEventAt = &now

	switch {
	case !c.PortDiscoveryDone:
		c.Phase = PhaseDiscovering
	case !c.HTTPDiscoveryDone || !c.DNSDiscoveryDone:
		c.Phase = PhaseEnumerating
	case !c.CorrelationCompleted || !c.NoveltyAnalyzed:
		c.Phase = PhaseAnalyzing
	case c.Opportunities > 0 && c.Hypotheses == 0:
		c.Phase = PhaseInvestigating
	case c.PendingApproval > 0 || c.Validations > 0:
		c.Phase = PhaseValidating
	case c.Findings > 0:
		c.Phase = PhaseReporting
	case c.JobsQueued == 0 && c.JobsRunning == 0:
		c.Phase = PhaseIdle
	default:
		c.Phase = PhaseInvestigating
	}
}

// IsActive returns true if the investigation is actively working.
func (c *InvestigationController) IsActive() bool {
	return c.Phase != PhaseIdle && c.Phase != PhaseComplete
}

// NeedsHuman returns true if human action is required.
func (c *InvestigationController) NeedsHuman() bool {
	return c.PendingApproval > 0 || c.PendingConfirm > 0
}

// Summary returns a human-readable status line.
func (c *InvestigationController) Summary() string {
	switch c.Phase {
	case PhaseInitializing:
		return "Initializing investigation..."
	case PhaseDiscovering:
		return "Discovering target services..."
	case PhaseEnumerating:
		return "Enumerating discovered services..."
	case PhaseAnalyzing:
		return "Analyzing correlations and novelty..."
	case PhaseInvestigating:
		return "Investigating research opportunities..."
	case PhaseValidating:
		return "Validation in progress..."
	case PhaseReporting:
		return "Ready to generate report."
	case PhaseIdle:
		return "Investigation idle — all jobs complete."
	case PhaseComplete:
		return "Investigation complete."
	default:
		return "Unknown phase."
	}
}
