package planner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/internal/scope"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ResearchPhase represents the staged progression of an investigation.
type ResearchPhase string

const (
	PhasePassiveRecon      ResearchPhase = "passive_recon"
	PhaseActiveMapping     ResearchPhase = "active_mapping"
	PhaseEndpointDiscovery ResearchPhase = "endpoint_discovery"
	PhaseHypothesisTesting ResearchPhase = "hypothesis_testing"
	PhaseSynthesis         ResearchPhase = "synthesis"
)

// ActionRisk classifies the operational risk of a planned action.
type ActionRisk string

const (
	RiskPassive  ActionRisk = "PASSIVE"  // Pure passive / OSINT / local analysis
	RiskLow      ActionRisk = "LOW"      // Standard GET requests, non-intrusive banner grabs
	RiskMedium   ActionRisk = "MEDIUM"   // Directory fuzzing, authenticated endpoint probing
	RiskHigh     ActionRisk = "HIGH"     // Stateful mutations, parameter injection tests
	RiskCritical ActionRisk = "CRITICAL" // Exploit execution, heavy fuzzing (strictly gated)
)

// ResearchAction represents a single concrete step planned by the engine.
type ResearchAction struct {
	ID                 uuid.UUID               `json:"id"`
	Phase              ResearchPhase           `json:"phase"`
	Tool               string                  `json:"tool"`
	Target             string                  `json:"target"`
	CommandArgs        []string                `json:"command_args"`
	Reason             string                  `json:"reason"`
	Risk               ActionRisk              `json:"risk"`
	RequiresApproval   bool                    `json:"requires_approval"`
	HypothesisID       *uuid.UUID              `json:"hypothesis_id,omitempty"`
	ScopeClassification scope.AssetClassification `json:"scope_classification"`
	CreatedAt          time.Time               `json:"created_at"`
	Status             string                  `json:"status"` // "planned", "running", "completed", "skipped", "failed"
}

// Plan tracks the staged research progression for a target.
type Plan struct {
	ID              uuid.UUID         `json:"id"`
	Target          string            `json:"target"`
	Environment     string            `json:"environment"`
	CurrentPhase    ResearchPhase     `json:"current_phase"`
	PlannedActions  []*ResearchAction `json:"planned_actions"`
	CompletedActions []*ResearchAction `json:"completed_actions"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// Planner generates and adapts the research action plan dynamically.
type Planner struct {
	mu           sync.RWMutex
	scopeEngine  *scope.ScopeEngine
	currentPlan  *Plan
}

// NewPlanner creates a new Research Planner.
func NewPlanner(scopeEngine *scope.ScopeEngine, target, environment string) *Planner {
	p := &Plan{
		ID:           uuid.New(),
		Target:       target,
		Environment:  environment,
		CurrentPhase: PhasePassiveRecon,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	return &Planner{
		scopeEngine: scopeEngine,
		currentPlan: p,
	}
}

// GetPlan returns the current research plan.
func (p *Planner) GetPlan() *Plan {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentPlan
}

// AdaptPlan analyzes current knowledge graph entities, hypotheses, and completed actions to generate next actions.
func (p *Planner) AdaptPlan(entities []domain.Entity, hyps []*hypothesis.ResearchHypothesis) []*ResearchAction {
	p.mu.Lock()
	defer p.mu.Unlock()

	var nextActions []*ResearchAction
	now := time.Now().UTC()
	target := p.currentPlan.Target

	// Track targets and tools already executed or planned
	executed := make(map[string]bool)
	for _, a := range p.currentPlan.CompletedActions {
		key := fmt.Sprintf("%s:%s", a.Tool, a.Target)
		executed[key] = true
	}
	for _, a := range p.currentPlan.PlannedActions {
		key := fmt.Sprintf("%s:%s", a.Tool, a.Target)
		executed[key] = true
	}

	// 1. Passive Recon Actions (if in Passive phase or new roots)
	if p.currentPlan.CurrentPhase == PhasePassiveRecon {
		if !executed["subfinder:"+target] {
			nextActions = append(nextActions, &ResearchAction{
				ID:                  uuid.New(),
				Phase:               PhasePassiveRecon,
				Tool:                "subfinder",
				Target:              target,
				CommandArgs:         []string{"-d", target, "-silent"},
				Reason:              "Passive subdomain enumeration for root domain",
				Risk:                RiskPassive,
				RequiresApproval:    p.requiresApproval(RiskPassive),
				ScopeClassification: scope.AssetInScope,
				CreatedAt:           now,
				Status:              "planned",
			})
		}
		if !executed["assetfinder:"+target] {
			nextActions = append(nextActions, &ResearchAction{
				ID:                  uuid.New(),
				Phase:               PhasePassiveRecon,
				Tool:                "assetfinder",
				Target:              target,
				CommandArgs:         []string{"--subs-only", target},
				Reason:              "Complementary passive subdomain discovery",
				Risk:                RiskPassive,
				RequiresApproval:    p.requiresApproval(RiskPassive),
				ScopeClassification: scope.AssetInScope,
				CreatedAt:           now,
				Status:              "planned",
			})
		}
	}

	// 2. Active Mapping Actions (for discovered domains / subdomains)
	subdomainCount := 0
	for _, e := range entities {
		if e.Type == domain.EntityDomain || e.Type == domain.EntitySubdomain || e.Type == domain.EntityIPAddress {
			subdomainCount++
			val := e.Value
			// Validate with scope engine
			cls, _ := p.scopeEngine.ClassifyAsset(val)
			if cls != scope.AssetInScope {
				continue
			}

			if !executed["httpx:"+val] {
				nextActions = append(nextActions, &ResearchAction{
					ID:                  uuid.New(),
					Phase:               PhaseActiveMapping,
					Tool:                "httpx",
					Target:              val,
					CommandArgs:         []string{"-u", val, "-silent", "-status-code", "-title", "-tech-detect"},
					Reason:              fmt.Sprintf("Probe HTTP status, service title, and web tech stack for %s", val),
					Risk:                RiskLow,
					RequiresApproval:    p.requiresApproval(RiskLow),
					ScopeClassification: scope.AssetInScope,
					CreatedAt:           now,
					Status:              "planned",
				})
			}
		}
	}

	// Transition phase if subdomains and initial mapping actions exist
	if len(entities) > 2 && p.currentPlan.CurrentPhase == PhasePassiveRecon {
		p.currentPlan.CurrentPhase = PhaseActiveMapping
	}

	// 3. Endpoint Discovery (for live web assets)
	for _, e := range entities {
		if e.Type == domain.EntityService || e.Type == domain.EntityEndpoint || e.Type == domain.EntityURL {
			val := e.Value
			cls, _ := p.scopeEngine.ClassifyAsset(val)
			if cls != scope.AssetInScope {
				continue
			}

			if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
				if !executed["katana:"+val] {
					nextActions = append(nextActions, &ResearchAction{
						ID:                  uuid.New(),
						Phase:               PhaseEndpointDiscovery,
						Tool:                "katana",
						Target:              val,
						CommandArgs:         []string{"-u", val, "-silent", "-depth", "2", "-jc"},
						Reason:              fmt.Sprintf("Crawl endpoints and discover API endpoints in JS on %s", val),
						Risk:                RiskLow,
						RequiresApproval:    p.requiresApproval(RiskLow),
						ScopeClassification: scope.AssetInScope,
						CreatedAt:           now,
						Status:              "planned",
					})
				}
				if !executed["ffuf:"+val] {
					nextActions = append(nextActions, &ResearchAction{
						ID:                  uuid.New(),
						Phase:               PhaseEndpointDiscovery,
						Tool:                "ffuf",
						Target:              val,
						CommandArgs:         []string{"-u", val + "/FUZZ", "-w", "wordlist.txt", "-mc", "200,204,301,302,307,401,403"},
						Reason:              fmt.Sprintf("Controlled directory and route fuzzing on %s", val),
						Risk:                RiskMedium,
						RequiresApproval:    p.requiresApproval(RiskMedium),
						ScopeClassification: scope.AssetInScope,
						CreatedAt:           now,
						Status:              "planned",
					})
				}
			}
		}
	}

	// 4. Targeted Hypothesis Validation Actions
	for _, h := range hyps {
		if h.Status == hypothesis.StatusUnvalidated || h.Status == hypothesis.StatusPlausible || h.Status == hypothesis.StatusSupported {
			hypID := h.ID
			targetVal := h.Target
			cls, _ := p.scopeEngine.ClassifyAsset(targetVal)
			if cls != scope.AssetInScope && targetVal != "" {
				continue
			}

			// Generate targeted validation action based on hypothesis category
			switch h.Category {
			case hypothesis.CatBOLA:
				actionKey := fmt.Sprintf("bola_probe:%s:%s", h.ID, targetVal)
				if !executed[actionKey] {
					nextActions = append(nextActions, &ResearchAction{
						ID:                  uuid.New(),
						Phase:               PhaseHypothesisTesting,
						Tool:                "httpx",
						Target:              targetVal,
						CommandArgs:         []string{"-u", targetVal, "-H", "X-Context: Validation-A", "-silent"},
						Reason:              fmt.Sprintf("Falsifiable BOLA validation step: %s", h.Title),
						Risk:                RiskMedium,
						RequiresApproval:    p.requiresApproval(RiskMedium),
						HypothesisID:        &hypID,
						ScopeClassification: scope.AssetInScope,
						CreatedAt:           now,
						Status:              "planned",
					})
				}
			case hypothesis.CatSSRF:
				actionKey := fmt.Sprintf("ssrf_probe:%s:%s", h.ID, targetVal)
				if !executed[actionKey] {
					nextActions = append(nextActions, &ResearchAction{
						ID:                  uuid.New(),
						Phase:               PhaseHypothesisTesting,
						Tool:                "httpx",
						Target:              targetVal,
						CommandArgs:         []string{"-u", targetVal, "-silent"},
						Reason:              fmt.Sprintf("SSRF parameter callback check for %s", h.Title),
						Risk:                RiskHigh,
						RequiresApproval:    p.requiresApproval(RiskHigh),
						HypothesisID:        &hypID,
						ScopeClassification: scope.AssetInScope,
						CreatedAt:           now,
						Status:              "planned",
					})
				}
			case hypothesis.CatNovelAnomaly, hypothesis.CatInjection:
				actionKey := fmt.Sprintf("anomaly_test:%s:%s", h.ID, targetVal)
				if !executed[actionKey] {
					nextActions = append(nextActions, &ResearchAction{
						ID:                  uuid.New(),
						Phase:               PhaseHypothesisTesting,
						Tool:                "kxss",
						Target:              targetVal,
						CommandArgs:         []string{"-u", targetVal},
						Reason:              fmt.Sprintf("Verify input reflection and encoding context for %s", h.Title),
						Risk:                RiskLow,
						RequiresApproval:    p.requiresApproval(RiskLow),
						HypothesisID:        &hypID,
						ScopeClassification: scope.AssetInScope,
						CreatedAt:           now,
						Status:              "planned",
					})
				}
			}
		}
	}

	// Update plan
	p.currentPlan.PlannedActions = append(p.currentPlan.PlannedActions, nextActions...)
	p.currentPlan.UpdatedAt = now

	return nextActions
}

// MarkActionCompleted updates the state of an action in the plan.
func (p *Planner) MarkActionCompleted(actionID uuid.UUID, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, a := range p.currentPlan.PlannedActions {
		if a.ID == actionID {
			a.Status = status
			p.currentPlan.CompletedActions = append(p.currentPlan.CompletedActions, a)
			p.currentPlan.PlannedActions = append(p.currentPlan.PlannedActions[:i], p.currentPlan.PlannedActions[i+1:]...)
			p.currentPlan.UpdatedAt = time.Now().UTC()
			return
		}
	}
}

// AdvancePhase transitions the research plan to a new phase.
func (p *Planner) AdvancePhase(phase ResearchPhase) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.currentPlan.CurrentPhase = phase
	p.currentPlan.UpdatedAt = time.Now().UTC()
}

func (p *Planner) requiresApproval(risk ActionRisk) bool {
	// In HTB/Lab environments, passive and low/medium risk actions are auto-approved.
	// In Authorized/Bug Bounty environments, anything above passive requires human approval.
	env := strings.ToLower(p.currentPlan.Environment)
	if env == "htb" || env == "lab" {
		return risk == RiskHigh || risk == RiskCritical
	}
	return risk != RiskPassive
}
