package gates

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/scope"
)

// GateType defines the classification of a human gate.
type GateType string

const (
	// GateTypeDirection represents strategic branch points (e.g., choice between API vs Auth vs Web enum).
	GateTypeDirection GateType = "direction"
	// GateTypeApproval represents strict permission checks for tool execution/probing.
	GateTypeApproval GateType = "approval"
	// GateTypeHypothesis represents approval to promote or validate a research hypothesis.
	GateTypeHypothesis GateType = "hypothesis"
	// GateTypeFinding represents human confirmation before finalizing a candidate finding.
	GateTypeFinding GateType = "finding"
)

// GateStatus tracks the decision state of a gate.
type GateStatus string

const (
	StatusPending  GateStatus = "pending"
	StatusApproved GateStatus = "approved"
	StatusRejected GateStatus = "rejected"
	StatusChosen   GateStatus = "chosen"
	StatusExpired  GateStatus = "expired"
)

// DirectionOption represents a choice in a Direction Gate.
type DirectionOption struct {
	Index       int    `json:"index"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Priority    string `json:"priority"` // e.g. "HIGH", "MEDIUM"
	Target      string `json:"target,omitempty"`
	Phase       string `json:"phase,omitempty"`
}

// GateContext holds detailed provenance and safety information for an approval decision.
type GateContext struct {
	Target             string                     `json:"target"`
	Tool               string                     `json:"tool"`
	Command            string                     `json:"command"`
	RiskLevel          string                     `json:"risk_level"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	ScopeClassification scope.AssetClassification `json:"scope_classification"`
	ScopeReason        string                     `json:"scope_reason"`
	HypothesisID       string                     `json:"hypothesis_id,omitempty"`
	HypothesisTitle    string                     `json:"hypothesis_title,omitempty"`
	EpistemicTier      string                     `json:"epistemic_tier,omitempty"`
	Confidence         float64                    `json:"confidence,omitempty"`
	Reason             string                     `json:"reason"`
	EstimatedRequests  int                        `json:"estimated_requests,omitempty"`
	EstimatedDuration  string                     `json:"estimated_duration,omitempty"`
}

// Gate represents an interactive human decision point.
type Gate struct {
	ID             uuid.UUID         `json:"id"`
	Type           GateType          `json:"type"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Status         GateStatus        `json:"status"`
	Context        GateContext       `json:"context"`
	Options        []DirectionOption `json:"options,omitempty"`
	SelectedOption int               `json:"selected_option,omitempty"`
	DecisionBy     string            `json:"decision_by,omitempty"`
	DecisionNotes  string            `json:"decision_notes,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	ResolvedAt     *time.Time        `json:"resolved_at,omitempty"`
}

// Manager handles in-memory and persisted gates for human-in-the-loop decisions.
type Manager struct {
	mu            sync.RWMutex
	workspacePath string
	gates         map[uuid.UUID]*Gate
	order         []uuid.UUID
	listeners     []chan *Gate
}

// NewManager creates a new Gate Manager.
func NewManager(workspacePath string) *Manager {
	m := &Manager{
		workspacePath: workspacePath,
		gates:         make(map[uuid.UUID]*Gate),
		order:         make([]uuid.UUID, 0),
		listeners:     make([]chan *Gate, 0),
	}
	_ = m.Load()
	return m
}

// CreateApprovalGate creates an execution approval gate.
func (m *Manager) CreateApprovalGate(title, description string, ctx GateContext) *Gate {
	m.mu.Lock()
	defer m.mu.Unlock()

	g := &Gate{
		ID:          uuid.New(),
		Type:        GateTypeApproval,
		Title:       title,
		Description: description,
		Status:      StatusPending,
		Context:     ctx,
		CreatedAt:   time.Now().UTC(),
	}

	m.gates[g.ID] = g
	m.order = append(m.order, g.ID)
	_ = m.saveLocked()
	m.notifyLocked(g)
	return g
}

// CreateDirectionGate creates a strategic direction choice gate.
func (m *Manager) CreateDirectionGate(title, description string, options []DirectionOption, ctx GateContext) *Gate {
	m.mu.Lock()
	defer m.mu.Unlock()

	g := &Gate{
		ID:          uuid.New(),
		Type:        GateTypeDirection,
		Title:       title,
		Description: description,
		Status:      StatusPending,
		Context:     ctx,
		Options:     options,
		CreatedAt:   time.Now().UTC(),
	}

	m.gates[g.ID] = g
	m.order = append(m.order, g.ID)
	_ = m.saveLocked()
	m.notifyLocked(g)
	return g
}

// Approve marks an approval gate as approved.
func (m *Manager) Approve(id uuid.UUID, decisionBy, notes string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.gates[id]
	if !ok {
		return fmt.Errorf("gate %s not found", id)
	}
	if g.Status != StatusPending {
		return fmt.Errorf("gate %s is already %s", id, g.Status)
	}

	now := time.Now().UTC()
	g.Status = StatusApproved
	g.DecisionBy = decisionBy
	g.DecisionNotes = notes
	g.ResolvedAt = &now

	_ = m.saveLocked()
	m.notifyLocked(g)
	return nil
}

// Reject marks a gate as rejected.
func (m *Manager) Reject(id uuid.UUID, decisionBy, notes string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.gates[id]
	if !ok {
		return fmt.Errorf("gate %s not found", id)
	}
	if g.Status != StatusPending {
		return fmt.Errorf("gate %s is already %s", id, g.Status)
	}

	now := time.Now().UTC()
	g.Status = StatusRejected
	g.DecisionBy = decisionBy
	g.DecisionNotes = notes
	g.ResolvedAt = &now

	_ = m.saveLocked()
	m.notifyLocked(g)
	return nil
}

// ChooseOption selects an option for a direction gate.
func (m *Manager) ChooseOption(id uuid.UUID, optionIdx int, decisionBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.gates[id]
	if !ok {
		return fmt.Errorf("gate %s not found", id)
	}
	if g.Type != GateTypeDirection {
		return fmt.Errorf("gate %s is not a direction gate", id)
	}
	if g.Status != StatusPending {
		return fmt.Errorf("gate %s is already %s", id, g.Status)
	}

	valid := false
	for _, opt := range g.Options {
		if opt.Index == optionIdx {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid option index %d", optionIdx)
	}

	now := time.Now().UTC()
	g.Status = StatusChosen
	g.SelectedOption = optionIdx
	g.DecisionBy = decisionBy
	g.ResolvedAt = &now

	_ = m.saveLocked()
	m.notifyLocked(g)
	return nil
}

// GetGate retrieves a gate by ID.
func (m *Manager) GetGate(id uuid.UUID) (*Gate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.gates[id]
	return g, ok
}

// ListPending returns all gates awaiting human action.
func (m *Manager) ListPending() []*Gate {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var pending []*Gate
	for _, id := range m.order {
		if g, ok := m.gates[id]; ok && g.Status == StatusPending {
			pending = append(pending, g)
		}
	}
	return pending
}

// ListAll returns all gates in creation order.
func (m *Manager) ListAll() []*Gate {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var all []*Gate
	for _, id := range m.order {
		if g, ok := m.gates[id]; ok {
			all = append(all, g)
		}
	}
	return all
}

// Subscribe returns a channel that receives gate updates.
func (m *Manager) Subscribe() chan *Gate {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := make(chan *Gate, 10)
	m.listeners = append(m.listeners, ch)
	return ch
}

// Unsubscribe removes a listener.
func (m *Manager) Unsubscribe(ch chan *Gate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, l := range m.listeners {
		if l == ch {
			m.listeners = append(m.listeners[:i], m.listeners[i+1:]...)
			close(ch)
			return
		}
	}
}

func (m *Manager) notifyLocked(g *Gate) {
	for _, ch := range m.listeners {
		select {
		case ch <- g:
		default:
		}
	}
}

// --- Persistence ---

const gatesFile = "gates.json"

func (m *Manager) saveLocked() error {
	if m.workspacePath == "" {
		return nil
	}
	dogeDir := filepath.Join(m.workspacePath, ".doge")
	if err := os.MkdirAll(dogeDir, 0755); err != nil {
		return err
	}

	var list []*Gate
	for _, id := range m.order {
		if g, ok := m.gates[id]; ok {
			list = append(list, g)
		}
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dogeDir, gatesFile), data, 0644)
}

// Load reads gates from disk.
func (m *Manager) Load() error {
	if m.workspacePath == "" {
		return nil
	}
	path := filepath.Join(m.workspacePath, ".doge", gatesFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var list []*Gate
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range list {
		m.gates[g.ID] = g
		m.order = append(m.order, g.ID)
	}
	return nil
}
