package novelty

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/correlation"
	"github.com/vKS-Rajput/doge/internal/surface"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Detector is a single novelty detection rule.
//
// Detectors are read-only and deterministic. They query the store
// and the attack-surface graph, then return novelty signals.
type Detector interface {
	// Name returns the detector identifier.
	Name() string

	// Detect runs the detector and returns discovered signals.
	Detect(ctx context.Context, input DetectorInput) ([]Signal, error)
}

// DetectorInput provides context for novelty detection.
type DetectorInput struct {
	// Store provides read access to entities and observations.
	Store correlation.ReadStore

	// Graph is the current attack-surface projection.
	Graph *surface.Graph

	// PreviousGraph is the previous attack-surface projection (if available).
	// Nil on first run.
	PreviousGraph *surface.Graph

	// ProjectID is the project being analyzed.
	ProjectID uuid.UUID
}

// Engine runs all novelty detectors and produces signals.
type Engine struct {
	detectors []Detector
	logger    *slog.Logger
}

// NewEngine creates a new Novelty Engine.
func NewEngine(logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		detectors: make([]Detector, 0),
		logger:    logger,
	}
}

// RegisterDetector adds a novelty detector.
func (e *Engine) RegisterDetector(d Detector) {
	for _, existing := range e.detectors {
		if existing.Name() == d.Name() {
			panic("novelty: duplicate detector: " + d.Name())
		}
	}
	e.detectors = append(e.detectors, d)
	e.logger.Info("novelty detector registered", "detector", d.Name())
}

// DetectAll runs all detectors and returns discovered signals,
// sorted by novelty score (highest first).
func (e *Engine) DetectAll(ctx context.Context, input DetectorInput) ([]Signal, error) {
	var allSignals []Signal

	for _, d := range e.detectors {
		signals, err := d.Detect(ctx, input)
		if err != nil {
			e.logger.Error("novelty detector failed",
				"detector", d.Name(),
				"error", err,
			)
			continue // Don't let one failed detector stop others.
		}

		allSignals = append(allSignals, signals...)

		e.logger.Info("novelty detector completed",
			"detector", d.Name(),
			"signals", len(signals),
		)
	}

	// Sort by novelty score descending.
	sort.Slice(allSignals, func(i, j int) bool {
		return allSignals[i].NoveltyScore > allSignals[j].NoveltyScore
	})

	return allSignals, nil
}

// DetectorNames returns the names of all registered detectors.
func (e *Engine) DetectorNames() []string {
	names := make([]string, len(e.detectors))
	for i, d := range e.detectors {
		names[i] = d.Name()
	}
	return names
}

// --- Structural Detector ---

// StructuralDetector finds new, removed, or changed surfaces
// by comparing two attack-surface graphs.
type StructuralDetector struct{}

func NewStructuralDetector() *StructuralDetector { return &StructuralDetector{} }

func (d *StructuralDetector) Name() string { return "structural" }

func (d *StructuralDetector) Detect(ctx context.Context, input DetectorInput) ([]Signal, error) {
	if input.Graph == nil {
		return nil, nil
	}

	var signals []Signal
	now := time.Now().UTC()

	if input.PreviousGraph == nil {
		// First run — everything is novel.
		for id, node := range input.Graph.Nodes {
			sig := classifyNewNode(node, id, input.ProjectID, now)
			if sig != nil {
				signals = append(signals, *sig)
			}
		}
		return signals, nil
	}

	// Compare current vs previous.
	prev := input.PreviousGraph

	// New nodes.
	for id, node := range input.Graph.Nodes {
		if _, existed := prev.Nodes[id]; !existed {
			sig := classifyNewNode(node, id, input.ProjectID, now)
			if sig != nil {
				signals = append(signals, *sig)
			}
		}
	}

	// Removed nodes (surface disappeared).
	for id, node := range prev.Nodes {
		if _, exists := input.Graph.Nodes[id]; !exists {
			signals = append(signals, Signal{
				ID:                uuid.New(),
				Type:              SignalSurfaceRemoved,
				Category:          CategoryStructural,
				Title:             fmt.Sprintf("Surface disappeared: %s", node.Entity.Value),
				Description:       fmt.Sprintf("Previously observed %s (%s) is no longer present in the attack surface.", node.Entity.Value, node.Category),
				NoveltyScore:      0.70,
				EntityIDs:         []uuid.UUID{id},
				SurfaceCategories: []surface.Category{node.Category},
				ProjectID:         input.ProjectID,
				DetectedAt:        now,
			})
		}
	}

	return signals, nil
}

func classifyNewNode(node surface.Node, id uuid.UUID, projectID uuid.UUID, now time.Time) *Signal {
	var sigType SignalType
	var score float64
	var desc string

	switch node.Category {
	case surface.CategoryUpload:
		sigType = SignalNewUploadSurface
		score = 0.85
		desc = fmt.Sprintf("New upload surface discovered: %s. Upload endpoints warrant investigation of accepted file types, validation, and storage behavior.", node.Entity.Value)
	case surface.CategoryAuthentication:
		sigType = SignalNewAuthSurface
		score = 0.80
		desc = fmt.Sprintf("New authentication surface discovered: %s. Authentication boundaries warrant investigation of session handling and credential management.", node.Entity.Value)
	case surface.CategoryAuthorization:
		sigType = SignalNewEndpoint
		score = 0.80
		desc = fmt.Sprintf("New authorization/admin surface discovered: %s. Administrative surfaces warrant investigation of access controls.", node.Entity.Value)
	case surface.CategoryAPI:
		sigType = SignalNewAPISurface
		score = 0.75
		desc = fmt.Sprintf("New API surface discovered: %s. API endpoints warrant investigation of input handling and authorization.", node.Entity.Value)
	case surface.CategoryNetwork:
		if node.Entity.Type == domain.EntityPort {
			sigType = SignalNewPort
			score = 0.65
			desc = fmt.Sprintf("New port discovered: %s.", node.Entity.Value)
		} else {
			return nil // IPs alone aren't interesting as novelty.
		}
	case surface.CategoryWeb:
		if node.Entity.Type == domain.EntitySubdomain {
			sigType = SignalNewSubdomain
			score = 0.60
			desc = fmt.Sprintf("New subdomain discovered: %s.", node.Entity.Value)
		} else if node.Entity.Type == domain.EntityEndpoint {
			sigType = SignalNewEndpoint
			score = 0.55
			desc = fmt.Sprintf("New endpoint discovered: %s.", node.Entity.Value)
		} else {
			return nil
		}
	default:
		return nil
	}

	// Boost score if correlated (multi-tool evidence).
	if node.Correlated {
		score = min(score+0.10, 1.0)
	}

	return &Signal{
		ID:                uuid.New(),
		Type:              sigType,
		Category:          CategoryStructural,
		Title:             fmt.Sprintf("New %s: %s", node.Category, node.Entity.Value),
		Description:       desc,
		NoveltyScore:      score,
		EntityIDs:         []uuid.UUID{id},
		SurfaceCategories: []surface.Category{node.Category},
		ProjectID:         projectID,
		DetectedAt:        now,
	}
}

// --- Contradiction Detector ---

// ContradictionDetector finds cross-tool contradictions and
// missing corroboration.
type ContradictionDetector struct{}

func NewContradictionDetector() *ContradictionDetector { return &ContradictionDetector{} }

func (d *ContradictionDetector) Name() string { return "contradiction" }

func (d *ContradictionDetector) Detect(ctx context.Context, input DetectorInput) ([]Signal, error) {
	if input.Graph == nil {
		return nil, nil
	}

	var signals []Signal
	now := time.Now().UTC()

	for id, node := range input.Graph.Nodes {
		if node.ObservationCount < 2 {
			continue
		}

		obs, err := input.Store.ObservationsForEntity(ctx, id)
		if err != nil || len(obs) < 2 {
			continue
		}

		// Check for conflicting technology/service reports.
		techByTool := make(map[string]string) // tool → reported value
		for _, o := range obs {
			if product, ok := o.Data["product"].(string); ok && product != "" {
				if o.SourceTool != "" {
					if existing, exists := techByTool[o.SourceTool]; exists && existing != product {
						// Same tool reported different products — internal inconsistency.
						continue
					}
					techByTool[o.SourceTool] = product
				}
			}
		}

		// Check for contradictions between tools.
		products := make(map[string][]string) // product → tools
		for tool, product := range techByTool {
			products[product] = append(products[product], tool)
		}

		if len(products) > 1 {
			var parts []string
			for product, tools := range products {
				parts = append(parts, fmt.Sprintf("%s (reported by %v)", product, tools))
			}
			signals = append(signals, Signal{
				ID:           uuid.New(),
				Type:         SignalContradiction,
				Category:     CategoryContradiction,
				Title:        fmt.Sprintf("Cross-tool contradiction on %s", node.Entity.Value),
				Description:  fmt.Sprintf("Different tools report conflicting information for %s: %v. This may indicate version differences, misidentification, or environment changes.", node.Entity.Value, parts),
				NoveltyScore: 0.75,
				EntityIDs:    []uuid.UUID{id},
				ProjectID:    input.ProjectID,
				DetectedAt:   now,
			})
		}
	}

	return signals, nil
}

// --- Combination Detector ---

// CombinationDetector finds novel combinations of interesting surfaces
// that appear on the same target.
type CombinationDetector struct{}

func NewCombinationDetector() *CombinationDetector { return &CombinationDetector{} }

func (d *CombinationDetector) Name() string { return "combination" }

func (d *CombinationDetector) Detect(ctx context.Context, input DetectorInput) ([]Signal, error) {
	if input.Graph == nil {
		return nil, nil
	}

	var signals []Signal
	now := time.Now().UTC()

	// Group interesting surface nodes by their parent host.
	hostSurfaces := make(map[string][]surface.Node) // host value → interesting nodes
	hostIDs := make(map[string]uuid.UUID)

	for _, edge := range input.Graph.Edges {
		sourceNode, sourceOK := input.Graph.Nodes[edge.SourceNode]
		targetNode, targetOK := input.Graph.Nodes[edge.TargetNode]
		if !sourceOK || !targetOK {
			continue
		}

		// If source is a host (subdomain/domain) and target is an interesting surface.
		if isHost(sourceNode) && isInteresting(targetNode) {
			hostSurfaces[sourceNode.Entity.Value] = append(hostSurfaces[sourceNode.Entity.Value], targetNode)
			hostIDs[sourceNode.Entity.Value] = sourceNode.Entity.ID
		}
	}

	// Find hosts with multiple interesting surface types.
	for host, nodes := range hostSurfaces {
		cats := distinctCategories(nodes)
		if len(cats) < 2 {
			continue
		}

		entityIDs := []uuid.UUID{hostIDs[host]}
		for _, n := range nodes {
			entityIDs = append(entityIDs, n.Entity.ID)
		}

		combo := describeCombo(cats)
		score := combinationScore(cats)

		signals = append(signals, Signal{
			ID:                uuid.New(),
			Type:              SignalNovelCombination,
			Category:          CategoryCombination,
			Title:             fmt.Sprintf("Novel surface combination on %s", host),
			Description:       fmt.Sprintf("Host %s exposes %s. This combination of surfaces may warrant investigation of boundary enforcement between them.", host, combo),
			NoveltyScore:      score,
			EntityIDs:         entityIDs,
			SurfaceCategories: cats,
			ProjectID:         input.ProjectID,
			DetectedAt:        now,
		})
	}

	return signals, nil
}

func isHost(n surface.Node) bool {
	return n.Entity.Type == domain.EntitySubdomain || n.Entity.Type == domain.EntityDomain
}

func isInteresting(n surface.Node) bool {
	switch n.Category {
	case surface.CategoryUpload, surface.CategoryAuthentication,
		surface.CategoryAuthorization, surface.CategoryAPI:
		return true
	default:
		return false
	}
}

func distinctCategories(nodes []surface.Node) []surface.Category {
	seen := make(map[surface.Category]bool)
	var cats []surface.Category
	for _, n := range nodes {
		if !seen[n.Category] {
			seen[n.Category] = true
			cats = append(cats, n.Category)
		}
	}
	return cats
}

func describeCombo(cats []surface.Category) string {
	parts := make([]string, len(cats))
	for i, c := range cats {
		parts[i] = string(c)
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			if i == len(parts)-1 {
				result += " + "
			} else {
				result += ", "
			}
		}
		result += p
	}
	return result
}

func combinationScore(cats []surface.Category) float64 {
	base := 0.70

	// High-risk combinations boost score.
	hasUpload := false
	hasAuth := false
	hasAuthz := false
	hasAPI := false

	for _, c := range cats {
		switch c {
		case surface.CategoryUpload:
			hasUpload = true
		case surface.CategoryAuthentication:
			hasAuth = true
		case surface.CategoryAuthorization:
			hasAuthz = true
		case surface.CategoryAPI:
			hasAPI = true
		}
	}

	// Upload + authorization is particularly interesting.
	if hasUpload && hasAuthz {
		base = max(base, 0.90)
	}
	// API + authentication combo.
	if hasAPI && hasAuth {
		base = max(base, 0.80)
	}
	// Upload + authentication.
	if hasUpload && hasAuth {
		base = max(base, 0.85)
	}
	// More surface types = more interesting.
	if len(cats) >= 3 {
		base = min(base+0.05, 1.0)
	}

	return base
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
