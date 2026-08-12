// Package correlation implements the Correlation Engine — deterministic
// cross-tool evidence correlation.
//
// The Correlation Engine finds relationships across observations that
// no individual security tool could see on its own. It runs deterministic
// rules against the Knowledge Graph and produces Correlation objects
// with full provenance.
//
// Architecture:
//
//	Knowledge Graph
//	      │
//	      ▼
//	Correlation Engine
//	      │
//	      ├── Rule: same_target
//	      ├── Rule: resolves_to
//	      ├── Rule: convergence
//	      └── Rule: service_stack
//	      │
//	      ▼
//	Correlations (stored)
//	      │
//	      ▼
//	Graph Relationships (materialized)
//
// Every correlation requires:
//   - Evidence: at least 2 supporting observations
//   - Deterministic Rule: a named, testable rule
//   - Provenance: traceable back to specific observations
//
// Correlations can discover relationships. They CANNOT declare vulnerabilities.
package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Rule is a single deterministic correlation rule.
//
// Rules are read-only: they query the store and return candidate
// correlations. The engine persists and deduplicates them.
type Rule interface {
	// Name returns the unique identifier for this rule.
	Name() string

	// Evaluate runs the rule against the store and returns
	// discovered correlations. Rules MUST NOT write to the store.
	Evaluate(ctx context.Context, store ReadStore) ([]domain.Correlation, error)
}

// ReadStore provides read-only access to entities, observations, and
// relationships for correlation rules. Rules never write directly.
type ReadStore interface {
	// EntitiesByType returns all entities of a given type for a project.
	EntitiesByType(ctx context.Context, entityType domain.EntityType, projectID uuid.UUID) ([]domain.Entity, error)

	// ObservationsForEntity returns all observations linked to an entity.
	ObservationsForEntity(ctx context.Context, entityID uuid.UUID) ([]domain.Observation, error)

	// RelationshipsForEntity returns relationships for an entity.
	RelationshipsForEntity(ctx context.Context, entityID uuid.UUID, direction domain.Direction) ([]domain.Relationship, error)

	// EntityByTypeAndValue looks up a specific entity by type + canonical value.
	EntityByTypeAndValue(ctx context.Context, entityType domain.EntityType, value string, projectID uuid.UUID) (*domain.Entity, error)
}

// WriteStore persists correlations and materializes relationships.
type WriteStore interface {
	// UpsertCorrelation creates or updates a correlation.
	// Identity key: Type + sorted EntityIDs + RuleName.
	// On match: updates LastSeenAt and appends new ObservationIDs.
	// On new: creates fresh correlation.
	UpsertCorrelation(ctx context.Context, c domain.Correlation) (*domain.Correlation, error)

	// MaterializeRelationship creates a graph relationship from
	// a correlation. This bridges Correlation → Knowledge Graph.
	MaterializeRelationship(ctx context.Context, rel domain.Relationship) error
}

// Engine runs deterministic correlation rules against the Knowledge Graph.
type Engine struct {
	read   ReadStore
	write  WriteStore
	rules  []Rule
	logger *slog.Logger
}

// NewEngine creates a new Correlation Engine.
func NewEngine(read ReadStore, write WriteStore, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		read:   read,
		write:  write,
		rules:  make([]Rule, 0),
		logger: logger,
	}
}

// RegisterRule adds a correlation rule.
func (e *Engine) RegisterRule(r Rule) {
	for _, existing := range e.rules {
		if existing.Name() == r.Name() {
			panic("correlation: duplicate rule: " + r.Name())
		}
	}
	e.rules = append(e.rules, r)
	e.logger.Info("correlation rule registered", "rule", r.Name())
}

// RunAll evaluates all registered rules and persists discovered correlations.
// Returns the total number of new or updated correlations.
func (e *Engine) RunAll(ctx context.Context) (int, error) {
	total := 0
	for _, rule := range e.rules {
		n, err := e.runRule(ctx, rule)
		if err != nil {
			e.logger.Error("correlation rule failed",
				"rule", rule.Name(),
				"error", err,
			)
			continue // Don't let one failed rule stop others.
		}
		total += n
	}
	return total, nil
}

// RunRule evaluates a single named rule.
func (e *Engine) RunRule(ctx context.Context, ruleName string) (int, error) {
	for _, rule := range e.rules {
		if rule.Name() == ruleName {
			return e.runRule(ctx, rule)
		}
	}
	return 0, fmt.Errorf("correlation: unknown rule: %s", ruleName)
}

// RuleNames returns the names of all registered rules.
func (e *Engine) RuleNames() []string {
	names := make([]string, len(e.rules))
	for i, r := range e.rules {
		names[i] = r.Name()
	}
	return names
}

func (e *Engine) runRule(ctx context.Context, rule Rule) (int, error) {
	start := time.Now()

	candidates, err := rule.Evaluate(ctx, e.read)
	if err != nil {
		return 0, fmt.Errorf("rule %s: %w", rule.Name(), err)
	}

	persisted := 0
	for _, candidate := range candidates {
		// Ensure rule name is set.
		candidate.RuleName = rule.Name()

		// Persist (upsert handles deduplication).
		result, err := e.write.UpsertCorrelation(ctx, candidate)
		if err != nil {
			e.logger.Error("failed to persist correlation",
				"rule", rule.Name(),
				"type", candidate.Type,
				"error", err,
			)
			continue
		}

		persisted++

		e.logger.Info("correlation persisted",
			"rule", rule.Name(),
			"type", candidate.Type,
			"entity_count", len(result.EntityIDs),
			"observation_count", len(result.ObservationIDs),
		)
	}

	e.logger.Info("correlation rule completed",
		"rule", rule.Name(),
		"candidates", len(candidates),
		"persisted", persisted,
		"duration", time.Since(start),
	)

	return persisted, nil
}

// CorrelationIdentityKey computes the deduplication key for a correlation.
// Identity: Type + sorted EntityIDs + RuleName.
func CorrelationIdentityKey(c domain.Correlation) string {
	ids := make([]string, len(c.EntityIDs))
	for i, id := range c.EntityIDs {
		ids[i] = id.String()
	}
	sort.Strings(ids)
	return fmt.Sprintf("%s:%s:%s", c.Type, c.RuleName, strings.Join(ids, ","))
}
