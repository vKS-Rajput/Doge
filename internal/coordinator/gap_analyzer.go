package coordinator

import (
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/attackgraph"
	"github.com/vKS-Rajput/doge/internal/property"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Gap represents a research opportunity discovered by analysing the world model
// and the set of security properties.
type Gap struct {
	Property  *property.SecurityProperty // the property that is currently untested/unknown
	Priority  float64                    // estimated information-gain score (higher = more urgent)
	Reason    string                     // human-readable explanation of why this gap matters
	Target    string                     // optional target asset (e.g. endpoint URL) the property applies to
	CreatedAt time.Time
}

// AnalyseGaps inspects the property evaluator and world model to produce ranked gaps.
func AnalyseGaps(eval *property.Evaluator, wm *worldmodel.WorldModel) []Gap {
	if eval == nil {
		return nil
	}
	var gaps []Gap
	now := time.Now().UTC()

	untested := eval.RankedUntested()
	for _, prop := range untested {
		priority := prop.Priority
		if priority <= 0 {
			priority = propertySeverityScore(prop)
		}
		target := prop.Subject
		gaps = append(gaps, Gap{
			Property:  prop,
			Priority:  priority,
			Reason:    "Untested security property: " + prop.Statement,
			Target:    target,
			CreatedAt: now,
		})
	}

	sort.Slice(gaps, func(i, j int) bool {
		return gaps[i].Priority > gaps[j].Priority
	})
	return gaps
}

// propertySeverityScore returns a normalized score (0-1) based on the property class.
func propertySeverityScore(p *property.SecurityProperty) float64 {
	switch p.Class {
	case property.ClassAuthorization, property.ClassIsolation, property.ClassPrivilegeContainment:
		return 1.0
	case property.ClassAuthentication, property.ClassSessionIntegrity, property.ClassWorkflowIntegrity:
		return 0.8
	case property.ClassSecretContainment, property.ClassServerSideSafety:
		return 0.7
	case property.ClassInputValidation, property.ClassTrustBoundary:
		return 0.5
	default:
		return 0.3
	}
}

// GenerateMissionsFromGaps converts gaps into MissionBriefs, scoring them by priority.
func GenerateMissionsFromGaps(gaps []Gap) []*domain.MissionBrief {
	var briefs []*domain.MissionBrief
	for _, g := range gaps {
		rtype := propertyToResearcher(g.Property)
		brief := &domain.MissionBrief{
			ID:              uuid.New(),
			ResearcherType:  rtype,
			Title:           "Validate property: " + g.Property.Statement,
			Description:     g.Reason,
			TargetBaseURL:   g.Target,
			Credentials:     nil,
			MaxRequests:     30,
			MaxDuration:     30 * time.Second,
			SuccessCriteria: "Property evaluated with confidence > 0.8",
		}
		briefs = append(briefs, brief)
	}
	return briefs
}

// propertyToResearcher maps a security property to an appropriate researcher implementation.
func propertyToResearcher(p *property.SecurityProperty) domain.ResearcherType {
	switch p.Class {
	case property.ClassAuthorization, property.ClassIsolation, property.ClassPrivilegeContainment:
		return domain.ResearcherAuthorization
	case property.ClassWorkflowIntegrity:
		return domain.ResearcherWorkflow
	case property.ClassInputValidation:
		return domain.ResearcherAnomaly
	default:
		return domain.ResearcherRecon
	}
}

// UpdateAttackGraphFromEvidence incorporates new evidence into the persistent attack graph.
func (c *ResearchCoordinator) UpdateAttackGraphFromEvidence(evidence []*domain.ExperimentEvidence) {
	if c.attackGraph == nil {
		return
	}
	for _, ev := range evidence {
		if ev.RequestURL != "" {
			node, exists := c.attackGraph.GetNodeByLabel(ev.RequestURL)
			if !exists || node == nil {
				node = c.attackGraph.AddNode(attackgraph.NodeResource, ev.RequestURL, "Discovered endpoint", 0.9)
			}
			if ev.IsAnomalous {
				vulnNode := c.attackGraph.AddNode(attackgraph.NodeWeakness, ev.Description, ev.Interpretation, 0.85)
				_, _ = c.attackGraph.AddEdge(node.ID, vulnNode.ID, attackgraph.EdgeLeadsTo, "exposes weakness", 0.85)
			}
		}
	}
}

