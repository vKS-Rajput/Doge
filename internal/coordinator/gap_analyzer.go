package coordinator

import (
    "math"
    "time"

    "github.com/vKS-Rajput/doge/internal/property"
    "github.com/vKS-Rajput/doge/internal/worldmodel"
    "github.com/vKS-Rajput/doge/internal/attackgraph"
    "github.com/vKS-Rajput/doge/internal/domain"
)

// Gap represents a research opportunity discovered by analysing the world model
// and the set of security properties.
type Gap struct {
    Property   *property.SecurityProperty // the property that is currently untested/unknown
    Priority   float64                    // estimated information‑gain score (higher = more urgent)
    Reason     string                     // human‑readable explanation of why this gap matters
    Target     string                     // optional target asset (e.g. endpoint URL) the property applies to
    CreatedAt  time.Time
}

// AnalyseWorldModel inspects the world model and the property catalog to produce a slice of gaps.
func AnalyseWorldModel(wm *worldmodel.WorldModel, catalog *property.Catalog) []Gap {
    var gaps []Gap
    now := time.Now().UTC()

    // For every property in the catalog, check whether it has been evaluated for any asset.
    for _, prop := range catalog.All() {
        // prop can be of type Endpoint, Parameter, Authentication, etc.
        // We ask the world model whether there exists any asset that satisfies the property.
        // If the property is not yet evaluated, we create a gap.
        evaluated := wm.HasPropertyEvidence(prop.ID)
        if !evaluated {
            // Estimate a simple priority: more severe properties get higher score.
            severity := propertySeverityScore(prop)
            // If the property applies to a specific target (e.g., an endpoint), we try to retrieve one.
            target := ""
            if prop.TargetHint != "" {
                // Use world model to find a matching asset (first one for now).
                if asset := wm.FindAssetByHint(prop.TargetHint); asset != nil {
                    target = asset.Value
                }
            }
            gaps = append(gaps, Gap{
                Property:  prop,
                Priority:  severity,
                Reason:    "Untested security property: " + prop.Description,
                Target:    target,
                CreatedAt: now,
            })
        }
    }
    return gaps
}

// propertySeverityScore returns a normalized score (0‑1) based on the property category.
func propertySeverityScore(p *property.SecurityProperty) float64 {
    // The catalog defines a severity field (Critical, High, Medium, Low).
    switch p.Severity {
    case property.Critical:
        return 1.0
    case property.High:
        return 0.8
    case property.Medium:
        return 0.5
    case property.Low:
        return 0.3
    default:
        return 0.2
    }
}

// GenerateMissionsFromGaps converts gaps into MissionBriefs, scoring them by priority.
func GenerateMissionsFromGaps(gaps []Gap) []*domain.MissionBrief {
    var briefs []*domain.MissionBrief
    for _, g := range gaps {
        // Choose researcher type based on property type.
        rtype := propertyToResearcher(g.Property)
        brief := &domain.MissionBrief{
            ID:              uuid.New(),
            ResearcherType:  rtype,
            Title:           "Validate property: " + g.Property.Name,
            Description:     g.Reason,
            TargetBaseURL:   g.Target,
            Credentials:    nil,
            MaxRequests:    30,
            MaxDuration:    30 * time.Second,
            SuccessCriteria: "Property evaluated with confidence > 0.8",
        }
        briefs = append(briefs, brief)
    }
    // Simple sort by descending priority.
    sort.Slice(briefs, func(i, j int) bool {
        return gaps[i].Priority > gaps[j].Priority
    })
    return briefs
}

// propertyToResearcher maps a security property to an appropriate researcher implementation.
func propertyToResearcher(p *property.SecurityProperty) domain.ResearcherType {
    // Mapping based on property category.
    switch p.Category {
    case property.CategoryAuthorization:
        return domain.ResearcherAuthorization
    case property.CategoryAuthentication:
        return domain.ResearcherAuthBoundary
    case property.CategoryWorkflow:
        return domain.ResearcherWorkflow
    case property.CategoryInputValidation:
        return domain.ResearcherInput
    case property.CategorySecretLeakage:
        return domain.ResearcherSecret
    default:
        return domain.ResearcherRecon // fallback generic recon
    }
}

// UpdateAttackGraph incorporates new evidence (e.g., a discovered endpoint, a successful exploit)
// into the persistent attack graph.
func (c *ResearchCoordinator) UpdateAttackGraph(evidence []*domain.ExperimentEvidence) {
    for _, ev := range evidence {
        // Very simple translation: each evidence becomes a node/edge in the graph.
        // In a real system this would be far richer.
        src := ev.Source // e.g., "endpoint"
        dst := ev.Target // e.g., "privileged_resource"
        if src != "" && dst != "" {
            c.attackGraph.AddEdge(src, dst, attackgraph.EdgeMetadata{Score: ev.Confidence})
        }
    }
}
