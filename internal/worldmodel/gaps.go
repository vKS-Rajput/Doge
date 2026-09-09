package worldmodel

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	privilegedRouteRegex = regexp.MustCompile(`/(?:admin|internal|manager|management|dashboard|superadmin|root|system|debug|actuator|metrics|metrics/prometheus|v1/management)`)
)

// ResearchGapDetector inspects the relational WorldModel graph to discover unanswered research questions and security uncertainties.
type ResearchGapDetector struct {
	wm *WorldModel
}

// NewResearchGapDetector creates a new gap detector for the world model.
func NewResearchGapDetector(wm *WorldModel) *ResearchGapDetector {
	return &ResearchGapDetector{wm: wm}
}

// DetectGaps scans all entities, objects, endpoints, and transitions in the world model to surface active research gaps.
func (d *ResearchGapDetector) DetectGaps() []*ResearchGap {
	if d.wm == nil {
		return nil
	}

	d.wm.mu.RLock()
	endpoints := make([]*EndpointModel, 0, len(d.wm.endpoints))
	for _, ep := range d.wm.endpoints {
		endpoints = append(endpoints, ep)
	}
	objects := make([]*ObjectResource, 0, len(d.wm.objects))
	for _, obj := range d.wm.objects {
		objects = append(objects, obj)
	}
	parameters := make([]*ParameterModel, 0, len(d.wm.parameters))
	for _, p := range d.wm.parameters {
		parameters = append(parameters, p)
	}
	transitions := make([]*StateTransition, len(d.wm.transitions))
	copy(transitions, d.wm.transitions)
	principals := make([]*Principal, 0, len(d.wm.principals))
	for _, p := range d.wm.principals {
		principals = append(principals, p)
	}
	existingGaps := make(map[string]bool)
	for _, g := range d.wm.gaps {
		if g.Status == GapStatusOpen || g.Status == GapStatusInvestigating {
			for _, ep := range g.AffectedEndpoints {
				existingGaps[fmt.Sprintf("%s:%s", g.Type, ep)] = true
			}
		}
	}
	d.wm.mu.RUnlock()

	var detected []*ResearchGap

	// 1. Detect GapUnknownTenantIsolation & GapUnknownObjectOwnership on Object Resources
	for _, obj := range objects {
		targetURL := obj.EndpointURL
		if targetURL == "" {
			continue
		}
		gapKey := fmt.Sprintf("%s:%s", GapUnknownTenantIsolation, targetURL)
		if existingGaps[gapKey] {
			continue
		}

		gap := &ResearchGap{
			ID:                uuid.New(),
			Type:              GapUnknownTenantIsolation,
			Description:       fmt.Sprintf("Tenant isolation and horizontal object authorization boundary unverified for object %s (%s)", obj.Identifier, targetURL),
			Uncertainty:       0.85,
			AffectedEntityIDs: []uuid.UUID{obj.ID},
			AffectedEndpoints: []string{targetURL},
			Evidence:          []string{fmt.Sprintf("Discovered addressable object resource %s in path", obj.Identifier)},
			ExpectedInfoGain:  0.90,
			Risk:              "medium",
			Cost:              1.5,
			Status:            GapStatusOpen,
			DiscoveredAt:      time.Now().UTC(),
			CandidateExperiments: []*CandidateExperiment{
				{
					ID:               uuid.New(),
					Title:            fmt.Sprintf("Cross-Tenant BOLA Probe on %s", obj.Identifier),
					Description:      "Send request with Tenant A credentials targeting Tenant B's object identifier and evaluate response status and payload",
					Tool:             "httpx",
					Command:          fmt.Sprintf("httpx -u %s -H 'X-Tenant-ID: secondary_tenant' -silent", targetURL),
					Target:           targetURL,
					ExpectedInfoGain: 0.90,
					Risk:             "medium",
					Cost:             1.5,
				},
			},
		}
		detected = append(detected, gap)
	}

	// 2. Detect GapUnknownPrivilegeBoundary on Privileged/Admin Routes
	for _, ep := range endpoints {
		targetURL := ep.URL
		if targetURL == "" {
			targetURL = fmt.Sprintf("https://%s%s", ep.Host, ep.Path)
		}

		if privilegedRouteRegex.MatchString(ep.Path) {
			gapKey := fmt.Sprintf("%s:%s", GapUnknownPrivilegeBoundary, targetURL)
			if existingGaps[gapKey] {
				continue
			}

			gap := &ResearchGap{
				ID:                uuid.New(),
				Type:              GapUnknownPrivilegeBoundary,
				Description:       fmt.Sprintf("Administrative and privileged route access boundary unverified for %s", targetURL),
				Uncertainty:       0.90,
				AffectedEntityIDs: []uuid.UUID{ep.ID},
				AffectedEndpoints: []string{targetURL},
				Evidence:          []string{fmt.Sprintf("Discovered administrative naming pattern in path: %s", ep.Path)},
				ExpectedInfoGain:  0.85,
				Risk:              "low",
				Cost:              1.0,
				Status:            GapStatusOpen,
				DiscoveredAt:      time.Now().UTC(),
				CandidateExperiments: []*CandidateExperiment{
					{
						ID:               uuid.New(),
						Title:            fmt.Sprintf("Unauthenticated Privilege Probe on %s", ep.Path),
						Description:      "Issue unauthenticated request to inspect status codes (401/403 vs 200/302)",
						Tool:             "httpx",
						Command:          fmt.Sprintf("httpx -u %s -status-code -silent", targetURL),
						Target:           targetURL,
						ExpectedInfoGain: 0.85,
						Risk:             "low",
						Cost:             1.0,
					},
				},
			}
			detected = append(detected, gap)
		}
	}

	// 3. Detect GapUnknownExternalInteraction on URL/Webhook Parameters
	for _, param := range parameters {
		if param.IsURLParameter {
			gapKey := fmt.Sprintf("%s:%s", GapUnknownExternalInteraction, param.Name)
			if existingGaps[gapKey] {
				continue
			}

			gap := &ResearchGap{
				ID:                uuid.New(),
				Type:              GapUnknownExternalInteraction,
				Description:       fmt.Sprintf("External fetch and egress callback validation unverified for parameter %q", param.Name),
				Uncertainty:       0.80,
				AffectedEntityIDs: []uuid.UUID{param.ID},
				AffectedEndpoints: []string{param.Name},
				Evidence:          []string{fmt.Sprintf("Discovered URL-like parameter name: %s", param.Name)},
				ExpectedInfoGain:  0.88,
				Risk:              "high",
				Cost:              2.0,
				Status:            GapStatusOpen,
				DiscoveredAt:      time.Now().UTC(),
				CandidateExperiments: []*CandidateExperiment{
					{
						ID:               uuid.New(),
						Title:            fmt.Sprintf("OOB Interaction Check on %s", param.Name),
						Description:      "Submit controlled out-of-band listener target to parameter and monitor for DNS/HTTP interaction",
						Tool:             "httpx",
						Command:          fmt.Sprintf("httpx -u https://%s/?%s=http://listener.doge-oob.net -silent", d.wm.target, param.Name),
						Target:           d.wm.target,
						ExpectedInfoGain: 0.88,
						Risk:             "high",
						Cost:             2.0,
					},
				},
			}
			detected = append(detected, gap)
		}
	}

	// 4. Detect GapUnknownWorkflowTransition on State Transitions
	for _, st := range transitions {
		gapKey := fmt.Sprintf("%s:%s->%s", GapUnknownWorkflowTransition, st.FromState, st.ToState)
		if existingGaps[gapKey] {
			continue
		}

		gap := &ResearchGap{
			ID:                uuid.New(),
			Type:              GapUnknownWorkflowTransition,
			Description:       fmt.Sprintf("Workflow state transition integrity and prerequisite enforcement unverified for %s -> %s (%s)", st.FromState, st.ToState, st.ActionName),
			Uncertainty:       0.75,
			AffectedEntityIDs: []uuid.UUID{st.ID},
			AffectedEndpoints: []string{st.ActionName},
			Evidence:          []string{fmt.Sprintf("Registered workflow transition action %s", st.ActionName)},
			ExpectedInfoGain:  0.78,
			Risk:              "medium",
			Cost:              1.5,
			Status:            GapStatusOpen,
			DiscoveredAt:      time.Now().UTC(),
			CandidateExperiments: []*CandidateExperiment{
				{
					ID:               uuid.New(),
					Title:            fmt.Sprintf("Out-of-Order Transition Probe on %s", st.ActionName),
					Description:      "Attempt to trigger state change without satisfying prerequisites",
					Tool:             "httpx",
					Command:          fmt.Sprintf("httpx -u https://%s/api/workflow/%s -X POST -silent", d.wm.target, strings.ToLower(st.ActionName)),
					Target:           d.wm.target,
					ExpectedInfoGain: 0.78,
					Risk:             "medium",
					Cost:             1.5,
				},
			},
		}
		detected = append(detected, gap)
	}

	return detected
}
