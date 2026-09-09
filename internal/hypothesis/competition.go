package hypothesis

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// CompetingCluster groups mutually competing explanations for an observed security surface.
type CompetingCluster struct {
	ID                       uuid.UUID                   `json:"id"`
	Title                    string                      `json:"title"`
	Target                   string                      `json:"target"`
	Observation              domain.Observation          `json:"observation"`
	Hypotheses               []*ResearchHypothesis       `json:"hypotheses"`
	DiscriminatingExperiments []*DiscriminatingExperiment `json:"discriminating_experiments"`
	CreatedAt                time.Time                   `json:"created_at"`
}

// GenerateCompetingHypotheses creates alternative competing explanations for an observation to prevent confirmation bias.
func GenerateCompetingHypotheses(target string, obs domain.Observation) *CompetingCluster {
	now := time.Now().UTC()
	cluster := &CompetingCluster{
		ID:          uuid.New(),
		Target:      target,
		Observation: obs,
		CreatedAt:   now,
	}

	raw := obs.RawValue

	// Scenario 1: Object ID exposure (/api/users/123, /orders/uuid)
	if obs.Type == domain.ObservationEndpointDiscovery && containsIDPattern(raw) {
		cluster.Title = fmt.Sprintf("Authorization Model for Object Endpoint (%s)", raw)

		// H1: Horizontal BOLA / IDOR vulnerability
		h1 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Horizontal BOLA on %s", raw),
			Statement: fmt.Sprintf("Endpoint %s references direct object ID. If authorization is client-side or missing tenant checks, cross-tenant access is possible.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatBOLA,
			Confidence: 0.65,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "Direct object identifier in endpoint path/parameter", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Issue differential cross-tenant request with User A credentials for User B resource", ExpectedProof: "200 OK with User B private data", RefutationProof: "403 Forbidden or 404 Not Found enforcing tenant isolation", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "403 Forbidden or 404 Not Found rejecting cross-tenant object ID access",
			ConfirmationCriteria: "200 OK returning unauthorized tenant data",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		// H2: Strict Server-Side Multi-Tenant Isolation
		h2 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Strict Multi-Tenant Isolation on %s", raw),
			Statement: fmt.Sprintf("Endpoint %s exposes object identifier, but server-side authorization middleware strictly validates session tenant context.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatAuthBoundary,
			Confidence: 0.50,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "Object ID exposed under standardized REST framework", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Verify tenant boundary rejection on ID mismatch", ExpectedProof: "403 Forbidden / 404 Not Found", RefutationProof: "200 OK with unauthorized data", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "200 OK revealing foreign tenant data",
			ConfirmationCriteria: "Consistent 403/404 rejection on cross-tenant ID access",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		// H3: Public Non-Sensitive Object
		h3 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Public Non-Sensitive Object on %s", raw),
			Statement: fmt.Sprintf("Endpoint %s serves publicly accessible shared metadata where ID access is unauthenticated or intentional.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatInformationLeak,
			Confidence: 0.35,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "Unauthenticated access may return static public content", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Compare unauthenticated vs authenticated response payload", ExpectedProof: "Identical public catalog payload without PII", RefutationProof: "Private tenant fields returned", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "Endpoint returns PII or tenant-scoped confidential state",
			ConfirmationCriteria: "Endpoint returns identical public catalog data regardless of authentication context",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		cluster.Hypotheses = []*ResearchHypothesis{h1, h2, h3}
		cluster.DiscriminatingExperiments = PlanDiscriminatingExperiments(cluster)
		return cluster
	}

	// Scenario 2: URL Ingestion parameter (url=https://...)
	if obs.Type == domain.ObservationEndpointDiscovery && containsURLParam(raw) {
		cluster.Title = fmt.Sprintf("URL Parameter Ingestion Handling on (%s)", raw)

		// H1: Server-Side Request Forgery (SSRF)
		h1 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("SSRF via Parameter on %s", raw),
			Statement: fmt.Sprintf("Endpoint parameter %s ingests remote URLs. Backend fetches remote target without strict loopback/internal IP egress filtering.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatSSRF,
			Confidence: 0.60,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "URL parameter observed in request surface", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Submit out-of-band callback URL and monitor DNS/HTTP ingress", ExpectedProof: "Out-of-band DNS/HTTP callback interaction", RefutationProof: "No connection or strict domain whitelist rejection", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "Parameter strictly rejected by whitelist or executed purely in client-side DOM",
			ConfirmationCriteria: "Server-side DNS resolution or HTTP request received on callback listener",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		// H2: Open Redirect Only
		h2 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Open Redirect on %s", raw),
			Statement: fmt.Sprintf("Endpoint %s returns HTTP 30x Location header pointing to input URL without server fetching the target itself.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatOpenRedirect,
			Confidence: 0.50,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "URL parameter name suggests navigation redirect", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Submit external redirect URL and inspect HTTP status code and Location header", ExpectedProof: "HTTP 301/302/307 with Location header", RefutationProof: "HTTP 200 or server-side fetch without redirect response", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "Server does not emit 30x redirect header with target URL",
			ConfirmationCriteria: "HTTP 30x response with untrusted host in Location header",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		// H3: Client-Side DOM Navigation Only
		h3 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Client-Side DOM Navigation on %s", raw),
			Statement: fmt.Sprintf("Parameter %s is consumed strictly client-side via JavaScript window.location or href without server-side HTTP action.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatClientSideURL,
			Confidence: 0.40,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "URL parameter observed on frontend single page application route", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Check server response headers and DOM sink for parameter reflection", ExpectedProof: "Parameter reflected in JavaScript navigation sink without backend egress", RefutationProof: "Server initiates backend network socket", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "Server performs backend network I/O or HTTP redirect",
			ConfirmationCriteria: "Client DOM script executes location redirect while server ignores parameter",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		// H4: Strictly Whitelisted URL Fetcher
		h4 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Strictly Whitelisted URL Fetcher on %s", raw),
			Statement: fmt.Sprintf("Endpoint %s accepts URLs but validates against an immutable hardcoded domain whitelist before issuing server requests.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatAuthBoundary,
			Confidence: 0.45,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "Backend fetches data from partner integrations", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Submit arbitrary domain and check rejection", ExpectedProof: "400 Bad Request domain not allowed", RefutationProof: "Egress callback received from arbitrary domain", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "Arbitrary untrusted domain successfully triggers egress",
			ConfirmationCriteria: "Rejection on all non-whitelisted domains with zero egress",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		// H5: Inert Parameter / Stored Metadata
		h5 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Inert Stored Metadata on %s", raw),
			Statement: fmt.Sprintf("Parameter %s is stored as inert metadata in database without server-side fetch or client-side execution.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatInformationLeak,
			Confidence: 0.30,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "Standard database field persistence", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Submit URL value and observe absence of network activity and redirect", ExpectedProof: "Value stored and echoed without side effects", RefutationProof: "Egress or redirect observed", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "Active network egress or redirect observed",
			ConfirmationCriteria: "Zero network egress, zero redirect, static persistence only",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		cluster.Hypotheses = []*ResearchHypothesis{h1, h2, h3, h4, h5}
		cluster.DiscriminatingExperiments = PlanDiscriminatingExperiments(cluster)
		return cluster
	}

	// Scenario 3: Sensitive / Privileged Admin Surface (/api/admin, /internal)
	if obs.Type == domain.ObservationEndpointDiscovery && privilegedRouteRegex.MatchString(raw) {
		cluster.Title = fmt.Sprintf("Access Control Model for Administrative Endpoint (%s)", raw)

		// H1: Vertical Privilege Escalation / Missing Role Check
		h1 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Vertical Privilege Escalation on %s", raw),
			Statement: fmt.Sprintf("Administrative route %s lacks server-side role check; standard user session can execute administrative functions.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatPrivilegeEsc,
			Confidence: 0.60,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "Administrative route discovered on external boundary", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Submit request using standard user credentials", ExpectedProof: "200 OK with admin response schema", RefutationProof: "403 Forbidden role enforced", RequiresScopeCheck: true, RequiresHumanGate: true},
			},
			RefutationCriteria:   "403 Forbidden properly enforcing admin role requirement",
			ConfirmationCriteria: "200 OK executing administrative action with standard user context",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		// H2: Authentication Bypass / Publicly Exposed Admin
		h2 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Unauthenticated Admin Access on %s", raw),
			Statement: fmt.Sprintf("Administrative route %s lacks authentication middleware entirely and is accessible without any credentials.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatAuthBoundary,
			Confidence: 0.45,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "Route exposed without apparent gate", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Submit unauthenticated HTTP request", ExpectedProof: "200 OK without session token", RefutationProof: "401 Unauthorized / 302 Login redirect", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "401 Unauthorized or 302 redirect to login",
			ConfirmationCriteria: "200 OK returned to unauthenticated client",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		// H3: Strict Role-Based Access Control (RBAC) Enforced
		h3 := &ResearchHypothesis{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Strict RBAC Enforcement on %s", raw),
			Statement: fmt.Sprintf("Administrative route %s strictly verifies caller's role and denies non-administrative principals.", raw),
			Target:    target,
			Tier:      TierHypothesis,
			Status:    StatusUnvalidated,
			Category:  CatAuthBoundary,
			Confidence: 0.55,
			SupportingEvidence: []EvidenceRef{
				{SourceTool: obs.SourceTool, Description: "Route defined behind enterprise API gateway", RawValue: raw},
			},
			ValidationSteps: []ValidationRequirement{
				{StepNumber: 1, ActionDescription: "Verify 401 on anonymous and 403 on standard user", ExpectedProof: "401/403 rejection", RefutationProof: "200 OK on low-privileged actor", RequiresScopeCheck: true, RequiresHumanGate: false},
			},
			RefutationCriteria:   "Low-privileged actor receives 200 OK",
			ConfirmationCriteria: "401/403 status returned to unauthorized principals",
			FirstObservedAt:      now,
			LastEvaluatedAt:      now,
		}

		cluster.Hypotheses = []*ResearchHypothesis{h1, h2, h3}
		cluster.DiscriminatingExperiments = PlanDiscriminatingExperiments(cluster)
		return cluster
	}

	return nil
}

// PlanDiscriminatingExperiments generates specific tests designed to rule in one hypothesis while ruling out another.
func PlanDiscriminatingExperiments(cluster *CompetingCluster) []*DiscriminatingExperiment {
	if cluster == nil || len(cluster.Hypotheses) < 2 {
		return nil
	}

	var experiments []*DiscriminatingExperiment

	// Pairwise experiment generation across top competing hypotheses
	for i := 0; i < len(cluster.Hypotheses)-1; i++ {
		hA := cluster.Hypotheses[i]
		hB := cluster.Hypotheses[i+1]

		exp := &DiscriminatingExperiment{
			ID:          uuid.New(),
			Title:       fmt.Sprintf("Discriminate %s vs %s", hA.Category, hB.Category),
			Description: fmt.Sprintf("Execute targeted test to distinguish whether target is %s (%s) or %s (%s)", hA.Category, hA.Title, hB.Category, hB.Title),
			HypothesisA: hA.ID,
			HypothesisB: hB.ID,
			Target:      cluster.Target,
			Risk:        "LOW",
			Cost:        1.5,
		}

		switch {
		case hA.Category == CatBOLA && hB.Category == CatAuthBoundary:
			exp.Command = fmt.Sprintf("doge_differential --url %s --mode bola --principal-a user1 --principal-b user2", cluster.Observation.RawValue)
			exp.ExpectedOutcomeA = "HTTP 200 with User A object data returned to User B session (Rules IN BOLA, Rules OUT Isolation)"
			exp.ExpectedOutcomeB = "HTTP 403/404 Forbidden returned to User B session (Rules OUT BOLA, Rules IN Isolation)"

		case hA.Category == CatSSRF && hB.Category == CatOpenRedirect:
			exp.Command = fmt.Sprintf("doge_ssrf_probe --url %s --param %s --oob-dns-listener $COLLAB_HOST", cluster.Target, cluster.Observation.RawValue)
			exp.ExpectedOutcomeA = "DNS/HTTP interaction received on OOB listener (Rules IN SSRF, Rules OUT Open Redirect)"
			exp.ExpectedOutcomeB = "HTTP 302 redirect header received with zero OOB interaction (Rules OUT SSRF, Rules IN Open Redirect)"

		case hA.Category == CatPrivilegeEsc && hB.Category == CatAuthBoundary:
			exp.Command = fmt.Sprintf("doge_auth_test --url %s --as standard_user", cluster.Observation.RawValue)
			exp.ExpectedOutcomeA = "HTTP 200 with administrative capabilities (Rules IN PrivEsc, Rules OUT RBAC)"
			exp.ExpectedOutcomeB = "HTTP 403 Forbidden access denied (Rules OUT PrivEsc, Rules IN RBAC)"

		default:
			exp.Command = fmt.Sprintf("doge_probe --target %s --param %s", cluster.Target, cluster.Observation.RawValue)
			exp.ExpectedOutcomeA = hA.ConfirmationCriteria
			exp.ExpectedOutcomeB = hB.ConfirmationCriteria
		}

		experiments = append(experiments, exp)
	}

	return experiments
}

func containsIDPattern(s string) bool {
	return idInPathRegex.MatchString(s)
}

func containsURLParam(s string) bool {
	return ssrfParamRegex.MatchString(s)
}
