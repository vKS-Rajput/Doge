package hypothesis

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Engine manages the generation, evaluation, and lifecycle of research hypotheses.
type Engine struct {
	mu          sync.RWMutex
	hypotheses  map[uuid.UUID]*ResearchHypothesis
	targetIndex map[string][]uuid.UUID
}

// NewEngine creates a new Hypothesis Engine.
func NewEngine() *Engine {
	return &Engine{
		hypotheses:  make(map[uuid.UUID]*ResearchHypothesis),
		targetIndex: make(map[string][]uuid.UUID),
	}
}

var (
	// BOLA / IDOR identifier patterns in URL paths: /api/users/123, /orders/3fa85f64-5717-4562-b3fc-2c963f66afa6
	idInPathRegex = regexp.MustCompile(`/(?:users|accounts|profiles|orders|items|files|documents|invoices|messages|conversations|orgs|organizations|teams)/([0-9a-fA-F-]{4,36}|\d+)`)

	// Sensitive / Privileged routes
	privilegedRouteRegex = regexp.MustCompile(`/(?:admin|internal|manager|management|dashboard|superadmin|root|system|debug|actuator|metrics|metrics/prometheus|v1/management)`)

	// SSRF / URL Ingestion parameter names
	ssrfParamRegex = regexp.MustCompile(`(?i)^(?:url|uri|dest|dest_url|destination|redirect|redirect_to|next|callback|webhook|webhook_url|feed|proxy|source|source_url|target_url|load_url|fetch|fetch_url|image_url|avatar_url|endpoint|endpoint_url|redirect_url|return_url|site|path|out|outgoing|forward|forward_url|open|link|goto|continue|service|service_url|host|remote)$`)

	// CORS reflection
	corsOriginRegex = regexp.MustCompile(`(?i)access-control-allow-origin:\s*(\*|https?://[^\s]+)`)
)

// AnalyzeEvidence scans the knowledge graph entities and observations to generate hypotheses.
func (e *Engine) AnalyzeEvidence(ctx context.Context, entities []domain.Entity, relationships []domain.Relationship, observations []domain.Observation) []*ResearchHypothesis {
	e.mu.Lock()
	defer e.mu.Unlock()

	var newOrUpdated []*ResearchHypothesis
	now := time.Now().UTC()

	// Map observations by checksum and raw value
	obsByTool := make(map[string][]domain.Observation)
	for _, obs := range observations {
		obsByTool[obs.SourceTool] = append(obsByTool[obs.SourceTool], obs)
	}

	// 1. Detect BOLA / IDOR Hypotheses
	for _, ent := range entities {
		if ent.Type == domain.EntityEndpoint || ent.Type == domain.EntityURL {
			val := ent.Value
			if matches := idInPathRegex.FindStringSubmatch(val); len(matches) == 2 {
				objID := matches[1]
				target := extractTarget(val)
				title := fmt.Sprintf("Object Identifier Exposure in Path (%s)", objID)

				hyp := e.findOrCreateHypothesis(target, CatBOLA, title, func() *ResearchHypothesis {
					return &ResearchHypothesis{
						ID:        uuid.New(),
						Title:     title,
						Statement: fmt.Sprintf("Endpoint %s contains resource identifier %s. If object-level access controls are client-controlled without server-side tenant validation, horizontal authorization bypass (BOLA/IDOR) is plausible.", val, objID),
						Target:    target,
						Tier:      TierHypothesis,
						Status:    StatusUnvalidated,
						Category:  CatBOLA,
						Confidence: 0.65,
						SupportingEvidence: []EvidenceRef{
							{
								SourceTool:  "doge_materializer",
								Description: fmt.Sprintf("Observed object-like identifier %s in endpoint %s", objID, val),
								RawValue:    val,
							},
						},
						ValidationSteps: []ValidationRequirement{
							{
								StepNumber:         1,
								ActionDescription:  "Submit request to endpoint with authorized User A context and verify baseline response",
								ExpectedProof:      "200 OK with User A data",
								RequiresScopeCheck: true,
								RequiresHumanGate:  false,
							},
							{
								StepNumber:         2,
								ActionDescription:  "Submit request to endpoint targeting User B's object ID using User A credentials",
								ExpectedProof:      "200 OK with User B private data (Confirms BOLA) vs 401/403/404 (Refutes BOLA)",
								RefutationProof:    "403 Forbidden or 404 Not Found enforcing tenant boundary",
								RequiresScopeCheck: true,
								RequiresHumanGate:  true,
							},
						},
						RefutationCriteria:   "Server returns 401/403/404 and strictly denies cross-tenant resource access",
						ConfirmationCriteria: "Server returns 200 OK containing unauthorized tenant data without administrative privileges",
						FirstObservedAt:      now,
						LastEvaluatedAt:      now,
					}
				})
				newOrUpdated = append(newOrUpdated, hyp)
			}
		}
	}

	// 2. Detect Sensitive / Privileged Admin Surface Hypotheses
	for _, ent := range entities {
		if ent.Type == domain.EntityEndpoint || ent.Type == domain.EntityURL {
			val := ent.Value
			if privilegedRouteRegex.MatchString(val) {
				target := extractTarget(val)
				title := fmt.Sprintf("Privileged Route Exposure (%s)", val)

				hyp := e.findOrCreateHypothesis(target, CatAuthBoundary, title, func() *ResearchHypothesis {
					return &ResearchHypothesis{
						ID:        uuid.New(),
						Title:     title,
						Statement: fmt.Sprintf("Privileged path %s is exposed on external surface. Potential risk of authentication bypass, missing role check, or sensitive administrative functionality access.", val),
						Target:    target,
						Tier:      TierHypothesis,
						Status:    StatusUnvalidated,
						Category:  CatAuthBoundary,
						Confidence: 0.60,
						SupportingEvidence: []EvidenceRef{
							{
								SourceTool:  "doge_surface",
								Description: fmt.Sprintf("Discovered administrative route: %s", val),
								RawValue:    val,
							},
						},
						ValidationSteps: []ValidationRequirement{
							{
								StepNumber:         1,
								ActionDescription:  "Check HTTP status code and response body for unauthenticated requests",
								ExpectedProof:      "401 Unauthorized / 302 Redirect to Login (Refutes public access)",
								RefutationProof:    "Strict auth redirect or 403 Forbidden",
								RequiresScopeCheck: true,
								RequiresHumanGate:  false,
							},
							{
								StepNumber:         2,
								ActionDescription:  "Test alternate HTTP methods (GET, POST, PUT, OPTIONS, HEAD) for access control inconsistencies",
								ExpectedProof:      "Differential access allowing unauthorized actions",
								RefutationProof:    "Uniform rejection across all methods",
								RequiresScopeCheck: true,
								RequiresHumanGate:  true,
							},
						},
						RefutationCriteria:   "Route strictly requires authenticated high-privilege session across all verbs",
						ConfirmationCriteria: "Route allows unauthenticated or low-privilege execution of administrative operations",
						FirstObservedAt:      now,
						LastEvaluatedAt:      now,
					}
				})
				newOrUpdated = append(newOrUpdated, hyp)
			}
		}
	}

	// 3. Detect SSRF / URL Ingestion Parameters
	for _, ent := range entities {
		var paramName string
		var target string
		var rawVal string

		if ent.Type == domain.EntityParameter {
			if ssrfParamRegex.MatchString(ent.Value) {
				paramName = ent.Value
				if host, ok := ent.Attributes["host"].(string); ok {
					target = host
				}
				rawVal = ent.Value
			}
		} else if ent.Type == domain.EntityEndpoint || ent.Type == domain.EntityURL {
			if strings.Contains(ent.Value, "?") {
				parts := strings.SplitN(ent.Value, "?", 2)
				queryParams := strings.Split(parts[1], "&")
				for _, qp := range queryParams {
					kv := strings.SplitN(qp, "=", 2)
					pKey := kv[0]
					if ssrfParamRegex.MatchString(pKey) {
						paramName = pKey
						target = extractTarget(ent.Value)
						rawVal = ent.Value
						break
					}
				}
			}
		}

		if paramName != "" {
			title := fmt.Sprintf("URL Ingestion Parameter (%s) on %s", paramName, rawVal)
			hyp := e.findOrCreateHypothesis(target, CatSSRF, title, func() *ResearchHypothesis {
				return &ResearchHypothesis{
					ID:        uuid.New(),
					Title:     title,
					Statement: fmt.Sprintf("Parameter %q on %s accepts URL/destination inputs. If server fetches external or internal resources without strict DNS validation and IP egress controls, SSRF or open redirect is plausible.", paramName, rawVal),
					Target:    target,
					Tier:      TierHypothesis,
					Status:    StatusUnvalidated,
					Category:  CatSSRF,
					Confidence: 0.55,
					SupportingEvidence: []EvidenceRef{
						{
							SourceTool:  "doge_surface",
							Description: fmt.Sprintf("Discovered URL-like parameter %q on %s", paramName, rawVal),
							RawValue:    rawVal,
						},
					},
					ValidationSteps: []ValidationRequirement{
						{
							StepNumber:         1,
							ActionDescription:  "Check if server accepts external domain callback / webhook parameter",
							ExpectedProof:      "Out-of-band DNS/HTTP interaction from server IP",
							RequiresScopeCheck: true,
							RequiresHumanGate:  true,
						},
					},
					RefutationCriteria:   "Server strictly validates whitelist of allowable domains or rejects remote URL fetching",
					ConfirmationCriteria: "Server initiates network connections to arbitrary external or internal IP addresses based on user parameter",
					FirstObservedAt:      now,
					LastEvaluatedAt:      now,
				}
			})
			newOrUpdated = append(newOrUpdated, hyp)
		}
	}

	// 4. Detect Novel Behavioral Anomalies (Combinations of observations)
	var authObs []domain.Observation
	var reflObs []domain.Observation
	for _, obs := range observations {
		if obs.Type == domain.ObservationAuthProbe || strings.Contains(obs.RawValue, "Bearer") || strings.Contains(obs.RawValue, "JWT") {
			authObs = append(authObs, obs)
		}
		if obs.Type == domain.ObservationEndpointDiscovery {
			if _, ok := obs.Data["reflection"]; ok {
				reflObs = append(reflObs, obs)
			}
		}
	}

	if len(authObs) > 0 && len(reflObs) > 0 {
		target := observations[0].SourceTool
		title := "Reflected Input in Authenticated Context"
		hyp := e.findOrCreateHypothesis(target, CatNovelAnomaly, title, func() *ResearchHypothesis {
			return &ResearchHypothesis{
				ID:        uuid.New(),
				Title:     title,
				Statement: "Discovered reflected parameter input within an authenticated API surface. Could lead to session-bound XSS or CSRF state confusion.",
				Target:    target,
				Tier:      TierHypothesis,
				Status:    StatusUnvalidated,
				Category:  CatNovelAnomaly,
				Confidence: 0.58,
				SupportingEvidence: []EvidenceRef{
					{
						SourceTool:  "doge_correlation",
						Description: "Correlated parameter reflection with authenticated session context",
					},
				},
				ValidationSteps: []ValidationRequirement{
					{
						StepNumber:         1,
						ActionDescription:  "Verify contextual encoding of reflected characters (quotes, angle brackets, javascript delimiters)",
						ExpectedProof:      "Unencoded reflection in script or DOM execution context",
						RefutationProof:    "HTML/JSON entity encoding applied safely",
						RequiresScopeCheck: true,
						RequiresHumanGate:  false,
					},
				},
				RefutationCriteria:   "Input is strictly encoded or sanitized before reflection in browser DOM",
				ConfirmationCriteria: "Arbitrary script executes in context of authenticated user session",
				FirstObservedAt:      now,
				LastEvaluatedAt:      now,
			}
		})
		newOrUpdated = append(newOrUpdated, hyp)
	}

	// 5. Detect Subdomain Attack Surface Patterns
	for _, ent := range entities {
		if ent.Type == domain.EntitySubdomain || ent.Type == domain.EntityDomain {
			sub := strings.ToLower(ent.Value)

			// QA / Branch / Staging Environments
			if strings.Contains(sub, "qa-") || strings.Contains(sub, "branch") || strings.Contains(sub, "trunk") || strings.Contains(sub, "test-") || strings.Contains(sub, "staging") {
				title := fmt.Sprintf("Pre-Production Staging Surface (%s)", sub)
				hyp := e.findOrCreateHypothesis(sub, CatAuthBoundary, title, func() *ResearchHypothesis {
					return &ResearchHypothesis{
						ID:        uuid.New(),
						Title:     title,
						Statement: fmt.Sprintf("Subdomain %s indicates a pre-production/QA staging environment. Staging assets typically exhibit weaker authentication boundaries, debug endpoints, or legacy API endpoints.", sub),
						Target:    sub,
						Tier:      TierHypothesis,
						Status:    StatusUnvalidated,
						Category:  CatAuthBoundary,
						Confidence: 0.70,
						SupportingEvidence: []EvidenceRef{
							{
								SourceTool:  "doge_materializer",
								Description: fmt.Sprintf("Identified pre-production staging naming pattern in host %s", sub),
								RawValue:    sub,
							},
						},
						ValidationSteps: []ValidationRequirement{
							{
								StepNumber:         1,
								ActionDescription:  "Perform passive banner probe and inspect response headers for debug/staging flags",
								ExpectedProof:      "Staging/QA indicators in headers or response body",
								RefutationProof:    "Production-grade hardened configuration with strict access control",
								RequiresScopeCheck: true,
								RequiresHumanGate:  false,
							},
							{
								StepNumber:         2,
								ActionDescription:  "Verify whether authentication endpoints on staging accept test/default credentials or bypass MFA",
								ExpectedProof:      "Differential authentication policies vs production",
								RefutationProof:    "Identical zero-trust SSO enforcement",
								RequiresScopeCheck: true,
								RequiresHumanGate:  true,
							},
						},
						RefutationCriteria:   "Staging host enforces identical zero-trust authentication and does not leak debug functionality",
						ConfirmationCriteria: "Staging host exposes internal APIs, debug panels, or bypassable authentication",
						FirstObservedAt:      now,
						LastEvaluatedAt:      now,
					}
				})
				newOrUpdated = append(newOrUpdated, hyp)
			}

			// Authentication Gateways
			if strings.HasPrefix(sub, "auth.") || strings.HasPrefix(sub, "login.") || strings.HasPrefix(sub, "sso.") || strings.HasPrefix(sub, "oauth.") {
				title := fmt.Sprintf("Centralized Authentication Gateway (%s)", sub)
				hyp := e.findOrCreateHypothesis(sub, CatAuthBoundary, title, func() *ResearchHypothesis {
					return &ResearchHypothesis{
						ID:        uuid.New(),
						Title:     title,
						Statement: fmt.Sprintf("Host %s serves as a centralized identity/authentication gateway. Critical attack surface for OAuth redirect manipulation, token leakage, or SAML/OIDC misconfigurations.", sub),
						Target:    sub,
						Tier:      TierHypothesis,
						Status:    StatusUnvalidated,
						Category:  CatAuthBoundary,
						Confidence: 0.75,
						SupportingEvidence: []EvidenceRef{
							{
								SourceTool:  "doge_materializer",
								Description: fmt.Sprintf("Identified identity provider service endpoint: %s", sub),
								RawValue:    sub,
							},
						},
						ValidationSteps: []ValidationRequirement{
							{
								StepNumber:         1,
								ActionDescription:  "Map OAuth/OIDC client redirect URI validation on authorization endpoints",
								ExpectedProof:      "Acceptance of arbitrary or subdomain-wildcard redirect_uri parameters",
								RefutationProof:    "Strict exact-match redirect_uri validation",
								RequiresScopeCheck: true,
								RequiresHumanGate:  false,
							},
						},
						RefutationCriteria:   "Auth gateway strictly validates exact redirect URIs and signs all state tokens",
						ConfirmationCriteria: "Auth gateway permits open redirects or leaks authorization codes/tokens cross-domain",
						FirstObservedAt:      now,
						LastEvaluatedAt:      now,
					}
				})
				newOrUpdated = append(newOrUpdated, hyp)
			}

			// IoT Edge & Message Broker Services
			if strings.HasPrefix(sub, "edge.") || strings.HasPrefix(sub, "push.") || strings.HasPrefix(sub, "mq.") || strings.HasPrefix(sub, "lw.") {
				title := fmt.Sprintf("IoT Edge & Messaging Infrastructure (%s)", sub)
				hyp := e.findOrCreateHypothesis(sub, CatNovelAnomaly, title, func() *ResearchHypothesis {
					return &ResearchHypothesis{
						ID:        uuid.New(),
						Title:     title,
						Statement: fmt.Sprintf("Host %s provides IoT edge telemetry, LwM2M, or message broker capabilities. Risk of unauthenticated device registration, unauthorized broker pub/sub, or message injection.", sub),
						Target:    sub,
						Tier:      TierHypothesis,
						Status:    StatusUnvalidated,
						Category:  CatNovelAnomaly,
						Confidence: 0.65,
						SupportingEvidence: []EvidenceRef{
							{
								SourceTool:  "doge_materializer",
								Description: fmt.Sprintf("Identified IoT edge/message broker host: %s", sub),
								RawValue:    sub,
							},
						},
						ValidationSteps: []ValidationRequirement{
							{
								StepNumber:         1,
								ActionDescription:  "Probe open broker ports (MQTT 1883/8883, LwM2M CoAP 5683/5684, AMQP 5672) and test authentication requirement",
								ExpectedProof:      "Broker accepts anonymous connections or default credentials",
								RefutationProof:    "Mutual TLS / strict device token authentication required",
								RequiresScopeCheck: true,
								RequiresHumanGate:  true,
							},
						},
						RefutationCriteria:   "Edge/broker service enforces mutual TLS or cryptographically verified device tokens",
						ConfirmationCriteria: "Anonymous access allows publishing/subscribing to device telemetry channels",
						FirstObservedAt:      now,
						LastEvaluatedAt:      now,
					}
				})
				newOrUpdated = append(newOrUpdated, hyp)
			}
		}
	}

	return newOrUpdated
}

// ListHypotheses returns all hypotheses currently tracked.
func (e *Engine) ListHypotheses() []*ResearchHypothesis {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]*ResearchHypothesis, 0, len(e.hypotheses))
	for _, h := range e.hypotheses {
		list = append(list, h)
	}
	return list
}

// AddHypothesis registers a hypothesis directly in the engine.
func (e *Engine) AddHypothesis(h *ResearchHypothesis) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hypotheses[h.ID] = h
	if h.Target != "" {
		e.targetIndex[h.Target] = append(e.targetIndex[h.Target], h.ID)
	}
}

// GetHypothesis retrieves a single hypothesis by ID.
func (e *Engine) GetHypothesis(id uuid.UUID) (*ResearchHypothesis, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	h, ok := e.hypotheses[id]
	return h, ok
}

// UpdateHypothesisStatus updates the epistemic status of a hypothesis.
func (e *Engine) UpdateHypothesisStatus(id uuid.UUID, status EpistemicStatus, notes string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	h, ok := e.hypotheses[id]
	if !ok {
		return fmt.Errorf("hypothesis %s not found", id)
	}

	h.Status = status
	h.Notes = notes
	now := time.Now().UTC()

	switch status {
	case StatusConfirmed:
		h.Tier = TierValidatedFinding
		h.Confidence = 1.0
		h.ConfirmedAt = &now
	case StatusRejected:
		h.Tier = TierHypothesis
		h.Confidence = 0.0
		h.RejectedAt = &now
	case StatusContradicted:
		h.ContradictionCount++
		h.RecalculateConfidence(false)
	case StatusSupported:
		h.Tier = TierCandidateFinding
		h.RecalculateConfidence(true)
	}

	return nil
}

func (e *Engine) findOrCreateHypothesis(target string, cat Category, title string, createFn func() *ResearchHypothesis) *ResearchHypothesis {
	// Look for existing hypothesis by target + category + title
	for _, h := range e.hypotheses {
		if h.Category == cat && h.Title == title && (h.Target == target || target == "") {
			h.RecalculateConfidence(true)
			return h
		}
	}

	h := createFn()
	e.hypotheses[h.ID] = h
	if target != "" {
		e.targetIndex[target] = append(e.targetIndex[target], h.ID)
	}
	return h
}

func extractTarget(raw string) string {
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	parts := strings.Split(raw, "/")
	return parts[0]
}
