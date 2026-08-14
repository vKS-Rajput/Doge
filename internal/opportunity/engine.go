package opportunity

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/novelty"
	"github.com/vKS-Rajput/doge/internal/surface"
)

// Generator converts novelty signals of a specific type into
// research opportunities with appropriate research questions.
type Generator interface {
	// Name returns the generator identifier.
	Name() string

	// CanGenerate returns true if this generator handles the signal.
	CanGenerate(signal novelty.Signal) bool

	// Generate produces research opportunities from the signal.
	Generate(ctx context.Context, signal novelty.Signal, projectID uuid.UUID) []Opportunity
}

// Engine converts novelty signals into prioritized research opportunities.
type Engine struct {
	generators []Generator
	logger     *slog.Logger
}

// NewEngine creates a new Research Opportunity Engine.
func NewEngine(logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		generators: make([]Generator, 0),
		logger:     logger,
	}
}

// RegisterGenerator adds an opportunity generator.
func (e *Engine) RegisterGenerator(g Generator) {
	e.generators = append(e.generators, g)
}

// GenerateAll converts novelty signals into research opportunities,
// sorted by priority.
func (e *Engine) GenerateAll(ctx context.Context, signals []novelty.Signal, projectID uuid.UUID) []Opportunity {
	var opportunities []Opportunity

	for _, signal := range signals {
		for _, gen := range e.generators {
			if gen.CanGenerate(signal) {
				opps := gen.Generate(ctx, signal, projectID)
				opportunities = append(opportunities, opps...)
			}
		}
	}

	// Sort by priority (critical first).
	sort.Slice(opportunities, func(i, j int) bool {
		return priorityRank(opportunities[i].Priority) > priorityRank(opportunities[j].Priority)
	})

	return opportunities
}

func priorityRank(p Priority) int {
	switch p {
	case PriorityCritical:
		return 4
	case PriorityHigh:
		return 3
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 1
	default:
		return 0
	}
}

// --- Upload Surface Generator ---

// UploadGenerator creates research opportunities for upload surfaces.
type UploadGenerator struct{}

func NewUploadGenerator() *UploadGenerator { return &UploadGenerator{} }

func (g *UploadGenerator) Name() string { return "upload" }

func (g *UploadGenerator) CanGenerate(s novelty.Signal) bool {
	return s.Type == novelty.SignalNewUploadSurface ||
		(s.Type == novelty.SignalNovelCombination && hasSurface(s, surface.CategoryUpload))
}

func (g *UploadGenerator) Generate(_ context.Context, signal novelty.Signal, projectID uuid.UUID) []Opportunity {
	target := extractTarget(signal)
	priority := signalToPriority(signal)

	return []Opportunity{{
		ID:          uuid.New(),
		Title:       fmt.Sprintf("Investigate upload functionality on %s", target),
		Target:      target,
		SurfaceType: surface.CategoryUpload,
		Description: fmt.Sprintf("Upload surface discovered on %s. Upload endpoints warrant investigation of accepted file types, validation, storage behavior, and access controls.", target),
		Questions: []ResearchQuestion{
			{
				Question:         "Is authentication required to access the upload endpoint?",
				Why:              "Unauthenticated upload endpoints allow anyone to submit content to the server.",
				ExpectedEvidence: "Authorized request succeeds; unauthenticated request is rejected with 401/403.",
				Effort:           "quick",
			},
			{
				Question:         "Is authorization enforced for upload functionality?",
				Why:              "Upload may be restricted to certain roles. Missing authorization allows privilege escalation.",
				ExpectedEvidence: "Different roles receive different upload permissions; unprivileged users are rejected.",
				Effort:           "moderate",
			},
			{
				Question:         "What file types are accepted?",
				Why:              "Unrestricted file types may allow executable upload. Server-side validation matters more than client-side.",
				ExpectedEvidence: "Server rejects dangerous file types; accepts only expected formats.",
				Effort:           "moderate",
			},
			{
				Question:         "Is uploaded content retrievable and where is it stored?",
				Why:              "Uploaded content that is publicly accessible or stored in web-accessible paths may enable further exploitation.",
				ExpectedEvidence: "Uploaded files are stored outside web root or require authentication to access.",
				Effort:           "moderate",
			},
		},
		Priority:       priority,
		NoveltySignals: []novelty.Signal{signal},
		EntityIDs:      signal.EntityIDs,
		ProjectID:      projectID,
		CreatedAt:      time.Now().UTC(),
	}}
}

// --- Auth Surface Generator ---

// AuthGenerator creates research opportunities for authentication surfaces.
type AuthGenerator struct{}

func NewAuthGenerator() *AuthGenerator { return &AuthGenerator{} }

func (g *AuthGenerator) Name() string { return "auth" }

func (g *AuthGenerator) CanGenerate(s novelty.Signal) bool {
	return s.Type == novelty.SignalNewAuthSurface ||
		(s.Type == novelty.SignalNovelCombination && hasSurface(s, surface.CategoryAuthentication))
}

func (g *AuthGenerator) Generate(_ context.Context, signal novelty.Signal, projectID uuid.UUID) []Opportunity {
	target := extractTarget(signal)
	priority := signalToPriority(signal)

	return []Opportunity{{
		ID:          uuid.New(),
		Title:       fmt.Sprintf("Investigate authentication boundary on %s", target),
		Target:      target,
		SurfaceType: surface.CategoryAuthentication,
		Description: fmt.Sprintf("Authentication surface discovered on %s. Authentication boundaries warrant investigation of session handling, credential management, and bypass resistance.", target),
		Questions: []ResearchQuestion{
			{
				Question:         "What authentication mechanism is used?",
				Why:              "Understanding the mechanism (session cookies, JWT, OAuth) reveals the attack surface boundary.",
				ExpectedEvidence: "Login response contains session token; authentication headers are present in subsequent requests.",
				Effort:           "quick",
			},
			{
				Question:         "Is the authentication boundary consistently enforced?",
				Why:              "Inconsistent enforcement may allow direct access to protected resources.",
				ExpectedEvidence: "All protected endpoints reject unauthenticated requests uniformly.",
				Effort:           "moderate",
			},
			{
				Question:         "How does the session lifecycle behave?",
				Why:              "Session fixation, insufficient expiration, or missing invalidation create persistence risks.",
				ExpectedEvidence: "Sessions expire after inactivity; logout invalidates the session server-side.",
				Effort:           "moderate",
			},
		},
		Priority:       priority,
		NoveltySignals: []novelty.Signal{signal},
		EntityIDs:      signal.EntityIDs,
		ProjectID:      projectID,
		CreatedAt:      time.Now().UTC(),
	}}
}

// --- API Surface Generator ---

// APIGenerator creates research opportunities for API surfaces.
type APIGenerator struct{}

func NewAPIGenerator() *APIGenerator { return &APIGenerator{} }

func (g *APIGenerator) Name() string { return "api" }

func (g *APIGenerator) CanGenerate(s novelty.Signal) bool {
	return s.Type == novelty.SignalNewAPISurface ||
		(s.Type == novelty.SignalNovelCombination && hasSurface(s, surface.CategoryAPI))
}

func (g *APIGenerator) Generate(_ context.Context, signal novelty.Signal, projectID uuid.UUID) []Opportunity {
	target := extractTarget(signal)
	priority := signalToPriority(signal)

	return []Opportunity{{
		ID:          uuid.New(),
		Title:       fmt.Sprintf("Investigate API surface on %s", target),
		Target:      target,
		SurfaceType: surface.CategoryAPI,
		Description: fmt.Sprintf("API surface discovered on %s. API endpoints warrant investigation of input handling, authorization, and data exposure.", target),
		Questions: []ResearchQuestion{
			{
				Question:         "What operations does the API expose?",
				Why:              "Understanding available operations reveals the functional attack surface.",
				ExpectedEvidence: "API documentation, introspection results, or endpoint enumeration output.",
				Effort:           "quick",
			},
			{
				Question:         "Is authorization enforced per-operation?",
				Why:              "APIs commonly enforce authentication but not per-operation authorization.",
				ExpectedEvidence: "Privileged operations reject requests from low-privilege users.",
				Effort:           "moderate",
			},
			{
				Question:         "Does the API expose excessive data in responses?",
				Why:              "APIs may return full objects when only partial data is needed, leaking sensitive fields.",
				ExpectedEvidence: "Responses contain only the expected fields; no internal IDs, emails, or metadata leak.",
				Effort:           "moderate",
			},
		},
		Priority:       priority,
		NoveltySignals: []novelty.Signal{signal},
		EntityIDs:      signal.EntityIDs,
		ProjectID:      projectID,
		CreatedAt:      time.Now().UTC(),
	}}
}

// --- Contradiction Generator ---

// ContradictionGenerator creates research opportunities from cross-tool contradictions.
type ContradictionGenerator struct{}

func NewContradictionGenerator() *ContradictionGenerator { return &ContradictionGenerator{} }

func (g *ContradictionGenerator) Name() string { return "contradiction" }

func (g *ContradictionGenerator) CanGenerate(s novelty.Signal) bool {
	return s.Type == novelty.SignalContradiction
}

func (g *ContradictionGenerator) Generate(_ context.Context, signal novelty.Signal, projectID uuid.UUID) []Opportunity {
	target := extractTarget(signal)

	return []Opportunity{{
		ID:          uuid.New(),
		Title:       fmt.Sprintf("Resolve cross-tool contradiction on %s", target),
		Target:      target,
		SurfaceType: surface.CategoryInfrastructure,
		Description: fmt.Sprintf("Different security tools report conflicting information about %s. This contradiction may indicate version differences, environment changes, or tool misidentification.", target),
		Questions: []ResearchQuestion{
			{
				Question:         "Which tool's report is accurate?",
				Why:              "Understanding the ground truth resolves the contradiction and improves future analysis.",
				ExpectedEvidence: "Manual verification confirms one tool's output; the other is explained (e.g., behind proxy, different vhost).",
				Effort:           "quick",
			},
			{
				Question:         "Does the contradiction indicate environmental complexity?",
				Why:              "Contradictions sometimes reveal load balancers, reverse proxies, or canary deployments.",
				ExpectedEvidence: "Multiple requests return different server headers, confirming infrastructure diversity.",
				Effort:           "moderate",
			},
		},
		Priority:       PriorityMedium,
		NoveltySignals: []novelty.Signal{signal},
		EntityIDs:      signal.EntityIDs,
		ProjectID:      projectID,
		CreatedAt:      time.Now().UTC(),
	}}
}

// --- helpers ---

func extractTarget(signal novelty.Signal) string {
	if signal.Title != "" {
		return signal.Title
	}
	return "unknown target"
}

func signalToPriority(signal novelty.Signal) Priority {
	switch {
	case signal.NoveltyScore >= 0.85:
		return PriorityHigh
	case signal.NoveltyScore >= 0.70:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

func hasSurface(signal novelty.Signal, cat surface.Category) bool {
	for _, c := range signal.SurfaceCategories {
		if c == cat {
			return true
		}
	}
	return false
}
