// Package model provides the model abstraction layer for DOGE V2.
//
// The model is replaceable. DOGE's research state, evidence, attack graph,
// learning, policy, missions, and validation infrastructure are not.
//
// Architecture:
//
//	DOGE Research Platform → ModelRouter → [Claude | GPT | Ollama | Deterministic] → Research result
package model

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ModelRole identifies what kind of reasoning task a model is being asked to perform.
type ModelRole string

const (
	RoleReasoning         ModelRole = "reasoning"
	RoleSecurityResearch  ModelRole = "security_research"
	RoleCodeGeneration    ModelRole = "code_generation"
	RoleJudge             ModelRole = "judge"
	RoleSummarization     ModelRole = "summarization"
	RoleHypothesisGen     ModelRole = "hypothesis_generation"
	RoleExperimentDesign  ModelRole = "experiment_design"
)

// CompletionRequest is a structured request to a model provider.
type CompletionRequest struct {
	Role        ModelRole      `json:"role"`
	SystemPrompt string       `json:"system_prompt"`
	UserPrompt  string        `json:"user_prompt"`
	Schema      *OutputSchema `json:"schema,omitempty"` // If set, response must conform
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
}

// CompletionResponse is the structured response from a model provider.
type CompletionResponse struct {
	Content     string `json:"content"`
	Provider    string `json:"provider"`
	Model       string `json:"model"`
	TokensUsed  int    `json:"tokens_used"`
}

// OutputSchema defines the expected JSON schema for structured model output.
type OutputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]SchemaField `json:"properties"`
	Required   []string               `json:"required"`
}

// SchemaField defines a single field in an output schema.
type SchemaField struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// ModelProvider is the interface for a single model backend.
type ModelProvider interface {
	Name() string
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
	SupportsRole(role ModelRole) bool
}

// ModelRouter routes model requests to the appropriate provider based on role and availability.
type ModelRouter interface {
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
	RegisterProvider(provider ModelProvider)
}

// DefaultRouter is the default model router implementation.
type DefaultRouter struct {
	providers []ModelProvider
}

// NewRouter creates a new model router.
func NewRouter() *DefaultRouter {
	return &DefaultRouter{
		providers: make([]ModelProvider, 0),
	}
}

// RegisterProvider adds a model provider to the router.
func (r *DefaultRouter) RegisterProvider(provider ModelProvider) {
	r.providers = append(r.providers, provider)
}

// Complete routes a completion request to the best available provider.
func (r *DefaultRouter) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	// Find a provider that supports the requested role
	for _, p := range r.providers {
		if p.SupportsRole(req.Role) {
			return p.Complete(ctx, req)
			}
	}
	// Fallback: use any available provider
	if len(r.providers) > 0 {
		return r.providers[0].Complete(ctx, req)
	}
	return nil, fmt.Errorf("no model provider available for role %s", req.Role)
}

// DeterministicProvider is a model provider that uses deterministic heuristic logic
// instead of an LLM. Used for testing and as a fallback when no LLM is available.
//
// This is critical: DOGE must be able to function (at reduced capability)
// without an LLM available. The research loop itself is the value,
// not the model.
type DeterministicProvider struct{}

// NewDeterministicProvider creates a deterministic model provider.
func NewDeterministicProvider() *DeterministicProvider {
	return &DeterministicProvider{}
}

// Name returns the provider name.
func (d *DeterministicProvider) Name() string {
	return "deterministic"
}

// SupportsRole returns true — the deterministic provider handles all roles as fallback.
func (d *DeterministicProvider) SupportsRole(role ModelRole) bool {
	return true
}

// Complete generates a deterministic response based on heuristic analysis of the prompt.
func (d *DeterministicProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	var content string

	switch req.Role {
	case RoleHypothesisGen:
		content = d.generateHypotheses(req.UserPrompt)
	case RoleExperimentDesign:
		content = d.designExperiments(req.UserPrompt)
	case RoleSecurityResearch:
		content = d.securityAnalysis(req.UserPrompt)
	case RoleJudge:
		content = d.judge(req.UserPrompt)
	default:
		content = d.defaultAnalysis(req.UserPrompt)
	}

	return &CompletionResponse{
		Content:  content,
		Provider: "deterministic",
		Model:    "heuristic-v1",
	}, nil
}

func (d *DeterministicProvider) generateHypotheses(prompt string) string {
	lower := strings.ToLower(prompt)

	var hypotheses []map[string]any

	// Object identifier patterns → BOLA hypothesis
	if strings.Contains(lower, "item") || strings.Contains(lower, "object") || strings.Contains(lower, "/id") || strings.Contains(lower, "{id}") {
		hypotheses = append(hypotheses, map[string]any{
			"title":      "Missing Object-Level Authorization",
			"statement":  "Object endpoints may not enforce ownership or tenant isolation, allowing cross-tenant access via direct object reference.",
			"confidence": 0.65,
			"type":       "BOLA",
			"confirmation_criteria": "Authenticated user A can access objects belonging to user B from a different tenant",
			"refutation_criteria":   "Server returns 403 Forbidden when accessing cross-tenant objects",
		})
	}

	// Multi-tenant patterns → tenant isolation hypothesis
	if strings.Contains(lower, "tenant") || strings.Contains(lower, "multi-tenant") {
		hypotheses = append(hypotheses, map[string]any{
			"title":      "Inconsistent Tenant Isolation",
			"statement":  "Tenant isolation may be enforced inconsistently across different endpoints. Some endpoints may properly validate tenant context while others may not.",
			"confidence": 0.60,
			"type":       "AUTHORIZATION",
			"confirmation_criteria": "Different endpoints show different authorization behavior for cross-tenant access",
			"refutation_criteria":   "All endpoints consistently enforce tenant isolation",
		})
	}

	// Auth patterns
	if strings.Contains(lower, "auth") || strings.Contains(lower, "bearer") || strings.Contains(lower, "token") {
		hypotheses = append(hypotheses, map[string]any{
			"title":      "Authentication Boundary Weakness",
			"statement":  "Authentication may be required but authorization (what a user can do) may not be properly enforced beyond verifying identity.",
			"confidence": 0.55,
			"type":       "AUTHORIZATION",
			"confirmation_criteria": "Authenticated requests succeed regardless of the user's relationship to the resource",
			"refutation_criteria":   "Server consistently rejects requests for resources outside the user's scope",
		})
	}

	if len(hypotheses) == 0 {
		hypotheses = append(hypotheses, map[string]any{
			"title":      "Unknown Security Boundary",
			"statement":  "The security model of this application is not yet understood. Further reconnaissance is required.",
			"confidence": 0.30,
			"type":       "UNKNOWN",
		})
	}

	result, _ := json.Marshal(map[string]any{"hypotheses": hypotheses})
	return string(result)
}

func (d *DeterministicProvider) designExperiments(prompt string) string {
	lower := strings.ToLower(prompt)
	var experiments []map[string]any

	if strings.Contains(lower, "bola") || strings.Contains(lower, "authorization") || strings.Contains(lower, "cross-tenant") {
		experiments = append(experiments, map[string]any{
			"title":       "Cross-Tenant Object Access Test",
			"description": "Access an object belonging to tenant B using tenant A credentials",
			"expected_if_vulnerable": "200 OK with tenant B data",
			"expected_if_secure":     "403 Forbidden or 404 Not Found",
		})
	}

	if strings.Contains(lower, "differential") || strings.Contains(lower, "inconsistent") {
		experiments = append(experiments, map[string]any{
			"title":       "Differential Authorization Test",
			"description": "Compare authorization behavior across different endpoint types with the same cross-tenant request",
			"expected_if_vulnerable": "Different status codes for same authorization concept across endpoints",
			"expected_if_secure":     "Consistent rejection across all endpoints",
		})
	}

	result, _ := json.Marshal(map[string]any{"experiments": experiments})
	return string(result)
}

func (d *DeterministicProvider) securityAnalysis(prompt string) string {
	return `{"analysis": "Security analysis requires investigating authorization boundaries, authentication mechanisms, and object access patterns."}`
}

func (d *DeterministicProvider) judge(prompt string) string {
	lower := strings.ToLower(prompt)
	if strings.Contains(lower, "200") && strings.Contains(lower, "cross-tenant") {
		return `{"verdict": "confirmed", "confidence": 0.95, "reason": "Cross-tenant object access returned 200 OK with unauthorized data"}`
	}
	if strings.Contains(lower, "403") || strings.Contains(lower, "forbidden") {
		return `{"verdict": "refuted", "confidence": 0.90, "reason": "Server correctly rejected cross-tenant access"}`
	}
	return `{"verdict": "inconclusive", "confidence": 0.50, "reason": "Insufficient evidence to determine"}`
}

func (d *DeterministicProvider) defaultAnalysis(prompt string) string {
	return `{"result": "Analysis completed with deterministic heuristics"}`
}
