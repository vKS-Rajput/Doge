package ai

import (
	"context"
	"fmt"
	"sync"
)

// TaskType indicates the specialized reasoning job being dispatched.
type TaskType string

const (
	TaskClassification         TaskType = "classification"          // Cheap / local model
	TaskSemanticInterpretation TaskType = "semantic_interpretation" // Local / specialized model
	TaskConceptNaming          TaskType = "concept_naming"           // Strong frontier model
	TaskHypothesisGeneration   TaskType = "hypothesis_generation"    // Strong frontier model
	TaskCodeAnalysis           TaskType = "code_analysis"            // Specialized coding model
	TaskFindingSynthesis       TaskType = "finding_synthesis"        // Strong frontier model
)

// ReasoningRequest is the structured input dispatched to a reasoning model.
type ReasoningRequest struct {
	TaskType    TaskType       `json:"task_type"`
	Prompt      string         `json:"prompt"`
	System      string         `json:"system,omitempty"`
	ContextData map[string]any `json:"context_data,omitempty"`
	Temperature float32        `json:"temperature,omitempty"`
	MaxTokens   int            `json:"max_tokens,omitempty"`
}

// ReasoningResponse is the model output.
type ReasoningResponse struct {
	Content      string       `json:"content"`
	ProviderUsed string       `json:"provider_used"`
	ModelUsed    string       `json:"model_used"`
	Metrics      ModelMetrics `json:"metrics"`
}

// ReasoningModel represents any pluggable model backend (OpenRouter, Ollama, vLLM, etc.).
type ReasoningModel interface {
	ProviderName() string
	ModelID() string
	Generate(ctx context.Context, req ReasoningRequest) (*ReasoningResponse, error)
}

// ModelRouter manages multi-provider model dispatch according to task requirements.
type ModelRouter struct {
	mu           sync.RWMutex
	providers    map[string]ReasoningModel
	routingTable map[TaskType]string // TaskType -> ProviderName
	defaultModel string
}

// NewModelRouter creates a new multi-model router.
func NewModelRouter(defaultModel string) *ModelRouter {
	return &ModelRouter{
		providers:    make(map[string]ReasoningModel),
		routingTable: make(map[TaskType]string),
		defaultModel: defaultModel,
	}
}

// RegisterProvider adds a model provider to the router.
func (r *ModelRouter) RegisterProvider(model ReasoningModel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[model.ProviderName()] = model
}

// SetRoute assigns a specialized provider for a specific task type.
func (r *ModelRouter) SetRoute(task TaskType, providerName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routingTable[task] = providerName
}

// Dispatch routes a reasoning request to the appropriate model provider.
func (r *ModelRouter) Dispatch(ctx context.Context, req ReasoningRequest) (*ReasoningResponse, error) {
	r.mu.RLock()
	providerName, ok := r.routingTable[req.TaskType]
	if !ok {
		providerName = r.defaultModel
	}
	model, exists := r.providers[providerName]
	r.mu.RUnlock()

	if !exists {
		// Fallback to first available provider
		r.mu.RLock()
		for _, m := range r.providers {
			model = m
			break
		}
		r.mu.RUnlock()
	}

	if model == nil {
		return nil, fmt.Errorf("no reasoning model provider registered")
	}

	return model.Generate(ctx, req)
}
