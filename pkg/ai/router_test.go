package ai

import (
	"context"
	"testing"
)

type mockModel struct {
	provider string
	modelID  string
}

func (m *mockModel) ProviderName() string { return m.provider }
func (m *mockModel) ModelID() string      { return m.modelID }
func (m *mockModel) Generate(ctx context.Context, req ReasoningRequest) (*ReasoningResponse, error) {
	return &ReasoningResponse{
		Content:      "mock response for " + string(req.TaskType),
		ProviderUsed: m.provider,
		ModelUsed:    m.modelID,
	}, nil
}

func TestModelRouter_Dispatch(t *testing.T) {
	router := NewModelRouter("local_ollama")

	localModel := &mockModel{provider: "local_ollama", modelID: "llama-3-8b"}
	frontierModel := &mockModel{provider: "openrouter", modelID: "anthropic/claude-3.5-sonnet"}

	router.RegisterProvider(localModel)
	router.RegisterProvider(frontierModel)

	// Set specialized route
	router.SetRoute(TaskHypothesisGeneration, "openrouter")
	router.SetRoute(TaskClassification, "local_ollama")

	ctx := context.Background()

	// 1. Test routed to frontier model
	resp1, err := router.Dispatch(ctx, ReasoningRequest{
		TaskType: TaskHypothesisGeneration,
		Prompt:   "Formulate an invariant contradiction hypothesis",
	})
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if resp1.ProviderUsed != "openrouter" {
		t.Errorf("expected openrouter, got %s", resp1.ProviderUsed)
	}

	// 2. Test routed to local model
	resp2, err := router.Dispatch(ctx, ReasoningRequest{
		TaskType: TaskClassification,
		Prompt:   "Classify HTTP endpoint",
	})
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if resp2.ProviderUsed != "local_ollama" {
		t.Errorf("expected local_ollama, got %s", resp2.ProviderUsed)
	}

	// 3. Test unrouted task falls back to default
	resp3, err := router.Dispatch(ctx, ReasoningRequest{
		TaskType: TaskSemanticInterpretation,
		Prompt:   "Interpret response body semantics",
	})
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if resp3.ProviderUsed != "local_ollama" {
		t.Errorf("expected fallback to default local_ollama, got %s", resp3.ProviderUsed)
	}
}

func TestDeterministicModel(t *testing.T) {
	model := NewDeterministicModel()
	ctx := context.Background()

	resp, err := model.Generate(ctx, ReasoningRequest{
		TaskType: TaskConceptNaming,
		Prompt:   "Suggest concept name for wallet race window",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "Latent Race Window Serialization Collapse" {
		t.Errorf("unexpected concept name: %s", resp.Content)
	}
}

