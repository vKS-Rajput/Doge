package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAICompatibleModel connects to OpenRouter, OpenAI, vLLM, or any OpenAI-compatible API.
type OpenAICompatibleModel struct {
	providerName string
	modelID      string
	baseURL      string
	apiKey       string
	httpClient   *http.Client
}

// NewOpenRouterModel creates an AI reasoning client targeting OpenRouter.
func NewOpenRouterModel(apiKey string, modelID string) *OpenAICompatibleModel {
	if modelID == "" {
		modelID = "anthropic/claude-3.5-sonnet"
	}
	return &OpenAICompatibleModel{
		providerName: "openrouter",
		modelID:      modelID,
		baseURL:      "https://openrouter.ai/api/v1/chat/completions",
		apiKey:       apiKey,
		httpClient:   &http.Client{Timeout: 60 * time.Second},
	}
}

// NewOpenAICompatibleModel creates a generic OpenAI-compatible model client.
func NewOpenAICompatibleModel(providerName, baseURL, apiKey, modelID string) *OpenAICompatibleModel {
	return &OpenAICompatibleModel{
		providerName: providerName,
		modelID:      modelID,
		baseURL:      baseURL,
		apiKey:       apiKey,
		httpClient:   &http.Client{Timeout: 60 * time.Second},
	}
}

func (m *OpenAICompatibleModel) ProviderName() string { return m.providerName }
func (m *OpenAICompatibleModel) ModelID() string      { return m.modelID }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float32       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func (m *OpenAICompatibleModel) Generate(ctx context.Context, req ReasoningRequest) (*ReasoningResponse, error) {
	messages := make([]chatMessage, 0, 2)
	if req.System != "" {
		messages = append(messages, chatMessage{Role: "system", Content: req.System})
	}
	messages = append(messages, chatMessage{Role: "user", Content: req.Prompt})

	bodyData, err := json.Marshal(chatRequest{
		Model:       m.modelID,
		Messages:    messages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal chat request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", m.baseURL, bytes.NewReader(bodyData))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if m.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+m.apiKey)
	}
	if m.providerName == "openrouter" {
		httpReq.Header.Set("HTTP-Referer", "https://github.com/vKS-Rajput/doge")
		httpReq.Header.Set("X-Title", "DOGE Autonomous Security Research")
	}

	start := time.Now()
	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("reasoning request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read reasoning response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("model api returned error %d: %s", resp.StatusCode, string(respBytes))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode reasoning response json: %w", err)
	}

	content := ""
	if len(chatResp.Choices) > 0 {
		content = chatResp.Choices[0].Message.Content
	}

	duration := time.Since(start)
	return &ReasoningResponse{
		Content:      content,
		ProviderUsed: m.providerName,
		ModelUsed:    m.modelID,
		Metrics: ModelMetrics{
			Model:          m.modelID,
			PromptTokens:   chatResp.Usage.PromptTokens,
			ResponseTokens: chatResp.Usage.CompletionTokens,
			TotalTokens:    chatResp.Usage.TotalTokens,
			Duration:       duration,
		},
	}, nil
}

// OllamaModel connects to local Ollama instances running on localhost:11434.
type OllamaModel struct {
	modelID    string
	baseURL    string
	httpClient *http.Client
}

// NewOllamaModel creates an AI reasoning client targeting local Ollama.
func NewOllamaModel(modelID string) *OllamaModel {
	if modelID == "" {
		modelID = "llama3:latest"
	}
	return &OllamaModel{
		modelID:    modelID,
		baseURL:    "http://127.0.0.1:11434/api/generate",
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (m *OllamaModel) ProviderName() string { return "local_ollama" }
func (m *OllamaModel) ModelID() string      { return m.modelID }

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	System string `json:"system,omitempty"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response   string `json:"response"`
	TotalNano  int64  `json:"total_duration"`
	PromptEval int    `json:"prompt_eval_count"`
	EvalCount  int    `json:"eval_count"`
}

func (m *OllamaModel) Generate(ctx context.Context, req ReasoningRequest) (*ReasoningResponse, error) {
	reqBody, err := json.Marshal(ollamaRequest{
		Model:  m.modelID,
		Prompt: req.Prompt,
		System: req.System,
		Stream: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", m.baseURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read ollama response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned error %d: %s", resp.StatusCode, string(body))
	}

	var oResp ollamaResponse
	if err := json.Unmarshal(body, &oResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ollama json: %w", err)
	}

	return &ReasoningResponse{
		Content:      oResp.Response,
		ProviderUsed: "local_ollama",
		ModelUsed:    m.modelID,
		Metrics: ModelMetrics{
			Model:          m.modelID,
			PromptTokens:   oResp.PromptEval,
			ResponseTokens: oResp.EvalCount,
			TotalTokens:    oResp.PromptEval + oResp.EvalCount,
			Duration:       time.Since(start),
		},
	}, nil
}

// DeterministicModel provides fast, deterministic reasoning responses for testing and offline air-gapped environments.
type DeterministicModel struct {
	providerName string
	modelID      string
}

// NewDeterministicModel creates a deterministic offline reasoning client.
func NewDeterministicModel() *DeterministicModel {
	return &DeterministicModel{
		providerName: "deterministic_brain",
		modelID:      "doge-symbolic-v1",
	}
}

func (m *DeterministicModel) ProviderName() string { return m.providerName }
func (m *DeterministicModel) ModelID() string      { return m.modelID }

func (m *DeterministicModel) Generate(ctx context.Context, req ReasoningRequest) (*ReasoningResponse, error) {
	var content string

	switch req.TaskType {
	case TaskConceptNaming:
		if strings.Contains(strings.ToLower(req.Prompt), "race") || strings.Contains(strings.ToLower(req.Prompt), "temporal") || strings.Contains(strings.ToLower(req.Prompt), "wallet") {
			content = "Latent Race Window Serialization Collapse"
		} else if strings.Contains(strings.ToLower(req.Prompt), "cache") || strings.Contains(strings.ToLower(req.Prompt), "normalization") {
			content = "Cache Key Normalization Collision Bleed"
		} else {
			content = "Emergent Observational Discrepancy"
		}

	case TaskHypothesisGeneration:
		if strings.Contains(strings.ToLower(req.Prompt), "wallet") || strings.Contains(strings.ToLower(req.Prompt), "transfer") {
			content = "Hypothesis: Asynchronous balance check in /api/v1/wallet/transfer admits a race window where concurrent requests overdraw funds."
		} else if strings.Contains(strings.ToLower(req.Prompt), "cache") {
			content = "Hypothesis: Inconsistent URI normalization between caching proxy and backend leads to private report exposure under public cache keys."
		} else {
			content = "Hypothesis: Interventional divergence indicates an unmodeled security invariant violation."
		}

	case TaskClassification:
		content = "SECURITY_CRITICAL_ENDPOINT"

	case TaskSemanticInterpretation:
		content = "Differential response reveals state leak across execution frames."

	case TaskFindingSynthesis:
		content = "Empirical proof demonstrates reproducible authorization boundary failure."

	default:
		content = "Deterministic reasoning completed."
	}

	return &ReasoningResponse{
		Content:      content,
		ProviderUsed: m.providerName,
		ModelUsed:    m.modelID,
		Metrics: ModelMetrics{
			Model:       m.modelID,
			TotalTokens: 10,
			Duration:    time.Millisecond,
		},
	}, nil
}
