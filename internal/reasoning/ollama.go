package reasoning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OllamaConfig configures the Ollama connection.
type OllamaConfig struct {
	BaseURL     string        `json:"base_url"`
	Model       string        `json:"model"`
	Temperature float64       `json:"temperature"`
	Timeout     time.Duration `json:"timeout"`
}

// DefaultOllamaConfig returns sensible defaults for Doge.
func DefaultOllamaConfig() OllamaConfig {
	return OllamaConfig{
		BaseURL:     "http://localhost:11434",
		Model:       "qwen3:4b",
		Temperature: 0.0, // Deterministic for structured output.
		Timeout:     60 * time.Second,
	}
}

// OllamaClient communicates with the Ollama API.
type OllamaClient struct {
	config OllamaConfig
	client *http.Client
}

// NewOllamaClient creates a new Ollama client.
func NewOllamaClient(config OllamaConfig) *OllamaClient {
	return &OllamaClient{
		config: config,
		client: &http.Client{Timeout: config.Timeout},
	}
}

// ollamaChatRequest is the request body for /api/chat.
type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Format   json.RawMessage `json:"format"`
	Options  ollamaOptions   `json:"options"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature"`
}

// ollamaChatResponse is the response from /api/chat (non-streaming).
type ollamaChatResponse struct {
	Model     string        `json:"model"`
	Message   ollamaMessage `json:"message"`
	Done      bool          `json:"done"`
	TotalDuration  int64    `json:"total_duration"`
	LoadDuration   int64    `json:"load_duration"`
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
	EvalDuration    int64  `json:"eval_duration"`
}

// Generate sends a structured prompt to Ollama and returns the raw response.
func (c *OllamaClient) Generate(ctx context.Context, systemPrompt, userPrompt string, jsonSchema string) (*OllamaResult, error) {
	// Build request with JSON schema in format field.
	var formatJSON json.RawMessage
	if jsonSchema != "" {
		formatJSON = json.RawMessage(jsonSchema)
	}

	reqBody := ollamaChatRequest{
		Model: c.config.Model,
		Messages: []ollamaMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream:  false,
		Format:  formatJSON,
		Options: ollamaOptions{Temperature: c.config.Temperature},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	url := c.config.BaseURL + "/api/chat"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(body))
	}

	var ollamaResp ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("decoding ollama response: %w", err)
	}

	// Calculate tokens per second from eval metrics.
	var tokensPerSec float64
	if ollamaResp.EvalDuration > 0 {
		tokensPerSec = float64(ollamaResp.EvalCount) / (float64(ollamaResp.EvalDuration) / 1e9)
	}

	return &OllamaResult{
		Content: ollamaResp.Message.Content,
		Model:   ollamaResp.Model,
		Metrics: ModelMetrics{
			Model:           ollamaResp.Model,
			PromptTokens:    ollamaResp.PromptEvalCount,
			ResponseTokens:  ollamaResp.EvalCount,
			TotalTokens:     ollamaResp.PromptEvalCount + ollamaResp.EvalCount,
			Duration:        duration,
			TokensPerSecond: tokensPerSec,
		},
	}, nil
}

// OllamaResult holds the raw Ollama response.
type OllamaResult struct {
	Content string       `json:"content"`
	Model   string       `json:"model"`
	Metrics ModelMetrics `json:"metrics"`
}

// Ping checks if Ollama is reachable.
func (c *OllamaClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.BaseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("ollama not reachable at %s: %w", c.config.BaseURL, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned %d", resp.StatusCode)
	}
	return nil
}
