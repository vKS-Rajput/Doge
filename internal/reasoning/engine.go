package reasoning

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	aicontext "github.com/vKS-Rajput/doge/internal/context"
	"github.com/vKS-Rajput/doge/internal/retriever"
	"github.com/vKS-Rajput/doge/internal/verification"
)

// Engine orchestrates the full reasoning pipeline:
// Prompt → Ollama → Parse → Validate → Verify → Response
type Engine struct {
	ollama   *OllamaClient
	verifier *verification.Verifier
	builder  *aicontext.Builder
	logger   *slog.Logger
}

// NewEngine creates a new Reasoning Engine.
func NewEngine(config OllamaConfig, logger *slog.Logger) *Engine {
	return &Engine{
		ollama:   NewOllamaClient(config),
		verifier: verification.New(),
		builder:  aicontext.NewBuilder(4000),
		logger:   logger,
	}
}

// Ask processes a question with evidence and returns a verified response.
func (e *Engine) Ask(ctx context.Context, question string, bundle *retriever.Bundle) (*VerifiedResponse, error) {
	start := time.Now()

	// Step 1: Build structured prompt.
	prompt := e.builder.Build(question, bundle)
	e.logger.Info("reasoning",
		"question", question,
		"evidence_count", prompt.EvidenceCount,
		"token_estimate", prompt.TokenEstimate,
	)

	// Step 2: Invoke Ollama.
	result, err := e.ollama.Generate(ctx, prompt.SystemMessage, prompt.UserMessage, aicontext.ResponseSchema)
	if err != nil {
		return nil, &ReasoningError{
			Stage:   "generation",
			Message: fmt.Sprintf("Ollama invocation failed: %v", err),
		}
	}

	e.logger.Info("ollama response received",
		"model", result.Model,
		"tokens", result.Metrics.TotalTokens,
		"tokens_per_sec", fmt.Sprintf("%.1f", result.Metrics.TokensPerSecond),
	)

	// Step 3: Parse structured JSON response.
	var response Response
	if err := json.Unmarshal([]byte(result.Content), &response); err != nil {
		// Malformed JSON = model failure. Retry once with repair prompt.
		e.logger.Warn("invalid JSON from model, retrying", "error", err)

		repairResult, retryErr := e.retryWithRepair(ctx, prompt, result.Content)
		if retryErr != nil {
			return nil, &ReasoningError{
				Stage:   "parsing",
				Message: "Model returned invalid JSON. Retry also failed.",
				Retried: true,
			}
		}
		result = repairResult
		if err := json.Unmarshal([]byte(result.Content), &response); err != nil {
			return nil, &ReasoningError{
				Stage:   "parsing",
				Message: "Model returned invalid JSON even after retry.",
				Retried: true,
			}
		}
	}

	// Step 4: Schema validation.
	if response.Answer == "" {
		return nil, &ReasoningError{
			Stage:   "validation",
			Message: "Model response has empty answer field.",
		}
	}

	// Step 5: Claim verification.
	verificationResults := e.verifier.Verify(&response, bundle)

	// Step 6: Build verified response.
	var supported, rejected []VerifiedClaim
	for i, vr := range verificationResults {
		vc := VerifiedClaim{
			Claim:              response.Claims[i],
			VerificationStatus: vr.Status,
			VerificationReason: vr.Reason,
		}

		switch vr.Status {
		case StatusSupported, StatusPartiallySupported:
			supported = append(supported, vc)
		case StatusUnsupported, StatusContradicted, StatusUnverifiable:
			rejected = append(rejected, vc)
		}
	}

	duration := time.Since(start)

	return &VerifiedResponse{
		Answer:          response.Answer,
		SupportedClaims: supported,
		RejectedClaims:  rejected,
		Limitations:     response.Limitations,
		Verification:    verificationResults,
		ModelUsed:       result.Model,
		TotalTokens:     result.Metrics.TotalTokens,
		DurationMs:      duration.Milliseconds(),
	}, nil
}

// retryWithRepair attempts to get valid JSON by sending a repair prompt.
func (e *Engine) retryWithRepair(ctx context.Context, prompt *aicontext.Prompt, invalidJSON string) (*OllamaResult, error) {
	repairPrompt := fmt.Sprintf(`Your previous response was not valid JSON. Please respond ONLY with valid JSON matching the required schema.

Previous invalid response:
%s

Please fix the JSON and respond again.`, invalidJSON)

	return e.ollama.Generate(ctx, prompt.SystemMessage, repairPrompt, aicontext.ResponseSchema)
}

// Ping checks if the Ollama backend is reachable.
func (e *Engine) Ping(ctx context.Context) error {
	return e.ollama.Ping(ctx)
}

// Model returns the configured model name.
func (e *Engine) Model() string {
	return e.ollama.config.Model
}
