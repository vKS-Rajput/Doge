package validation

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// BoundedHTTPClient is a restricted HTTP client for validation.
//
// Hard limits (NOT configurable):
//   - Max body size: 1 MB
//   - Allowed methods: GET, HEAD, OPTIONS
//   - Request body: NOT allowed
//   - Max redirects: 3 (with scope re-check each time)
//   - TLS verification: required
//   - User-Agent: Doge/0.9.5
//   - Request timeout: 10s
//
// GET ≠ non-destructive. HTTP method safety ≠ application safety.
type BoundedHTTPClient struct {
	client         *http.Client
	maxBodySize    int64
	redirectPolicy *RedirectPolicy
	userAgent      string
}

const (
	defaultMaxBodySize = 1 << 20 // 1 MB
	defaultTimeout     = 10 * time.Second
	defaultUserAgent   = "Doge/0.9.5 (security-research)"
)

// NewBoundedHTTPClient creates a bounded HTTP client.
func NewBoundedHTTPClient(scopeGate *ScopeGate) *BoundedHTTPClient {
	redirectPolicy := &RedirectPolicy{
		MaxRedirects: 3,
		ScopeGate:    scopeGate,
	}

	b := &BoundedHTTPClient{
		maxBodySize:    defaultMaxBodySize,
		redirectPolicy: redirectPolicy,
		userAgent:      defaultUserAgent,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// TLS verification required — no InsecureSkipVerify.

	b.client = &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Re-check scope on every redirect.
			redirectURL := req.URL.String()
			_, _, err := redirectPolicy.CheckRedirect(redirectURL, len(via))
			if err != nil {
				return err
			}

			// Strip credentials on cross-origin redirect.
			if len(via) > 0 {
				originalURL := via[0].URL.String()
				if IsCrossOrigin(originalURL, redirectURL) {
					req.Header.Del("Authorization")
					req.Header.Del("Cookie")
				}
			}

			return nil
		},
	}

	return b
}

// Do executes a bounded HTTP request.
func (b *BoundedHTTPClient) Do(
	ctx context.Context,
	approved *ApprovedTarget,
	method string,
	headers map[string]string,
) (*Result, error) {
	// Validate method.
	if !AllowedMethods[method] {
		return nil, fmt.Errorf("method %s not permitted in v0.9.5 (allowed: GET, HEAD, OPTIONS)", method)
	}

	// Build request — NO body allowed.
	req, err := http.NewRequestWithContext(ctx, method, approved.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set user agent.
	req.Header.Set("User-Agent", b.userAgent)

	// Inject credential headers (only allowed headers).
	for k, v := range headers {
		if AllowedCredentialHeaders[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
		// Silently drop non-allowed headers — don't leak info about what was attempted.
	}

	// Execute.
	start := time.Now()
	resp, err := b.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body with size limit.
	limitedReader := io.LimitReader(resp.Body, b.maxBodySize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check if body was truncated.
	bodySize := len(body)
	if int64(bodySize) > b.maxBodySize {
		body = body[:b.maxBodySize] // Truncate
	}

	// Hash the body (don't store the actual content).
	bodyHash := fmt.Sprintf("%x", sha256.Sum256(body))

	// Capture response headers.
	respHeaders := make(map[string][]string)
	for k, v := range resp.Header {
		respHeaders[k] = v
	}

	return &Result{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		BodyHash:   bodyHash,
		BodySize:   bodySize,
		Duration:   duration,
		Timestamp:  time.Now().UTC(),
	}, nil
}

// CredentialStore holds pre-registered credential profiles.
type CredentialStore struct {
	profiles map[string]*CredentialProfile
}

// NewCredentialStore creates a credential store.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		profiles: make(map[string]*CredentialProfile),
	}
}

// Register adds a credential profile.
func (s *CredentialStore) Register(profile *CredentialProfile) {
	s.profiles[profile.ID] = profile
}

// Get retrieves a credential profile by ID.
func (s *CredentialStore) Get(id string) (*CredentialProfile, error) {
	profile, ok := s.profiles[id]
	if !ok {
		return nil, fmt.Errorf("credential profile %q not found", id)
	}
	return profile, nil
}

// Executor runs validated actions through the full safety pipeline.
//
// Pipeline per action:
//  1. Verify approval binding (plan digest)
//  2. Check request budget (3-tier)
//  3. Validate scope (DNS-aware, full pipeline)
//  4. Validate method (GET/HEAD/OPTIONS only)
//  5. Inject credentials (from profile, not AI)
//  6. Execute bounded HTTP request
//  7. Capture result as observation
type Executor struct {
	scopeGate  *ScopeGate
	httpClient *BoundedHTTPClient
	budget     *RequestBudget
	creds      *CredentialStore
	logger     *slog.Logger
}

// NewExecutor creates a new executor.
func NewExecutor(
	scopeGate *ScopeGate,
	budget *RequestBudget,
	creds *CredentialStore,
	logger *slog.Logger,
) *Executor {
	return &Executor{
		scopeGate:  scopeGate,
		httpClient: NewBoundedHTTPClient(scopeGate),
		budget:     budget,
		creds:      creds,
		logger:     logger,
	}
}

// ExecutePlan runs all actions in an approved plan.
func (e *Executor) ExecutePlan(ctx context.Context, plan ExecutablePlan) (*PlanResult, error) {
	// Step 0: Verify approval binding.
	if err := VerifyApproval(plan); err != nil {
		return nil, fmt.Errorf("approval verification failed: %w", err)
	}

	e.logger.Info("executing validation plan",
		"plan_id", plan.ID,
		"hypothesis_id", plan.HypothesisID,
		"actions", len(plan.Actions),
	)

	planResult := &PlanResult{
		PlanID:           plan.ID,
		HypothesisID:     plan.HypothesisID,
		SafetyDisclaimer: SafetyDisclaimer,
	}

	for i, action := range plan.Actions {
		// Step 1: Budget check.
		if err := e.budget.CheckBudget(plan.ID, plan.HypothesisID); err != nil {
			e.logger.Warn("budget exhausted", "action", i, "error", err)
			planResult.BudgetExhausted = true
			break
		}

		// Step 2: Scope validation (full DNS-aware pipeline).
		targetURL := fmt.Sprintf("https://%s%s", action.Target, action.Path)
		approved, err := e.scopeGate.ValidateTarget(targetURL)
		if err != nil {
			e.logger.Warn("scope violation", "target", targetURL, "error", err)
			planResult.Results = append(planResult.Results, ActionResult{
				Action: action, Error: err, ExecutedAt: time.Now().UTC(),
			})
			continue
		}

		// Step 3: Method check.
		if !AllowedMethods[action.Method] {
			err := fmt.Errorf("method %s not permitted in v0.9.5", action.Method)
			planResult.Results = append(planResult.Results, ActionResult{
				Action: action, Error: err, ExecutedAt: time.Now().UTC(),
			})
			continue
		}

		// Step 4: Inject credentials (if profile specified).
		headers := make(map[string]string)
		if action.CredentialProfileID != "" {
			profile, err := e.creds.Get(action.CredentialProfileID)
			if err != nil {
				planResult.Results = append(planResult.Results, ActionResult{
					Action: action, Error: err, ExecutedAt: time.Now().UTC(),
				})
				continue
			}
			for k, v := range profile.Headers {
				if AllowedCredentialHeaders[strings.ToLower(k)] {
					headers[k] = v
				}
			}
		}

		// Step 5: Execute bounded HTTP request.
		e.logger.Info("executing action",
			"action", i+1,
			"type", action.Type,
			"method", action.Method,
			"target", action.Target,
			"path", action.Path,
		)

		result, err := e.httpClient.Do(ctx, approved, action.Method, headers)
		e.budget.RecordRequest(plan.ID, plan.HypothesisID)

		planResult.Results = append(planResult.Results, ActionResult{
			Action:     action,
			Result:     result,
			Error:      err,
			ExecutedAt: time.Now().UTC(),
		})

		if result != nil {
			e.logger.Info("action complete",
				"action", i+1,
				"status", result.StatusCode,
				"duration_ms", result.Duration.Milliseconds(),
			)
		}
	}

	planResult.Completed = !planResult.BudgetExhausted
	return planResult, nil
}
