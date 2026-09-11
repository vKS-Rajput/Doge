package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ReplayEntry records an individual network transaction for deterministic playback.
type ReplayEntry struct {
	ID             uuid.UUID         `json:"id"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	RequestHeaders map[string]string `json:"request_headers"`
	RequestBody    string            `json:"request_body"`
	StatusCode     int               `json:"status_code"`
	ResponseBody   string            `json:"response_body"`
	LatencyMs      int64             `json:"latency_ms"`
	Timestamp      time.Time         `json:"timestamp"`
}

// SandboxConfig specifies execution and resource limits for a tactical sandbox.
type SandboxConfig struct {
	MaxRequests     int           `json:"max_requests"`
	Timeout         time.Duration `json:"timeout"`
	RateLimitPerSec int           `json:"rate_limit_per_sec"`
	AllowedHosts    []string      `json:"allowed_hosts"`
}

// TacticalSandbox wraps HTTP and tactical execution with containment, accounting, and replay.
type TacticalSandbox struct {
	mu           sync.Mutex
	cfg          SandboxConfig
	client       *http.Client
	requestCount int
	journal      []ReplayEntry
	accountant   *ResourceAccountant
	lastRequest  time.Time
}

// NewTacticalSandbox creates a new tactical execution sandbox.
func NewTacticalSandbox(cfg SandboxConfig) *TacticalSandbox {
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 50
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.RateLimitPerSec <= 0 {
		cfg.RateLimitPerSec = 20
	}

	return &TacticalSandbox{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		journal:    make([]ReplayEntry, 0),
		accountant: NewResourceAccountant(),
	}
}

// ExecuteHTTP runs an HTTP request under strict sandbox constraints.
func (s *TacticalSandbox) ExecuteHTTP(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	s.mu.Lock()

	// 1. Budget Enforcement
	if s.requestCount >= s.cfg.MaxRequests {
		s.mu.Unlock()
		return nil, nil, fmt.Errorf("sandbox error: request budget of %d exceeded", s.cfg.MaxRequests)
	}

	// 2. Host Scope Enforcement
	reqHost := req.URL.Host
	if idx := strings.Index(reqHost, ":"); idx != -1 {
		reqHost = reqHost[:idx]
	}

	if len(s.cfg.AllowedHosts) > 0 {
		inScope := false
		for _, allowed := range s.cfg.AllowedHosts {
			cleanAllowed := allowed
			if idx := strings.Index(cleanAllowed, ":"); idx != -1 {
				cleanAllowed = cleanAllowed[:idx]
			}
			if strings.EqualFold(reqHost, cleanAllowed) || strings.HasSuffix(strings.ToLower(reqHost), "."+strings.ToLower(cleanAllowed)) {
				inScope = true
				break
			}
		}
		if !inScope {
			s.mu.Unlock()
			return nil, nil, fmt.Errorf("sandbox error: target %s is outside authorized scope %v", reqHost, s.cfg.AllowedHosts)
		}
	}

	// 3. Rate Limiting
	if s.cfg.RateLimitPerSec > 0 && !s.lastRequest.IsZero() {
		minInterval := time.Second / time.Duration(s.cfg.RateLimitPerSec)
		elapsed := time.Since(s.lastRequest)
		if elapsed < minInterval {
			time.Sleep(minInterval - elapsed)
		}
	}
	s.lastRequest = time.Now()
	s.requestCount++
	s.mu.Unlock()

	// Capture request body for journal and accounting
	var reqBodyBytes []byte
	if req.Body != nil {
		reqBodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(reqBodyBytes))
	}

	startTime := time.Now()
	req = req.WithContext(ctx)
	resp, err := s.client.Do(req)
	latency := time.Since(startTime).Milliseconds()

	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading response body: %w", err)
	}

	// Update Accounting
	s.accountant.RecordTransaction(len(reqBodyBytes), len(respBodyBytes), latency)

	// Record Journal Entry
	reqHeaders := make(map[string]string)
	for k, v := range req.Header {
		reqHeaders[k] = strings.Join(v, ", ")
	}

	entry := ReplayEntry{
		ID:             uuid.New(),
		Method:         req.Method,
		URL:            req.URL.String(),
		RequestHeaders: reqHeaders,
		RequestBody:    string(reqBodyBytes),
		StatusCode:     resp.StatusCode,
		ResponseBody:   string(respBodyBytes),
		LatencyMs:      latency,
		Timestamp:      startTime.UTC(),
	}

	s.mu.Lock()
	s.journal = append(s.journal, entry)
	s.mu.Unlock()

	return resp, respBodyBytes, nil
}

// GetJournal returns the immutable audit journal of all transactions in this sandbox.
func (s *TacticalSandbox) GetJournal() []ReplayEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := make([]ReplayEntry, len(s.journal))
	copy(res, s.journal)
	return res
}

// Accountant returns the resource tracking metrics.
func (s *TacticalSandbox) Accountant() *ResourceAccountant {
	return s.accountant
}

func sanitizeURLHost(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return rawURL
}
