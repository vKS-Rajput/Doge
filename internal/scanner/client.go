// Package scanner provides a real-world HTTP security scanner that autonomously
// discovers endpoints, tests for vulnerabilities, and generates cryptographic
// proof bundles. This is the concrete execution layer that makes actual HTTP
// requests against live targets.
package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RateLimitedClient wraps http.Client with per-second rate limiting,
// request counting, and full response capture for proof generation.
type RateLimitedClient struct {
	inner       *http.Client
	mu          sync.Mutex
	rps         int
	tokens      int
	lastRefill  time.Time
	totalSent   int
	budget      int
	headers     map[string]string
	timeout     time.Duration
}

// ClientConfig configures the rate-limited HTTP client.
type ClientConfig struct {
	RatePerSecond  int
	Budget         int
	TimeoutSeconds int
	Headers        map[string]string
	FollowRedirect bool
	SkipTLSVerify  bool
}

// NewRateLimitedClient creates a client that enforces rate limits and budget.
func NewRateLimitedClient(cfg ClientConfig) *RateLimitedClient {
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = 10
	}
	if cfg.Budget <= 0 {
		cfg.Budget = 200
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 15
	}

	jar, _ := cookiejar.New(nil)
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second

	transport := &http.Transport{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify},
	}

	client := &http.Client{
		Timeout:   timeout,
		Jar:       jar,
		Transport: transport,
	}

	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &RateLimitedClient{
		inner:      client,
		rps:        cfg.RatePerSecond,
		tokens:     cfg.RatePerSecond,
		lastRefill: time.Now(),
		budget:     cfg.Budget,
		headers:    cfg.Headers,
		timeout:    timeout,
	}
}

// CapturedResponse holds the full HTTP response data for proof generation.
type CapturedResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
	URL        string
	Method     string
	ReqBody    string
	ReqHeaders map[string]string
}

// Do executes an HTTP request with rate limiting and budget enforcement.
// Returns a CapturedResponse with the full response body for proof generation.
func (c *RateLimitedClient) Do(req *http.Request) (*CapturedResponse, error) {
	c.mu.Lock()
	if c.totalSent >= c.budget {
		c.mu.Unlock()
		return nil, fmt.Errorf("request budget exhausted (%d/%d)", c.totalSent, c.budget)
	}

	// Token bucket rate limiting
	now := time.Now()
	elapsed := now.Sub(c.lastRefill)
	refill := int(elapsed.Seconds()) * c.rps
	if refill > 0 {
		c.tokens += refill
		if c.tokens > c.rps {
			c.tokens = c.rps
		}
		c.lastRefill = now
	}

	if c.tokens <= 0 {
		c.mu.Unlock()
		// Wait for next token
		time.Sleep(time.Second / time.Duration(c.rps))
		c.mu.Lock()
		c.tokens = 1
	}
	c.tokens--
	c.totalSent++
	c.mu.Unlock()

	// Apply default headers
	for k, v := range c.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "DOGE-SecurityResearch/7.0")
	}

	// Capture request body for proof
	var reqBody string
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		reqBody = string(bodyBytes)
		req.Body = io.NopCloser(strings.NewReader(reqBody))
	}

	reqHeaders := make(map[string]string)
	for k, vals := range req.Header {
		reqHeaders[k] = strings.Join(vals, ", ")
	}

	start := time.Now()
	resp, err := c.inner.Do(req)
	duration := time.Since(start)

	if err != nil {
		return &CapturedResponse{
			URL:        req.URL.String(),
			Method:     req.Method,
			ReqBody:    reqBody,
			ReqHeaders: reqHeaders,
			Duration:   duration,
			StatusCode: 0,
		}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB max

	return &CapturedResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Duration:   duration,
		URL:        req.URL.String(),
		Method:     req.Method,
		ReqBody:    reqBody,
		ReqHeaders: reqHeaders,
	}, nil
}

// Get is a convenience method for GET requests.
func (c *RateLimitedClient) Get(targetURL string) (*CapturedResponse, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post is a convenience method for POST requests.
func (c *RateLimitedClient) Post(targetURL, contentType, body string) (*CapturedResponse, error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// RequestsSent returns the total number of requests made.
func (c *RateLimitedClient) RequestsSent() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalSent
}

// BudgetRemaining returns remaining request budget.
func (c *RateLimitedClient) BudgetRemaining() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.budget - c.totalSent
}

// IsInScope checks whether a URL is within the allowed target scope.
func IsInScope(targetURL string, baseHost string, outOfScope []string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()
	if host != baseHost && !strings.HasSuffix(host, "."+baseHost) {
		// Allow localhost variants
		if host != "127.0.0.1" && host != "localhost" && host != "0.0.0.0" {
			return false
		}
	}

	path := parsed.Path
	for _, blocked := range outOfScope {
		blocked = strings.TrimSpace(blocked)
		if blocked == "" {
			continue
		}
		if strings.HasSuffix(blocked, "*") {
			prefix := strings.TrimSuffix(blocked, "*")
			if strings.HasPrefix(path, prefix) {
				return false
			}
		} else if path == blocked {
			return false
		}
	}
	return true
}
