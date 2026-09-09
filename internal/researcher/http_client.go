package researcher

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// DefaultHTTPClient implements HTTPClient with full request/response evidence capture.
type DefaultHTTPClient struct {
	client *http.Client
}

// NewHTTPClient creates an HTTP client configured for controlled experiment execution.
func NewHTTPClient() *DefaultHTTPClient {
	return &DefaultHTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects — capture the raw redirect response
				return http.ErrUseLastResponse
			},
		},
	}
}

// Do executes an HTTP request and captures the complete evidence.
func (c *DefaultHTTPClient) Do(ctx context.Context, method, url string, headers map[string]string, body string) (*domain.ExperimentEvidence, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Capture timing
	start := time.Now()

	resp, err := c.client.Do(req)
	if err != nil {
		return &domain.ExperimentEvidence{
			ID:             uuid.New(),
			RequestMethod:  method,
			RequestURL:     url,
			RequestHeaders: headers,
			RequestBody:    body,
			ResponseStatus: 0,
			Interpretation: "Request failed: " + err.Error(),
			CapturedAt:     time.Now().UTC(),
		}, err
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	// Read response body
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		respBody = []byte("(body read error: " + err.Error() + ")")
	}

	// Capture response headers
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	evidence := &domain.ExperimentEvidence{
		ID:              uuid.New(),
		RequestMethod:   method,
		RequestURL:      url,
		RequestHeaders:  headers,
		RequestBody:     body,
		ResponseStatus:  resp.StatusCode,
		ResponseHeaders: respHeaders,
		ResponseBody:    string(respBody),
		ResponseTimeMs:  elapsed.Milliseconds(),
		CapturedAt:      time.Now().UTC(),
	}

	return evidence, nil
}
