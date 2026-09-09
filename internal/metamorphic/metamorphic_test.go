package metamorphic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

type testHTTPClient struct {
	client *http.Client
}

func (c *testHTTPClient) Do(ctx context.Context, method, targetURL string, headers map[string]string, body string) (*domain.ExperimentEvidence, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return &domain.ExperimentEvidence{
		ID:             uuid.New(),
		RequestURL:     targetURL,
		RequestMethod:  method,
		RequestBody:    body,
		ResponseStatus: resp.StatusCode,
		ResponseBody:   string(respBody),
		CapturedAt:     time.Now().UTC(),
	}, nil
}

func TestMetamorphic_ProbeContextIsolation(t *testing.T) {
	// Mock server with simulated context bleed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Operations []BatchSubOp `json:"operations"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		results := make([]SubOpResult, 0)
		hasPrivilege := false

		for _, op := range req.Operations {
			if op.Privilege == "high" {
				hasPrivilege = true
				results = append(results, SubOpResult{
					OpID:       op.ID,
					StatusCode: 200,
					Body:       `{"status":"privileged_ok"}`,
				})
			} else {
				// Context bleed flaw: if hasPrivilege is set from prior op, allow!
				if hasPrivilege {
					results = append(results, SubOpResult{
						OpID:       op.ID,
						StatusCode: 200,
						Body:       `{"data":"confidential_report_leaked"}`,
					})
				} else {
					results = append(results, SubOpResult{
						OpID:       op.ID,
						StatusCode: 403,
						Body:       `{"error":"forbidden"}`,
					})
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BatchResponse{Results: results})
	}))
	defer server.Close()

	httpClient := &testHTTPClient{client: server.Client()}
	prober := NewProber(httpClient)

	privOp := BatchSubOp{
		ID:        "op-auth-check",
		Method:    "GET",
		Path:      "/api/v1/admin/ping",
		Privilege: "high",
	}

	unprivOp := BatchSubOp{
		ID:        "op-confidential-fetch",
		Method:    "GET",
		Path:      "/api/v1/tenant-beta/reports",
		Privilege: "low",
	}

	res, err := prober.ProbeContextIsolation(
		context.Background(),
		server.URL,
		"/api/v1/batch",
		nil,
		privOp,
		unprivOp,
	)
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}

	if !res.RelationViolated {
		t.Fatal("expected metamorphic relation to be violated by context bleed flaw")
	}

	t.Logf("✓ %s", res.DifferentialDetails)
}
