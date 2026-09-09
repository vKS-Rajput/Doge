package metamorphic

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// HTTPClient defines the interface for making controlled HTTP requests.
type HTTPClient interface {
	Do(ctx context.Context, method, url string, headers map[string]string, body string) (*domain.ExperimentEvidence, error)
}

// SubOpResult captures the response for an individual sub-operation.
type SubOpResult struct {
	OpID       string `json:"op_id"`
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
}

// BatchResponse matches standard REST batch execution responses.
type BatchResponse struct {
	Results []SubOpResult `json:"results"`
}

// MetamorphicResult contains the comparative findings of a metamorphic test.
type MetamorphicResult struct {
	RelationName        string                      `json:"relation_name"`
	RelationViolated    bool                        `json:"relation_violated"`
	DifferentialDetails string                      `json:"differential_details"`
	ForwardEvidence     domain.ExperimentEvidence   `json:"forward_evidence"`
	ReverseEvidence     domain.ExperimentEvidence   `json:"reverse_evidence"`
	ControlEvidence     domain.ExperimentEvidence   `json:"control_evidence"`
	AnomalousEvidence   []domain.ExperimentEvidence `json:"anomalous_evidence"`
}

// Prober executes metamorphic experiments against a target application.
type Prober struct {
	httpClient HTTPClient
}

// NewProber creates a new metamorphic prober.
func NewProber(httpClient HTTPClient) *Prober {
	return &Prober{httpClient: httpClient}
}

// ProbeContextIsolation executes a 3-way metamorphic experiment:
// 1. Forward: [Privileged, Unprivileged]
// 2. Reverse: [Unprivileged, Privileged]
// 3. Control: [Unprivileged alone]
//
// Invariant: Unprivileged operation must have identical authorization behavior
// regardless of whether a privileged operation preceded it in the same batch.
func (p *Prober) ProbeContextIsolation(
	ctx context.Context,
	baseURL string,
	batchEndpoint string,
	headers map[string]string,
	privOp, unprivOp BatchSubOp,
) (*MetamorphicResult, error) {
	forwardOps, reverseOps, controlOps := PairPrivilegedAndUnprivileged(privOp, unprivOp)

	// Step 1: Forward Batch [Privileged, Unprivileged]
	forwardJSON, _ := json.Marshal(map[string]any{"operations": forwardOps})
	forwardEv, err := p.httpClient.Do(ctx, "POST", baseURL+batchEndpoint, headers, string(forwardJSON))
	if err != nil {
		return nil, fmt.Errorf("forward batch execution failed: %w", err)
	}
	forwardEv.Description = fmt.Sprintf("Metamorphic Forward: [%s, %s]", privOp.ID, unprivOp.ID)

	// Step 2: Reverse Batch [Unprivileged, Privileged]
	reverseJSON, _ := json.Marshal(map[string]any{"operations": reverseOps})
	reverseEv, err := p.httpClient.Do(ctx, "POST", baseURL+batchEndpoint, headers, string(reverseJSON))
	if err != nil {
		return nil, fmt.Errorf("reverse batch execution failed: %w", err)
	}
	reverseEv.Description = fmt.Sprintf("Metamorphic Reverse: [%s, %s]", unprivOp.ID, privOp.ID)

	// Step 3: Control Batch [Unprivileged alone]
	controlJSON, _ := json.Marshal(map[string]any{"operations": controlOps})
	controlEv, err := p.httpClient.Do(ctx, "POST", baseURL+batchEndpoint, headers, string(controlJSON))
	if err != nil {
		return nil, fmt.Errorf("control batch execution failed: %w", err)
	}
	controlEv.Description = fmt.Sprintf("Metamorphic Control: [%s alone]", unprivOp.ID)

	// Parse sub-responses
	forwardSubResults := extractSubResults(forwardEv.ResponseBody)
	reverseSubResults := extractSubResults(reverseEv.ResponseBody)
	controlSubResults := extractSubResults(controlEv.ResponseBody)

	// Check status of the unprivileged operation in each configuration
	forwardUnprivStatus := getSubStatus(forwardSubResults, unprivOp.ID)
	reverseUnprivStatus := getSubStatus(reverseSubResults, unprivOp.ID)
	controlUnprivStatus := getSubStatus(controlSubResults, unprivOp.ID)

	res := &MetamorphicResult{
		RelationName:    "ContextIsolationUnderOrderInversion",
		ForwardEvidence: *forwardEv,
		ReverseEvidence: *reverseEv,
		ControlEvidence: *controlEv,
	}

	// Metamorphic relation:
	// If unpriv operation returns 200 when after privileged, but 401 or 403 when alone or before:
	// The relation is VIOLATED, proving context bleed!
	if forwardUnprivStatus == 200 && (reverseUnprivStatus == 401 || reverseUnprivStatus == 403 || controlUnprivStatus == 401 || controlUnprivStatus == 403) {
		res.RelationViolated = true
		res.DifferentialDetails = fmt.Sprintf(
			"METAMORPHIC RELATION VIOLATION: Unprivileged op %s succeeded (HTTP 200) when preceded by %s, "+
				"but was denied (HTTP %d reverse, HTTP %d control) when executed before or alone. "+
				"Proves context/authorization leakage across batch execution boundary.",
			unprivOp.ID, privOp.ID, reverseUnprivStatus, controlUnprivStatus,
		)

		forwardEv.IsAnomalous = true
		forwardEv.Interpretation = res.DifferentialDetails
		res.ForwardEvidence = *forwardEv
		res.AnomalousEvidence = append(res.AnomalousEvidence, *forwardEv)
	}

	return res, nil
}

func extractSubResults(body string) []SubOpResult {
	var resp BatchResponse
	if err := json.Unmarshal([]byte(body), &resp); err == nil && len(resp.Results) > 0 {
		return resp.Results
	}

	// Try alternate map wrapper
	var alt struct {
		Data []SubOpResult `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &alt); err == nil && len(alt.Data) > 0 {
		return alt.Data
	}

	return nil
}

func getSubStatus(results []SubOpResult, opID string) int {
	for _, r := range results {
		if r.OpID == opID {
			return r.StatusCode
		}
	}
	return 0
}

func init() {
	_ = time.Now()
	_ = uuid.Nil
}
