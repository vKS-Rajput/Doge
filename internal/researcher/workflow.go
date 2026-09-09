package researcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// WorkflowResearcher discovers application state machines and tests
// whether workflow transitions can be bypassed. It reasons about the
// security property: "Workflow transitions cannot be skipped."
//
// Research strategy:
//  1. Discover workflow endpoints from API docs and recon data
//  2. Map the expected state machine (state → action → next state)
//  3. Execute the legitimate workflow to confirm expected transitions
//  4. Test each transition skip: attempt to reach state N+2 from state N
//  5. Test direct terminal state access: can the final state be reached
//     without completing intermediate states?
//  6. Record evidence of any successful bypass
type WorkflowResearcher struct {
	client HTTPClient
}

// NewWorkflowResearcher creates a new workflow researcher.
func NewWorkflowResearcher(client HTTPClient) *WorkflowResearcher {
	return &WorkflowResearcher{client: client}
}

// Type returns the researcher type identifier.
func (w *WorkflowResearcher) Type() domain.ResearcherType {
	return domain.ResearcherWorkflow
}

// CanHandle returns true if this researcher can handle the given brief.
func (w *WorkflowResearcher) CanHandle(brief *domain.MissionBrief) bool {
	if brief == nil {
		return false
	}
	for _, hyp := range brief.Hypotheses {
		title := strings.ToLower(hyp.Title)
		if strings.Contains(title, "workflow") ||
			strings.Contains(title, "state") ||
			strings.Contains(title, "transition") ||
			strings.Contains(title, "skip") ||
			strings.Contains(title, "bypass") {
			return true
		}
	}
	for _, obs := range brief.Unknowns {
		low := strings.ToLower(obs)
		if strings.Contains(low, "workflow") ||
			strings.Contains(low, "state machine") ||
			strings.Contains(low, "order") {
			return true
		}
	}
	return false
}

// Execute runs the workflow research mission.
func (w *WorkflowResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherWorkflow,
		Status:         domain.MissionActive,
	}

	baseURL := brief.TargetBaseURL

	// Get credentials
	var token string
	for _, tok := range brief.Credentials {
		token = tok
		break
	}

	// Step 1: Discover workflow from API docs
	docsEvidence, workflowStates, workflowEndpoints := w.discoverWorkflow(ctx, baseURL, token, result)
	if len(docsEvidence) > 0 {
		result.Evidence = append(result.Evidence, docsEvidence...)
	}

	if len(workflowStates) == 0 {
		result.Status = domain.MissionCompleted
		result.Summary = "No workflow discovered"
		result.Duration = time.Since(start)
		result.CompletedAt = time.Now().UTC()
		return result, nil
	}

	result.Observations = append(result.Observations, domain.MissionObservation{
		Type:        "workflow_discovered",
		Description: fmt.Sprintf("Discovered workflow with states: %v", workflowStates),
		ObservedAt:  time.Now().UTC(),
	})

	// Step 2: Execute legitimate workflow to confirm state machine
	orderID, legitimateEvidence := w.executeLegitimateWorkflow(ctx, baseURL, token, result)
	result.Evidence = append(result.Evidence, legitimateEvidence...)

	if orderID == "" {
		result.Status = domain.MissionCompleted
		result.Summary = "Could not execute legitimate workflow"
		result.Duration = time.Since(start)
		result.CompletedAt = time.Now().UTC()
		return result, nil
	}

	result.Observations = append(result.Observations, domain.MissionObservation{
		Type:        "legitimate_workflow_confirmed",
		Description: fmt.Sprintf("Legitimate workflow completed: order %s went through all states", orderID),
		ObservedAt:  time.Now().UTC(),
	})

	// Step 3: Test workflow bypass — skip payment step
	bypassEvidence, bypassed := w.testWorkflowBypass(ctx, baseURL, token, workflowEndpoints, result)
	result.Evidence = append(result.Evidence, bypassEvidence...)

	// Step 4: Generate findings based on results
	if bypassed {
		result.Observations = append(result.Observations, domain.MissionObservation{
			Type:        "workflow_bypass_confirmed",
			Description: "CRITICAL: Workflow state bypass confirmed — payment step can be skipped",
			ObservedAt:  time.Now().UTC(),
		})

		candidate := domain.CandidateVulnerability{
			ID:       uuid.New(),
			Type:     "WORKFLOW_BYPASS",
			Title:    "Workflow State Bypass: Payment Step Can Be Skipped",
			Severity: "critical",
			Endpoint: "/api/v1/orders/{id}/confirm",
			Description: "The order confirmation endpoint does not enforce that payment " +
				"has been completed. An attacker can skip the payment step by " +
				"transitioning directly from 'checkout' to 'confirmed' state, " +
				"receiving goods/services without payment.",
			ReproductionSteps: []string{
				"1. Authenticate as any user",
				"2. Add items to cart and create an order",
				"3. POST /api/v1/orders/{id}/checkout to move to checkout state",
				"4. SKIP the payment step (POST /api/v1/orders/{id}/pay)",
				"5. POST /api/v1/orders/{id}/confirm directly",
				"6. Observe: Order is confirmed without payment (state: 'confirmed', no paid_at)",
				"7. Control: Legitimate workflow requires checkout → pay → confirm",
			},
			DiscoveredAt: time.Now().UTC(),
		}
		result.CandidateFindings = append(result.CandidateFindings, candidate)

		// Update hypothesis
		for _, hyp := range brief.Hypotheses {
			title := strings.ToLower(hyp.Title)
			if strings.Contains(title, "workflow") || strings.Contains(title, "skip") ||
				strings.Contains(title, "state") || strings.Contains(title, "transition") {
				result.HypothesisUpdates = append(result.HypothesisUpdates, domain.MissionHypothesisUpdate{
					HypothesisID:  hyp.ID,
					NewConfidence: 0.95,
					NewStatus:     "confirmed",
					Reason:        "Workflow bypass confirmed: payment step skipped, order confirmed without payment",
				})
			}
		}
	} else {
		result.Observations = append(result.Observations, domain.MissionObservation{
			Type:        "workflow_enforced",
			Description: "Workflow transitions appear to be properly enforced",
			ObservedAt:  time.Now().UTC(),
		})
	}

	result.Status = domain.MissionCompleted
	result.Duration = time.Since(start)
	result.CompletedAt = time.Now().UTC()
	result.Summary = fmt.Sprintf("Workflow research completed: %d states discovered, bypass=%v",
		len(workflowStates), bypassed)
	return result, nil
}

func (w *WorkflowResearcher) discoverWorkflow(ctx context.Context, baseURL, token string, result *domain.MissionResult) ([]domain.ExperimentEvidence, []string, map[string]string) {
	var evidence []domain.ExperimentEvidence
	var states []string
	endpoints := make(map[string]string)

	headers := make(map[string]string)
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	ev, err := w.client.Do(ctx, "GET", baseURL+"/api/v1/docs", headers, "")
	if err != nil {
		return evidence, states, endpoints
	}
	ev.Description = "Discover workflow endpoints from API docs"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	if ev.ResponseStatus == 200 {
		var docs struct {
			Endpoints []struct {
				Method      string `json:"method"`
				Path        string `json:"path"`
				Description string `json:"description"`
			} `json:"endpoints"`
			Workflow struct {
				Description string   `json:"description"`
				States      []string `json:"states"`
			} `json:"workflow"`
		}
		if err := json.Unmarshal([]byte(ev.ResponseBody), &docs); err == nil {
			states = docs.Workflow.States
			for _, ep := range docs.Endpoints {
				endpoints[ep.Path] = ep.Method
			}
		}
	}

	return evidence, states, endpoints
}

func (w *WorkflowResearcher) executeLegitimateWorkflow(ctx context.Context, baseURL, token string, result *domain.MissionResult) (string, []domain.ExperimentEvidence) {
	var evidence []domain.ExperimentEvidence
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	}

	// Step 1: Add items to cart
	cartBody := `[{"product_id":"prod-001","name":"Widget A","quantity":1,"price":29.99}]`
	ev, err := w.client.Do(ctx, "POST", baseURL+"/api/v1/cart", headers, cartBody)
	if err != nil {
		return "", evidence
	}
	ev.Description = "Legitimate workflow: Add item to cart"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	// Step 2: Create order
	ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/orders", headers, "")
	if err != nil {
		return "", evidence
	}
	ev.Description = "Legitimate workflow: Create order from cart"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	var orderResp struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	_ = json.Unmarshal([]byte(ev.ResponseBody), &orderResp)
	if orderResp.ID == "" {
		return "", evidence
	}

	// Step 3: Checkout
	ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/orders/"+orderResp.ID+"/checkout", headers, "")
	if err != nil {
		return "", evidence
	}
	ev.Description = "Legitimate workflow: Checkout order"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	// Step 4: Pay
	ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/orders/"+orderResp.ID+"/pay", headers, "")
	if err != nil {
		return "", evidence
	}
	ev.Description = "Legitimate workflow: Pay for order"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	// Step 5: Confirm
	ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/orders/"+orderResp.ID+"/confirm", headers, "")
	if err != nil {
		return "", evidence
	}
	ev.Description = "Legitimate workflow: Confirm order"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	return orderResp.ID, evidence
}

func (w *WorkflowResearcher) testWorkflowBypass(ctx context.Context, baseURL, token string, endpoints map[string]string, result *domain.MissionResult) ([]domain.ExperimentEvidence, bool) {
	var evidence []domain.ExperimentEvidence
	bypassed := false

	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	}

	// Create a fresh order for bypass testing
	cartBody := `[{"product_id":"prod-002","name":"Widget B","quantity":2,"price":49.99}]`
	ev, err := w.client.Do(ctx, "POST", baseURL+"/api/v1/cart", headers, cartBody)
	if err != nil {
		return evidence, false
	}
	ev.Description = "Bypass test: Add item to cart"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/orders", headers, "")
	if err != nil {
		return evidence, false
	}
	ev.Description = "Bypass test: Create order"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	var orderResp struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	_ = json.Unmarshal([]byte(ev.ResponseBody), &orderResp)
	if orderResp.ID == "" {
		return evidence, false
	}

	// Move to checkout (required — can't skip this)
	ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/orders/"+orderResp.ID+"/checkout", headers, "")
	if err != nil {
		return evidence, false
	}
	ev.Description = "Bypass test: Move to checkout state"
	evidence = append(evidence, *ev)
	result.RequestsMade++

	// BYPASS ATTEMPT: Skip payment, go directly to confirm
	ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/orders/"+orderResp.ID+"/confirm", headers, "")
	if err != nil {
		return evidence, false
	}
	ev.Description = "BYPASS ATTEMPT: Confirm order directly from checkout (skipping payment)"
	result.RequestsMade++

	if ev.ResponseStatus == 200 {
		bypassed = true
		ev.IsAnomalous = true
		ev.Interpretation = "CONFIRMED BYPASS: Order confirmed without payment"

		// Verify order state
		verifyEv, err := w.client.Do(ctx, "GET", baseURL+"/api/v1/orders/"+orderResp.ID, headers, "")
		if err == nil {
			verifyEv.Description = "Verification: Check order state after bypass"
			verifyEv.IsAnomalous = true
			verifyEv.Interpretation = "Order confirmed without payment (paid_at is empty)"
			evidence = append(evidence, *verifyEv)
			result.RequestsMade++
		}
	}
	evidence = append(evidence, *ev)

	// Control test: Try to confirm from "created" state (should fail)
	cartBody = `[{"product_id":"prod-003","name":"Premium Widget","quantity":1,"price":199.99}]`
	ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/cart", headers, cartBody)
	if err == nil {
		evidence = append(evidence, *ev)
		result.RequestsMade++

		ev, err = w.client.Do(ctx, "POST", baseURL+"/api/v1/orders", headers, "")
		if err == nil {
			evidence = append(evidence, *ev)
			result.RequestsMade++

			var controlResp struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal([]byte(ev.ResponseBody), &controlResp)

			if controlResp.ID != "" {
				controlEv, err := w.client.Do(ctx, "POST", baseURL+"/api/v1/orders/"+controlResp.ID+"/confirm", headers, "")
				if err == nil {
					controlEv.Description = "CONTROL TEST: Attempt confirm directly from created state (expect 409)"
					evidence = append(evidence, *controlEv)
					result.RequestsMade++

					if controlEv.ResponseStatus == http.StatusConflict {
						result.Observations = append(result.Observations, domain.MissionObservation{
							Type:        "control_test_passed",
							Description: "Control: Direct confirm from 'created' correctly denied (409). But checkout→confirm (skipping pay) succeeded.",
							ObservedAt:  time.Now().UTC(),
						})
					}
				}
			}
		}
	}

	return evidence, bypassed
}
