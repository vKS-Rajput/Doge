package differential

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
)

// ClientRunnerFunc abstracts HTTP dispatch for cross-principal testing.
type ClientRunnerFunc func(ctx context.Context, op OperationSpec, p *worldmodel.Principal) (*ExecutionResponse, error)

// Engine orchestrates principal-aware differential security research.
type Engine struct{}

// NewEngine creates a new differential research engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Compare computes the structural and authorization difference between two principal observations.
func (e *Engine) Compare(
	pA *worldmodel.Principal,
	respA *ExecutionResponse,
	pB *worldmodel.Principal,
	respB *ExecutionResponse,
	targetObjectID string,
) *StructuralDiff {
	diff := &StructuralDiff{
		StatusA:       respA.StatusCode,
		StatusB:       respB.StatusCode,
		IsStatusMatch: respA.StatusCode == respB.StatusCode,
		Confidence:    0.50,
	}

	// 1. Analyze JSON body structure
	keysA, countA, _ := extractJSONStructure(respA.Body)
	keysB, countB, mapB := extractJSONStructure(respB.Body)

	diff.FieldCountA = countA
	diff.FieldCountB = countB

	// Extra keys in A vs B
	for k := range keysA {
		if !keysB[k] {
			diff.ExtraKeysInA = append(diff.ExtraKeysInA, k)
		}
	}
	for k := range keysB {
		if !keysA[k] {
			diff.ExtraKeysInB = append(diff.ExtraKeysInB, k)
		}
	}
	sort.Strings(diff.ExtraKeysInA)
	sort.Strings(diff.ExtraKeysInB)

	// Check if target object ID leaked into Principal B's response
	if targetObjectID != "" {
		if containsIdentifier(respB.Body, mapB, targetObjectID) {
			diff.ObjectLeakDetected = true
			diff.LeakedIdentifiers = append(diff.LeakedIdentifiers, targetObjectID)
		}
	}

	// 2. Evaluate Authorization Outcome
	// Case 1: Strict isolation enforced (Principal B receives 401/403/404)
	if respA.StatusCode >= 200 && respA.StatusCode < 300 && (respB.StatusCode == 401 || respB.StatusCode == 403 || respB.StatusCode == 404) {
		diff.Outcome = OutcomeStrictIsolationEnforced
		diff.Confidence = 0.95
		diff.Explanation = fmt.Sprintf("Access boundary strictly enforced: Principal A (%s) received HTTP %d, while Principal B (%s) received HTTP %d with tenant denial",
			pA.Name, respA.StatusCode, pB.Name, respB.StatusCode)
		diff.MinimalProof = fmt.Sprintf("Request A -> HTTP %d | Request B -> HTTP %d", respA.StatusCode, respB.StatusCode)
		return diff
	}

	// Case 2: Horizontal BOLA (Unauthorized cross-tenant / cross-user object access)
	if respA.StatusCode >= 200 && respA.StatusCode < 300 && respB.StatusCode >= 200 && respB.StatusCode < 300 {
		if diff.ObjectLeakDetected {
			diff.Outcome = OutcomeBOLAConfirmed
			diff.Confidence = 0.95
			diff.Explanation = fmt.Sprintf("BOLA Vulnerability Confirmed: Principal B (%s) successfully retrieved private object %s owned by Principal A (%s) with HTTP 200",
				pB.Name, targetObjectID, pA.Name)
			diff.MinimalProof = fmt.Sprintf("Principal B (%s) received HTTP %d containing unauthorized object identifier %q in response body",
				pB.Name, respB.StatusCode, targetObjectID)
			return diff
		}

		// Case 3: Vertical Privilege Escalation
		if (pA.Type == worldmodel.PrincipalSystemAdmin || pA.Type == worldmodel.PrincipalTenantAdmin) &&
			(pB.Type == worldmodel.PrincipalUser || pB.Type == worldmodel.PrincipalAnonymous) {
			// Check if Principal B received admin payload
			if countB > 0 && len(diff.ExtraKeysInA) == 0 {
				if pB.Type == worldmodel.PrincipalAnonymous {
					diff.Outcome = OutcomeAuthBypassConfirmed
					diff.Confidence = 0.90
					diff.Explanation = fmt.Sprintf("Authentication Bypass Confirmed: Unauthenticated/Anonymous principal accessed administrative endpoint with HTTP %d", respB.StatusCode)
					diff.MinimalProof = fmt.Sprintf("Anonymous access to administrative route yielded HTTP %d with %d response fields", respB.StatusCode, countB)
				} else {
					diff.Outcome = OutcomePrivEscConfirmed
					diff.Confidence = 0.90
					diff.Explanation = fmt.Sprintf("Privilege Escalation Confirmed: Standard user Principal B (%s) accessed administrative functionality with HTTP %d", pB.Name, respB.StatusCode)
					diff.MinimalProof = fmt.Sprintf("Standard user received HTTP %d matching admin response schema (%d fields)", respB.StatusCode, countB)
				}
				return diff
			}
		}

		// Case 4: Public Endpoint / Identical Content
		if countA == countB && len(diff.ExtraKeysInA) == 0 && len(diff.ExtraKeysInB) == 0 && respA.Body == respB.Body {
			diff.Outcome = OutcomePublicEndpoint
			diff.Confidence = 0.80
			diff.Explanation = "Identical responses observed across distinct principals; endpoint appears to serve public non-sensitive data."
			diff.MinimalProof = fmt.Sprintf("Identical HTTP %d payload across both principals", respA.StatusCode)
			return diff
		}

		// Case 5: Role-Restricted filtering (e.g. Empty list or filtered fields for B)
		if countB < countA || strings.Contains(respB.Body, "[]") || strings.Contains(respB.Body, "null") {
			diff.Outcome = OutcomeRoleRestricted
			diff.Confidence = 0.75
			diff.Explanation = fmt.Sprintf("Response filtering observed: Principal A received %d fields, while Principal B received %d fields or empty dataset", countA, countB)
			diff.MinimalProof = fmt.Sprintf("Field reduction: A=%d fields vs B=%d fields", countA, countB)
			return diff
		}
	}

	diff.Outcome = OutcomeInconclusive
	diff.Explanation = fmt.Sprintf("Inconclusive variance: Status A=%d, Status B=%d", respA.StatusCode, respB.StatusCode)
	diff.MinimalProof = fmt.Sprintf("Status A=%d vs Status B=%d", respA.StatusCode, respB.StatusCode)
	return diff
}

// Execute performs a differential research experiment by executing the operation under both principal contexts.
func (e *Engine) Execute(
	ctx context.Context,
	op OperationSpec,
	pA *worldmodel.Principal,
	pB *worldmodel.Principal,
	runner ClientRunnerFunc,
	targetObjectID string,
) (*DifferentialTestResult, error) {
	if pA == nil || pB == nil {
		return nil, fmt.Errorf("both primary and secondary principals must be provided")
	}

	// 1. Execute Operation as Principal A (Baseline)
	respA, err := runner(ctx, op, pA)
	if err != nil {
		return nil, fmt.Errorf("failed executing operation as Principal A (%s): %w", pA.Name, err)
	}

	// 2. Execute Operation as Principal B (Differential Test)
	respB, err := runner(ctx, op, pB)
	if err != nil {
		return nil, fmt.Errorf("failed executing operation as Principal B (%s): %w", pB.Name, err)
	}

	// 3. Compare & compute structural differential
	diff := e.Compare(pA, respA, pB, respB, targetObjectID)

	result := &DifferentialTestResult{
		ID:        uuid.New(),
		TargetURL: op.URL,
		Operation: op,
		ObservationA: &PrincipalObservation{
			Principal: pA,
			Response:  respA,
		},
		ObservationB: &PrincipalObservation{
			Principal: pB,
			Response:  respB,
		},
		Diff:        diff,
		EvaluatedAt: time.Now().UTC(),
	}

	return result, nil
}

func extractJSONStructure(body string) (map[string]bool, int, any) {
	keys := make(map[string]bool)
	var raw any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return keys, 0, nil
	}

	count := 0
	var traverse func(node any, prefix string)
	traverse = func(node any, prefix string) {
		switch v := node.(type) {
		case map[string]any:
			for k, val := range v {
				fullKey := k
				if prefix != "" {
					fullKey = prefix + "." + k
				}
				keys[fullKey] = true
				count++
				traverse(val, fullKey)
			}
		case []any:
			for i, item := range v {
				traverse(item, fmt.Sprintf("%s[%d]", prefix, i))
			}
		}
	}

	traverse(raw, "")
	return keys, count, raw
}

func containsIdentifier(body string, jsonNode any, targetID string) bool {
	if strings.Contains(body, fmt.Sprintf("%q", targetID)) || strings.Contains(body, targetID) {
		return true
	}
	return false
}
