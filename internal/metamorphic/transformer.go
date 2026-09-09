// Package metamorphic implements metamorphic experiment design and probing for DOGE.
//
// Metamorphic testing evaluates relations between multiple executions rather than
// matching static strings or vulnerability signatures.
//
// Key metamorphic relations for security:
// 1. Order Inversion: Eval([Op1, Op2]) vs Eval([Op2, Op1])
//    Invariant: Unprivileged Op2 must not succeed merely because Op1 preceded it.
// 2. Identity Isolation: Eval([Op_auth, Op_unauth]) vs Eval([Op_unauth])
//    Invariant: Unauthenticated sub-op must not inherit authentication context.
package metamorphic

// BatchSubOp represents a sub-operation within a batched request.
type BatchSubOp struct {
	ID        string            `json:"id"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Privilege string            `json:"privilege,omitempty"` // "high", "low", "none"
}

// InvertOrder reverses the order of sub-operations in a batch.
func InvertOrder(ops []BatchSubOp) []BatchSubOp {
	reversed := make([]BatchSubOp, len(ops))
	for i, op := range ops {
		reversed[len(ops)-1-i] = op
	}
	return reversed
}

// PairPrivilegedAndUnprivileged creates paired batches to test context bleed.
// Batch A: [Privileged, Unprivileged]
// Batch B: [Unprivileged, Privileged]
// Control C: [Unprivileged] alone
func PairPrivilegedAndUnprivileged(privOp, unprivOp BatchSubOp) (forward []BatchSubOp, reverse []BatchSubOp, control []BatchSubOp) {
	forward = []BatchSubOp{privOp, unprivOp}
	reverse = []BatchSubOp{unprivOp, privOp}
	control = []BatchSubOp{unprivOp}
	return forward, reverse, control
}
