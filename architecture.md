# DOGE Architecture: Security Research Operating Environment

**Version**: 3.0 (Autonomous Security Research Operating Environment)  
**Status**: Active Architectural Specification  
**Date**: 2026-09-12  
**Master Blueprint**: `.doge/design/DOGE-OPERATING-ENVIRONMENT-SPEC.md`

---

## Executive Summary

DOGE is an **autonomous, evidence-driven security research operating environment**. It is structured as a 4-tier system:
1. **The Cockpit**: Windows Native Application (Wails desktop shell)
2. **The Kernel**: DOGE Go Core Research Engine (World Model, SCM, MDL, Strategy Synthesizer, CEGAR, MAP-Elites, Cryptographic Proofs)
3. **The Laboratory**: WSL2 Linux Substrate (Managed, versioned, and isolated offensive toolchain)
4. **The Subject**: Authorized targets, source repositories, and networked services

DOGE treats vulnerability discovery as an **algorithmic scientific-discovery problem** governed by epistemic logic:
> **Target → World Model → Uncertainty Frontier → Causal Experiment → Cryptographic Evidence → Verified Knowledge**

**Key Architectural Principle**: The LLM is a **bounded, replaceable hypothesis/labeling source** — never the orchestrator, validator, or authority. The deterministic core owns authorization, scope, validation-truth, execution, and safety.

---

## 1. Overall System Architecture

### 1.1 Module Inventory

| Module | Responsibility | Location |
|--------|---------------|----------|
| **Operating Runtime** | Seam managing WSL laboratory, process streaming, .doge workspace, and local IPC/SSE | `internal/runtime/` |
| **Active Scanner** | Real-world reconnaissance, 13 vulnerability detectors, and cryptographic proof sealing | `internal/scanner/` |
| **Research Coordinator** | Central orchestration: plan → dispatch → debrief → loop | `internal/coordinator/` |
| **World Model** | Unified typed graph: principals, tenants, objects, endpoints, states, transitions, relationships, gaps | `internal/worldmodel/` |
| **Research Gap Detector** | Discovers untested properties, missing isolation boundaries, unknown state transitions | `internal/coordinator/gap_analyzer.go` |
| **Property System** | Testable security properties (not vulnerability classes) with epistemic states | `internal/property/` |
| **Invariant Miner** | Dynamic induction of behavioral invariants from execution traces | `internal/invariant/` |
| **Metamorphic Prober** | 3-way differential probes (forward/reverse/control) for context isolation | `internal/metamorphic/` |
| **Dimension Miner** | Latent behavioral basis discovery (temporal, encoding, serialization, pipeline, idempotency) | `internal/dimension/` |
| **Causal Engine** | Structural Causal Model + interventional surprise detection | `internal/causal/` |
| **CEGAR Synthesizer** | Counterexample-guided abstraction refinement → separating predicates | `internal/synthesis/` |
| **Ontology Expander** | Promotes validated anomalies to formal security concepts | `internal/ontology/` |
| **Researchers** | Short-lived focused workers: Recon, Authorization, Workflow, Anomaly, Validation, Impact | `internal/researcher/` |
| **Independent Verifier** | Deterministic claim verification against evidence (no LLM) | `internal/verification/` |
| **Model Router** | Multi-provider LLM routing with deterministic fallback | `internal/reasoning/`, `pkg/ai/` |
| **Learning System** | Layered memory with failure learning, strategy credit assignment | `internal/learning/` |
| **Session & Budget** | Replay, checkpointing, multi-dimensional budget governance | `internal/session/` |
| **Benchmark Suite** | Adversarial synthetic targets with planted vulnerabilities | `internal/benchmark/` |

### 1.2 Communication Paths

```
┌─────────────────────────────────────────────────────────────────────┐
│                        RESEARCH COORDINATOR                         │
│  (Deterministic Core — Owns Auth, Scope, Validation, Execution)    │
└────────────────────────────┬────────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   ┌─────────┐         ┌───────────┐        ┌──────────┐
   │ World   │         │  Property │        │  Gap     │
   │ Model   │◄───────►│  Catalog  │◄──────►│ Detector │
   │ (Graph) │         │           │        │          │
   └────┬────┘         └─────┬─────┘        └────┬─────┘
        │                    │                    │
        ▼                    ▼                    ▼
   ┌─────────────────────────────────────────────────────┐
   │              RESEARCHER DISPATCH                     │
   │  Recon │ Authorization │ Workflow │ Anomaly │ Impact │
   └──────────────────────┬──────────────────────────────┘
                          │
                          ▼
   ┌─────────────────────────────────────────────────────┐
   │              EXPERIMENT EXECUTION                    │
   │  HTTP Client → Evidence Capture → Mission Result     │
   └────────────────────────────┬────────────────────────┘
                          │
                          ▼
   ┌─────────────────────────────────────────────────────┐
   │              DEBRIEF & WORLD MODEL UPDATE            │
   │  Observations → Hypotheses → Candidates → Validated  │
   │  → Impact → Proven Findings → Concept Learning       │
   └─────────────────────────────────────────────────────┘
```

**Two paths, not one**:
- **Write path (async, event-driven)**: File Watcher → Parser → KB → Timeline → Memory → UI
- **Read path (synchronous, direct)**: TUI, Search, AI Context Builder query KB directly

---

## 2. The Research Loop (Mathematical Specification)

### 2.1 State Definitions

```
S_t          : Hidden target state (unobserved)
O_t          : Observation = G(S_t, A_t, N_t) — what execution returns
A_t ∈ A_auth : Authorized intervention/experiment
W_t          : Unified typed world-model graph (V_t, E_t, τ)
B_t          : Belief = version space of hypotheses not yet falsified + confidence
F_t          : Frontier = {v ∈ W_t : confidence(v) < c_min ∨ Anomaly(v) > a_min}
H_t          : Hypothesis = candidate relation in Concept/Causal Graph, tagged with source + validation status
E_t          : Experiment = (I, C, A, O) — grammar-composed, Pareto-selected
J(π)         : Objective = E_π[ΔL(K) + λ₁I(S_t;O_t|A_t) + λ₂ImpactPotential]
ρ            : Ontology-expansion operator ρ:(O_{1:t}, K_t) → K_{t+1}, K_{t+1} ⊇ K_t
D            : Discovery operator — promotes validated MDL-anomalous hypothesis to new Concept Graph node
N            : Novelty operator — structural-similarity check against Concept/Strategy Graph
Stop         : Budget exhausted ∨ frontier confidence > threshold ∨ marginal J/cost < floor for k steps
```

### 2.2 The Autonomous Loop (Refined)

```
while budget_remaining and not Stop(W, budget):

    O = observe_authorized(select_probe(W))          # deterministic, scoped
    W.update(O)                                       # unified graph update

    anomalies = mdl_anomaly_scan(W)                    # Part 6
    for a in anomalies:
        relation = abstract(a, W)                       # structural abstraction
        match = structural_match(relation, W.concepts)  # graph similarity
        if match is None:
            concept = provisional_concept(relation)      # new node, unnamed
            W.concepts.add(concept)
            H = spawn_hypothesis(concept)
        else:
            H = refine_hypothesis(match, relation)       # version-space narrowing

        candidates = synthesize_experiments(H, W)         # grammar composition
        frontier_set = pareto_front(candidates,           # multi-objective
                                     axes=[info_gain, novelty, sec_relevance],
                                     costs=[cost, risk])
        E = select_from_frontier(frontier_set, rule=DETERMINISTIC_POLICY)
        E = typecheck_against_authorization(E)            # structurally rejects unsafe E
        if E is None:
            continue

        result = execute_authorized(E)
        W.update(result)

        if falsifies(H, result):
            H = narrow_or_enlarge(H, result)              # CEGAR-style
        elif supports(H, result) and independent_validate(H, W):
            impact = safely_demonstrate(H)                 # bounded, authorized only
            finding = produce_proven_finding(H, impact)
            W.concepts.name(finding.concept, via=llm_naming_only)  # LLM: labeling ONLY
            learn_strategy_credit(current_strategy, finding)

    W.decay_stale_confidence()   # keeps frontier honest over long runs
```

**Key Refinements vs. Prior Drafts**:
- Anomaly detection → concept discovery **before** hypothesis generation (catches novel-ontology cases)
- Pareto-based experiment selection (not single greedy `select_experiment`)
- LLM touchpoint isolated to exactly **one line** (`llm_naming_only`) with zero effect on correctness

---

## 3. World Model: The Unified Typed Graph

### 3.1 Why a Single Graph?

**Anti-pattern to avoid**: Separate Attack Graph, Causal Graph, Knowledge Graph, Concept Graph, Strategy Graph, Evidence DB → synchronization nightmares.

**DOGE's approach**: One typed attributed graph `W_t = (V_t, E_t, τ)` where node/edge *types* correspond to roles (state, capability, invariant, hypothesis, experiment, evidence, concept, strategy). Different "views" are **queries/projections** over this one structure.

```
                    WORLD MODEL (W_t)
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
    Attack View     Causal View      Concept View
   (capability      (intervention     (induced
    composition)     edges, SCM)        concepts)
         │               │               │
         └───────────────┼───────────────┘
                         ▼
                  Strategy View
           (learned DSL strategies)
```

**Every edge carries provenance**: source experiment, timestamp, confidence, target, evidence, causal provenance → auditable, diffable, cross-target transferable.

### 3.2 Core Entity Types

| Entity | Type ID | Key Fields |
|--------|---------|------------|
| **Principal** | `Principal` | id, credentials, user_id, tenant_id, role |
| **Tenant** | `Tenant` | id, name, isolation_level |
| **Account** | `Account` | id, principal_id, tenant_id, type |
| **ObjectResource** | `ObjectResource` | id, type, identifier, owner_principal_id, tenant_id, endpoint_id |
| **EndpointModel** | `EndpointModel` | id, host, path, method, url, requires_auth, required_roles, parameters[] |
| **ParameterModel** | `ParameterModel` | id, name, location, is_url_parameter, endpoint_id |
| **StateNode** | `StateNode` | id, name, type (auth, workflow, session), properties |
| **StateTransition** | `StateTransition` | id, from_state, to_state, action, preconditions, postconditions |
| **ResearchGap** | `ResearchGap` | id, type (UNKNOWN_AUTH_BOUNDARY, UNKNOWN_TENANT_ISOLATION, etc.), uncertainty, status |

### 3.3 Relationship Types (`domain.RelationshipType`)

- `RelOwnsObject` — Principal → Object
- `RelPartOf` — Tenant → Object
- `RelAcceptsParam` — Endpoint → Parameter
- `RelTransitionsTo` — StateNode → StateNode
- `RelLeadsTo` — Endpoint → Capability/Weakness
- `RelHasEvidence` — Hypothesis → Evidence
- `RelViolates` — Experiment → SecurityProperty

### 3.4 Gap Detection

`ResearchGapDetector` analyzes the world model + property catalog to produce gaps:

```go
type Gap struct {
    Property   *property.SecurityProperty
    Priority   float64  // information-gain score
    Reason     string
    Target     string   // endpoint/asset the property applies to
    CreatedAt  time.Time
}
```

Gaps drive mission planning: untested properties → high information gain → prioritized missions.

---

## 4. Property-Based Security Reasoning

### 4.1 Properties vs. Vulnerability Classes

**Traditional**: Scan for SQLi, XSS, IDOR, SSRF — fixed taxonomy.

**DOGE**: Properties are testable assertions about what **should be true**:
- "Only authorized principals can access resource X" (Authorization)
- "Tenant A cannot access Tenant B's resources" (Isolation)
- "Workflow transitions cannot be skipped" (Workflow Integrity)
- "Untrusted input cannot influence privileged operations" (Input Validation)

When a property is **violated**, that violation **IS the vulnerability** — regardless of whether it matches a known CWE.

### 4.2 Epistemic States

```
StateUnknown ──(test)──► StateSupported ──(more evidence)──► StateValidated
     │                        │
     │                        └──(contradiction)──► StateContradicted ──► StateViolated
     │
     └──(assume)──► StateAssumed ──(test)──► StateSupported/Contradicted
     │
     └──(identified untested)──► StateUntested
```

### 4.3 Information Gain Scoring

```
StateUnknown:           1.0 * Priority           // Maximum — we know nothing
StateAssumed:           0.9 * Priority           // High — assumption needs testing
StateUntested:          0.85 * Priority          // High — known untested
StatePartiallyTested:   0.5 * (1-Confidence) * P // Proportional to remaining uncertainty
StateSupported:         0.3 * (1-Confidence) * P // Low — could be wrong
StateContradicted:      0.7 * Priority           // High — need to confirm/reject
StateViolated:          0.1 * (1-Confidence) * P // Very low — mostly known
StateValidated:         0.0                      // Zero — independently confirmed
```

---

## 5. Researchers: Short-Lived Focused Workers

### 5.1 Researcher Interface

```go
type Researcher interface {
    Type() domain.ResearcherType
    Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error)
}
```

Each researcher receives a `MissionBrief`, executes bounded experiments, returns structured `MissionResult`. Researchers are **retired after each mission** to prevent bias accumulation.

### 5.2 Researcher Types

| Type | Purpose | Key Technique |
|------|---------|---------------|
| **Recon** | Map attack surface: endpoints, auth, tenants, objects | Parsing + entity extraction |
| **Authorization** | Cross-principal differential testing (BOLA/IDOR) | `SAME_OPERATION + DIFFERENT_PRINCIPAL = DIFFERENTIAL_OBSERVATION` |
| **Workflow** | State machine mapping + transition integrity testing | StateNode/StateTransition registration |
| **Anomaly** | Unknown-space metamorphic probing | Invariant induction + 3-way differential probes |
| **Validation** | Independent reproduction with fresh context | Deterministic confirmation/refutation |
| **Impact** | Bounded impact demonstration within authorization | Evidence collection for proven finding |

### 5.3 Authorization Researcher (Differential Engine)

**Core insight**: `SAME_OPERATION + DIFFERENT_PRINCIPAL = DIFFERENTIAL_OBSERVATION`

```
Principal A (Tenant 1) → GET /api/v1/items/{B's_item} → 200 OK (VULNERABLE)
Principal A (Tenant 1) → GET /api/v1/users/{B's_id}   → 403 FORBIDDEN (CORRECT)
                                                      ↑
                                          Differential proof:
                                          Items endpoint missing authz middleware
```

### 5.4 Anomaly Researcher (Metamorphic + Invariant Induction)

**Three anomaly families discovered**:
1. **Batch Pipeline Context Bleed** — Authorization state persists across execution frames
2. **Latent Race Window** — Asynchronous balance check allows overdraw (temporal_concurrency)
3. **Cache Normalization Collision** — Proxy path cleaning exposes private reports (encoding_normalization)

**3-way metamorphic probe**:
```
Forward:  [Privileged Op, Unprivileged Op] → Unprivileged succeeds (context bleed)
Reverse:  [Unprivileged Op, Privileged Op] → Unprivileged fails (control)
Control:  Unprivileged Op alone            → Unprivileged fails (baseline)
```

---

## 6. Causal Reasoning & Experiment Synthesis

### 6.1 Structural Causal Model (SCM)

Variables = latent dimensions + observed endpoints + security properties.
Edges = causal relationships induced from differential experiments.

```
Intervention(I) on Variable X
    │
    ├─► Outcome Y changes? ── YES ──► Causal edge X → Y
    │
    └─► Outcome Y unchanged ── NO ──► No causal edge
```

### 6.2 CEGAR Synthesis

Counterexample-Guided Abstraction Refinement synthesizes **separating predicates** that distinguish vulnerable from safe executions.

```go
// Example: Temporal Concurrency (Race Condition)
Formula: (Endpoint == /wallet/transfer) && (Delta_t < 40ms) && (Concurrent_Bursts > 1)

// Example: Encoding Normalization (Cache Collision)
Formula: (CacheKey(Req) == '/public') && (BackendPath(Req) CONTAINS '..%2F')

// Example: Pipeline Interleaving (Batch Context Bleed)
Formula: (Batch_SubOps[0].IsPrivileged == true) && (Batch_SubOps[1].InheritsContext == true)
```

These predicates become **reproduction templates** for future targets — cross-target transfer.

---

## 7. Ontology Expansion: Discovering New Concepts

### 7.1 The Representation-Expansion Operator ρ

```
ρ: (O_{1:t}, K_t) → K_{t+1},  where K_{t+1} ⊇ K_t

K_t = {vuln classes, security properties, transformations, experiment families}
```

### 7.2 Pipeline: Anomaly → New Concept

```
1. DETECT    — MDL anomaly score fires (observation resists current ontology)
2. ABSTRACT  — Represent as typed relation over world-model graph:
               (actor, resource, action, expected_denial, observed_allow, invariant_violated)
3. CLUSTER   — Graph edit distance / relational similarity vs. Concept Graph
4. NAME      — LLM proposes human-readable label (ONLY labeling, zero correctness impact)
5. GENERALIZE — Spawn experiment-family template parameterized over new relation
```

**Why structural not textual?** `Graph similarity` catches "same shape, different labels" — formal concept analysis / ILP-style, not text classification.

### 7.3 SecurityConcept Structure

```go
type SecurityConcept struct {
    ConceptID            string       // CONCEPT_BATCH_CONTEXT_BLEED_A1B2C3D4
    Name                 string       // "Batch Pipeline Context Bleed"
    Dimension            string       // "pipeline_interleaving"
    SeparatingPredicate  string       // CEGAR formula
    ViolationType        string       // DimensionType
    Severity             domain.Severity
    ReproductionTemplate string       // Parameterized steps
    Description          string
    LearnedAt            time.Time
    EmpiricalEvidenceCount int
}
```

---

## 8. Independent Verification (Deterministic)

### 8.1 Verification Layers (No LLM)

1. **Evidence ID Validation** — cited IDs exist?
2. **Claim Category Validation** — appropriate category?
3. **Entity/Relationship Matching** — evidence contains referenced entities?
4. **Structured Field Comparison** — evidence attributes support claim properties?
5. **Contradiction Detection** — evidence contradicts claim?
6. **Vulnerability Claim Gate** — vuln claims require explicit vuln evidence, not mere existence
7. **Provenance Consistency** — claim references entity X, evidence references X (not Y sharing keywords)

### 8.2 Key Rule: Vulnerability Claims Need Vulnerability Evidence

```go
// Claim: "admin.example.com is vulnerable to IDOR"
// Evidence: "admin.example.com exists" → UNSUPPORTED
// Required: Evidence showing cross-tenant access GRANTED
```

The LLM can **hypothesize** vulnerabilities; the Verifier **confirms** them.

---

## 9. LLM Integration: Bounded, Replaceable, Authority-Free

### 9.1 What LLMs Do (Narrow Interface)

| Task | Why LLM | Correctness Impact |
|------|---------|-------------------|
| **Document grounding** | Extract invariants from unstructured prose (API docs, ToS, comments) | Low — output goes to hypothesis generation, validated downstream |
| **Concept naming** | Human-readable label for induced concept | **Zero** — underlying relation already correct |
| **Strategy explanation** | Human-readable rationale for reviewers | Zero — strategy evaluated by discovery rate, not explanation |
| **Cross-domain bridging** | Recognize structural pattern match across disjoint domains | Low — mapped relation verified by experiment |

### 9.2 What LLMs NEVER Do

| Forbidden | Enforcement |
|-----------|-------------|
| Authorization decisions | Type-level in experiment DSL — unsafe experiments cannot be constructed |
| Validation truth | Deterministic Verifier owns `StatusSupported`/`StatusUnsupported` |
| Execution | Only deterministic HTTPClient runs requests |
| Scope/budget/safety | Coordinator enforces via hardcoded policy |

### 9.3 Model Routing

```
┌──────────────────────────────────────────┐
│         MODEL ROUTER (ai.ModelRouter)    │
│  Common interface: Dispatch(ReasoningRequest) │
└────────────────┬─────────────────────────┘
                 │
     ┌───────────┼───────────┐
     ▼           ▼           ▼
 Local Model  Frontier API  Deterministic
 (Ollama)     (OpenRouter)  Fallback (always)
```

- All providers scored on rolling basis by **proposal survival rate**
- If all LLM providers vanish → deterministic core unaffected (owns everything downstream)

---

## 10. Learning System: Strategy Discovery

### 10.1 Layered Memory Architecture

| Layer | Scope | Decay | Purpose |
|-------|-------|-------|---------|
| **Short-term** | Current session | None | Active hypotheses, recent evidence |
| **Session** | Current investigation | TTL | Patterns within engagement |
| **Long-term** | Cross-target | Slow decay | Transferable concepts, strategies |
| **Tool** | Per-tool | Medium | Tool-specific effectiveness |
| **Hypothesis** | Per-hypothesis-type | Fast | Hypothesis-class win rates |
| **Target** | Per-target | Very slow | Target-specific baselines |

### 10.2 Strategy Representation

Strategy = small program in constrained DSL:
```
{observe, hypothesize-template, experiment-template, stopping-rule}
```

Evaluated by running against held-out benchmarks → scored by **discovery rate per unit cost**.

**Program synthesis over strategies** — search over bounded DSL, guided by evaluation.

### 10.3 Failure-Driven Update (CEGAR-style)

Every failed experiment = counterexample to current hypothesis:
- (a) Narrower hypothesis consistent with all evidence, OR
- (b) Flag: hypothesis class needs enlarging → routes back to ontology expansion

**Monotonic non-regression**: System never re-tests what it has falsified (falsification stored as constraint).

### 10.4 Meta-Learning (Phase 4+)

```
Strategy 1 → fails
Strategy 2 → partial
Strategy 3 → finds anomaly
    │
    └─► Combine successful components → New Strategy
        │
        ├─► Benchmark
        │
        └─► Retain if superior
```

DOGE learns **better research algorithms**, not just better payloads.

---

## 11. Cross-Target Transfer

### 11.1 What Transfers

| Transfers | Does NOT Transfer |
|-----------|-------------------|
| Abstract causal mechanisms | Raw endpoint signatures |
| Induced SecurityConcepts | Target-specific credentials |
| Learned DSL strategies | Target-specific object IDs |
| Dimension parameters (window_ms, encodings) | Target-specific workflow states |

### 11.2 Structural Isomorphism Recognition

Target A discovers:
```
Actor state transition → authorization evaluated using stale state → resource accessible
```

Target B (different API, framework, language, DB):
```
DOGE recognizes: G_A ≅ G_B at abstract relational level
```

**Mechanism**: Compare/merge typed subgraphs from World Model — not conversation transcripts.

### 11.3 Transfer Protocol

1. After finding: extract minimal validated structural relation + DSL strategy
2. Store with confidence decay + provenance
3. New target: seed frontier-selection with strategies ranked by past success
4. **Require independent re-validation** on new target before reporting (no negative transfer)

---

## 12. Attack-Chain Discovery: AND/OR Hypergraph

### 12.1 Capability Graph → AND/OR Hypergraph

- **OR-nodes**: Alternative ways to reach a capability
- **AND-nodes**: Capabilities that must jointly hold
- **Edges**: Discovered capabilities with typed pre/post-conditions

### 12.2 MCTS Search with Novelty/Impact Bias

```
Capability A (Auth bypass)
    +
Capability B (Object enumeration)
    +
Capability C (Privilege escalation)
    ↓
New reachable capability (Full account takeover)
```

Emerges **without hardcoded chain templates** — each edge individually discovered by unrelated experiments, composed by hypergraph search.

**Requirement**: Capabilities represented with rich typed pre/post-conditions (world-model design, not search algorithm).

---

## 13. Safety & Governance (Deterministic Invariants)

### 13.1 Four Hard Invariants (Never Relaxed)

1. **AI never independently executes** security tools, sends requests, attempts exploitation
2. **AI activates only on triggers**: new file, file change, explicit question, explicit analyze command
3. **AI never fabricates findings** — "I do not have evidence" is correct output when unsupported
4. **Every AI claim traceable** to specific stored artifact — untraceable claims don't ship

### 13.2 Authorization Enforcement

```go
// Experiment DSL — unsafe experiments CANNOT BE CONSTRUCTED (type-level)
type Experiment struct {
    Action   AuthorizedAction  // Only pre-approved actions type-check
    Target   InScopeTarget     // Scope enforced at construction
    Budget   BudgetConstraints // Time/request/concurrency/token budgets
}
```

### 13.3 Human Approval Gates

```
AI Hypothesis → Human Approves → Validation Runs
Candidate Finding → Human Confirms → Confirmed Finding
```

Learning system changes **ranking/context only** — NEVER scope, authorization, safety constraints.

---

## 14. Benchmarking & Falsification

### 14.1 Critical Benchmarks (Stress-Test the Core Bet)

| Benchmark | Tests |
|-----------|-------|
| **C: Unmodeled Vulnerability Class** | MDL anomaly → new concept pipeline |
| **D: Adversarial Target Behavior** | Rate limits, canaries, honeypots — causal model vs transcript |
| **J: Genuinely Novel Mechanism** | Out-of-ontology discovery rate |

**Falsification criterion**: If algorithm-only DOGE performs no better than random fuzzing on C/D/J, the MDL-anomaly-to-concept mechanism has failed.

### 14.2 Ablation Priority (Predicted Impact)

1. **MDL anomaly detection** — largest drop in novel-discovery
2. **Unified world-model graph** — flat log replacement causes sync bugs
3. **Pareto experiment selection** — greedy loses diversity
4. **LLM naming layer** — almost no drop (only labeling)

### 14.3 Adversarial Synthetic Suite

`internal/benchmark/` contains planted-vulnerability targets:
- BOLA (cross-tenant item access)
- Tenant isolation bypass
- Multi-step workflow skip
- SSRF via server-side primitives
- Privilege escalation chains

With **distraction noise** and strict metrics:
- Discovery Rate, False-Positive Rate, Time-to-Validation, Info-Gain/Action

---

## 15. Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| **Core Language** | Go 1.23+ | Single binary, no runtime, cross-platform, strong concurrency |
| **Database** | SQLite + sqlite-vec | Embedded, zero-config, vector search for embeddings |
| **TUI** | Bubble Tea + Lipgloss | Terminal-native, lazygit/k9s UX |
| **Event Bus** | Go channels (in-process) | No daemon needed, daemon-mode upgrade path available |
| **LLM** | ModelRouter → Ollama/OpenRouter/Deterministic | Swappable, scored by proposal quality |
| **Parsers** | 25+ tool-specific (nmap, httpx, nuclei, ffuf, katana, ...) | Auto-capture from researcher's workflow |
| **Testing** | Go test + race detector + integration | 100% offline deterministic tests |

---

## 16. Implementation Status & Roadmap

### 16.1 Completed (Phases 1-3)

- ✅ Research Coordinator with full mission loop
- ✅ World Model with unified typed graph
- ✅ Property system with epistemic states
- ✅ Authorization differential engine
- ✅ Anomaly researcher (metamorphic + invariant induction)
- ✅ Dimension miner (5 latent dimensions)
- ✅ Causal SCM + CEGAR synthesis
- ✅ Ontology expander with concept learning
- ✅ Independent deterministic verifier
- ✅ Layered learning with failure learning
- ✅ Session persistence + replay + budgets
- ✅ Adversarial benchmark suite (7 scenarios)

### 16.2 In Progress / Next (Phase 4+)

- [ ] **Hypothesis Engine 2.0**: Competing hypothesis trees + discriminating experiments
- [ ] **10-tier epistemic hierarchy**: OBSERVATION → FACT → INFERENCE → HYPOTHESIS → PLAUSIBLE → SUPPORTED → CONTRADICTED → REJECTED → CONFIRMED → VALIDATED_FINDING
- [ ] **Strategy DSL + Program Synthesis**: Automated strategy discovery/evaluation
- [ ] **Cross-target structural isomorphism**: Graph matching for causal transfer
- [ ] **Meta-learning loop**: Strategy composition from components

### 16.3 Ultimate Vision (Phase 5+)

> **Can DOGE automatically discover, evaluate, and transfer entirely new security-research strategies across previously unseen targets, while its deterministic core remains capable of operating with zero LLM availability?**

This connects: **Ontology Expansion → Cross-Target Transfer → Strategy Discovery → Meta-Learning**

---

## 17. Design Decisions Summary

| Decision | Rationale |
|----------|-----------|
| **Single unified world-model graph** | Avoids multi-store sync bugs; views = queries |
| **Properties not vulnerability classes** | Generalizes beyond fixed taxonomy; violation = vulnerability |
| **MDL anomaly as discovery signal** | Finds "resists explanation" not just "crashes/changes status" |
| **Pareto experiment selection** | Novelty/info-gain/security-relevance not commensurable in single ratio |
| **LLM only for naming/grounding** | Zero correctness impact; graceful degradation if LLM absent |
| **Researchers short-lived + retired** | Prevents bias accumulation; each mission fresh |
| **Deterministic verification** | LLM hallucinations caught at gate; never become findings |
| **Type-level safety in experiment DSL** | Unsafe experiments structurally unrepresentable |
| **CEGAR for predicate synthesis** | Minimal separating formulas; auditable, composable |
| **Strategy as DSL program** | Searchable, evaluatable, transferable, composable |

---

## 18. File Organization Reference

```
cmd/workspace/           CLI commands (work, monitor, notebook, investigate, ...)
internal/
├── coordinator/         ResearchCoordinator + GapAnalyzer
├── worldmodel/          Unified typed graph + gap detector
├── property/            Security properties + epistemic states + catalog
├── invariant/           Dynamic invariant induction
├── metamorphic/         3-way differential probing
├── dimension/           Latent behavioral basis (5 dimensions)
├── causal/              Structural Causal Model + interventions
├── synthesis/           CEGAR separating predicate synthesis
├── ontology/            Dynamic concept expansion + naming
├── researcher/          6 specialized researchers
├── verification/        Deterministic claim verifier
├── reasoning/           LLM integration (bounded, replaceable)
├── learning/            Layered memory + strategy credit
├── session/             Replay, checkpoint, budgets
├── benchmark/           Adversarial synthetic targets
├── attackgraph/         AND/OR hypergraph + MCTS
├── parser/              25+ tool parsers
├── entity/              Knowledge graph materialization
├── correlation/         Entity relationship detection
├── coverage/            Evidence-derived coverage
├── opportunity/         Research opportunity ranking
├── insight/             Pattern detection
├── finding/             Validated finding pipeline
├── validation/          Evidence validation
├── timeline/            Temporal event tracking
├── search/              Hybrid keyword+semantic search
├── tui/                 Terminal UI (Bubble Tea)
├── bus/                 In-process event bus
├── cache/               Query + embedding cache
├── config/              Configuration management
├── logging/             Structured logging + redaction
├── db/                  SQLite + migrations
├── runner/              Command execution + capture
├── journal/             Command history
├── watcher/             Filesystem change detection
├── watch/               Watch orchestrator
├── scheduler/           Mission scheduling
├── scope/               Authorization scope policy
├── gates/               Human approval gates
├── integration/         End-to-end integration tests
└── e2e/                 Full trajectory tests
pkg/
├── domain/              Core types (Observation, Entity, Evidence, Hypothesis, Finding, ...)
├── ai/                  ModelRouter, providers, types
├── events/              Event type definitions
└── errors/              Shared error types
```

---

## 19. Conclusion

DOGE is **not** an LLM agent wrapper. It is a **deterministic autonomous security research system** with a bounded LLM component used only for:
- Natural-language grounding (docs → invariants)
- Concept naming (induced relations → human labels)
- Cross-domain pattern bridging (verified by experiment)

The core discovery loop — **MDL anomaly → structural abstraction → causal experiment → ontology expansion → strategy learning** — operates fully algorithmically and is **falsifiable on Benchmarks C/D/J**.

This architecture transforms DOGE from "autonomous pentester" to **"autonomous security science system"** — the genuine research contribution.

---

*Generated from analysis of implementation (334 Go files) and design documents (.doge/design/*.md)*