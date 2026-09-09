# DOGE Project Audit & Baseline State Assessment

**Date**: 2026-09-09  
**Version**: DOGE Alpha 1.0 (Phase 1 Closed-Loop Baseline)  
**Supervisor**: Senior Security Engineering & Research Supervisor  
**Build & Test Status**: `go test -count=1 ./...` PASSED (40+ packages, 100% clean), `go vet ./...` PASSED, `go build ./...` PASSED  

---

## 1. Executive Summary

DOGE has successfully transitioned from an initial collection of disconnected recon tools and database models into an operational, closed-loop autonomous security research engine. The Phase 1 milestone established:
1. Multi-factor Information Gain priority action ranking.
2. Structured hypothesis competition and falsification evaluation.
3. Persistent, bidirectional learning feedback across sessions.
4. Fail-closed runtime policy enforcement (rate-limits and concurrency semaphores).
5. A unified `ResearchAgent` orchestrator executing the 10-step cognitive cycle.
6. A deterministic end-to-end research trajectory test suite (`internal/e2e`).

However, to evolve DOGE into a senior-tier autonomous security research system capable of complex multi-step reasoning, differential authorization testing, and adversarial benchmarking, we must address critical architectural gaps outlined in this baseline.

---

## 2. Current Subsystem Capabilities & Status

| Subsystem | Component Path | Current Capability | Status |
|---|---|---|---|
| **Autonomous Research Loop** | `internal/research/agent.go`<br>`internal/research/loop.go` | Unified `ResearchAgent` coordinating: Ingest $\to$ Materialize $\to$ Hypothesize $\to$ Score $\to$ Scope Gate $\to$ Execute $\to$ Parse $\to$ Falsify $\to$ Learn $\to$ Replan. | **Operational & Verified** |
| **Information Gain Scoring** | `internal/planner/scoring.go`<br>`internal/planner/planner.go` | Multi-factor epistemic value scoring incorporating Confidence, Impact, Relevance, Info Gain, Novelty, Cost, Risk, and Learning Delta. | **Operational & Verified** |
| **Hypothesis & Falsification Engine** | `internal/hypothesis/engine.go`<br>`internal/hypothesis/evaluator.go`<br>`internal/hypothesis/competition.go` | Generates hypotheses (BOLA, SSRF, Auth Boundary, Anomaly); evaluates HTTP codes, error payloads, reflection, and OOB callbacks to transition states (`UNVALIDATED` $\to$ `REJECTED`/`SUPPORTED`/`CONFIRMED`). | **Operational & Verified** |
| **Learning & Feedback** | `internal/learning/feedback.go`<br>`internal/learning/memory.go` | Persists productive outcomes (+0.5 boost) and refutations/penalties (-0.6 to -0.8) into SQLite persistent memory across sessions. | **Operational & Verified** |
| **Scope & Runtime Policy** | `internal/scope/policy.go`<br>`internal/scope/scope.go` | Hard scope classifier (InScope, OutOfScope, ThirdParty) + token bucket rate limiter (`RateLimitPerSec`) + semaphore (`MaxConcurrency`). | **Operational & Verified** |
| **Human Approval Gates** | `internal/gates/gates.go` | Context-rich approval gates for high-risk tools and active validation steps. | **Operational & Verified** |
| **Tool Execution & Sandboxing** | `internal/runner/runner.go` | Process execution runner with timeout handling and platform-specific process attributes. | **Operational & Verified** |
| **Parser & Materialization** | `internal/parser/`<br>`internal/entity/` | 20+ specialized parsers (httpx, ffuf, katana, nmap, nuclei, gau, hakrawler, etc.) materializing into normalized entities and observations. | **Operational & Verified** |
| **Local LLM / Reasoning Engine** | `internal/reasoning/` | Ollama client with structured JSON schema validation, hallucination detection, and prompt grounding checks (`internal/aieval`). | **Operational (Deterministic fallback active)** |
| **CLI & TUI Console** | `cmd/workspace/`<br>`internal/tui/` | CLI commands (`doge start`, `research`, `investigate`, `scope`, `approvals`, `why`, `insights`, `graph`, `timeline`, `tasks`). | **Operational** |

---

## 3. Identified Architectural Gaps & Next Evolution Milestones

To satisfy the full Autonomous Security Research Evolution specification, the following capabilities must be designed and implemented:

### Milestone 1: Unified World Model & Relational Research Context (`Section 3 & 4`)
- **Current Limitation**: Entities and observations are stored as flat slices or SQLite tables; complex relational graphs (Principal $\to$ Account $\to$ Tenant $\to$ Object $\to$ Endpoint $\to$ Parameter $\to$ State) are not explicitly queryable.
- **Required**: `WorldModel` / `ResearchContext` abstraction maintaining connected entities, state machines, active uncertainties, and explicit `ResearchGap` trackers (e.g. `UNKNOWN_AUTHORIZATION_BOUNDARY`, `UNKNOWN_TENANT_ISOLATION`).

### Milestone 2: Principal-Aware Differential Research Engine (`Section 5 & 16`)
- **Current Limitation**: Probes execute without explicit multi-principal context (Anonymous vs User A vs User B vs Admin).
- **Required**: `DifferentialEngine` executing `SAME_OPERATION + DIFFERENT_PRINCIPAL = DIFFERENTIAL_OBSERVATION` comparing HTTP status, body structure, object identities, and authorization boundaries.

### Milestone 3: State-Machine & Workflow Research (`Section 6`)
- **Current Limitation**: No formal model of multi-step application state transitions.
- **Required**: State machine analyzer modeling `STATE_A → ACTION → STATE_B` to test for out-of-order transitions, privilege escalation, transition skips, and replay bugs.

### Milestone 4: Hypothesis Engine 2.0 & Epistemic Hierarchy (`Section 7`)
- **Current Limitation**: Linear hypothesis evaluation without multi-step discriminating experiments.
- **Required**: Competing hypothesis trees with discriminating experiment planning (e.g., $H_1$: Server retrieval vs $H_2$: Open redirect vs $H_3$: Client-side only) and full 10-tier epistemic transition tracking (`OBSERVATION` $\to$ `FACT` $\to$ `INFERENCE` $\to$ `HYPOTHESIS` $\to$ `PLAUSIBLE` $\to$ `SUPPORTED` $\to$ `CONTRADICTED` $\to$ `REJECTED` $\to$ `CONFIRMED` $\to$ `VALIDATED_FINDING`).

### Milestone 5: Layered Research Memory & Failure Learning (`Section 10, 11, 12`)
- **Current Limitation**: Flat pattern boost storage.
- **Required**: Layered memory architecture (`SHORT_TERM`, `SESSION_MEMORY`, `LONG_TERM_MEMORY`, `TOOL_MEMORY`, `HYPOTHESIS_MEMORY`, `TARGET_MEMORY`) with decay and explicit failure/noise penalty modeling.

### Milestone 6: Replayability, Session Persistence & Budget-Aware Autonomy (`Section 18, 19, 20`)
- **Current Limitation**: Limited session replay and budgeting.
- **Required**: `doge replay <session>`, session checkpoint recovery, and multi-dimensional budget governance (Time, Request, Action, Concurrency, Token budgets).

### Milestone 7: Adversarial Synthetic Benchmark Suite (`Section 23, 24, 25`)
- **Current Limitation**: Basic synthetic trajectory test.
- **Required**: Automated benchmark framework (`internal/benchmark`) evaluating DOGE against planted vulnerabilities (BOLA, Tenant Bypass, Multi-step Workflow, SSRF, PrivEsc) with distraction noise and strict quantitative metrics (Discovery Rate, False-Positive Rate, Time-to-Validation, Information Gain Per Action).

---

## 4. Test & Verification Baseline

- **Package Test Coverage**: 100% of internal packages compile and pass tests.
- **E2E Trajectory**: Demonstrates hypothesis refutation (403 tenant mismatch $\to$ `REJECTED`), SSRF confirmation via OOB interaction, learning feedback penalty/boost, and dynamic replanning.
- **Flakiness / Network Dependencies**: 0% (all tests run deterministically offline with synthetic mocks and isolated SQLite instances).

---

## 5. Evolution Roadmap & Implementation Order

1. **Step 1**: Build the **World Model & Research Gaps Subsystem** (`internal/worldmodel/`).
2. **Step 2**: Build the **Principal-Aware Differential Research Engine** (`internal/differential/`).
3. **Step 3**: Build the **State-Machine & Workflow Research Subsystem** (`internal/workflow/`).
4. **Step 4**: Upgrade **Hypothesis Engine 2.0** with Discriminating Experiments (`internal/hypothesis/`).
5. **Step 5**: Implement **Layered Memory & Failure Learning** (`internal/learning/`).
6. **Step 6**: Implement **Session Persistence, Replay Engine & Budget Controller** (`internal/session/`).
7. **Step 7**: Build the **Adversarial Research Benchmark Suite** (`internal/benchmark/`).
8. **Step 8**: Benchmark, Measure, and Iteratively Refine.
