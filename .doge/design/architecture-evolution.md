# DOGE Architecture Evolution

## From Vertical Slice to Research OS

### Phase 0: Vertical Slice ✅ (Complete)

**Proven**: BOLA discovery through complete research loop.

```
Target → Recon → Hypothesis → Authorization Researcher → Validation → Impact → Proven Finding
```

**Result**: 4 missions, 48 requests, 1 proven finding in 6ms.

---

### Phase 1: Security Property Reasoning + Attack Graph + Dynamic Dispatch

**The Three Highest-Leverage Capabilities**

These were selected because they **unlock the largest amount of future autonomous research capability**, not because they are easy.

#### 1. Security Property Reasoning (unlocks: generalization beyond BOLA)

**Why highest leverage**: Without this, every new vulnerability class requires a new hardcoded researcher. With this, DOGE reasons about **properties** and discovers **violations** — making it general-purpose.

```
Security Properties:
├── "Only authorized users can access resource X"
├── "Tenant A cannot access Tenant B's resources"
├── "A user cannot escalate privileges"
├── "Workflow transitions cannot be skipped"
├── "Untrusted input cannot influence privileged operations"
├── "Secrets cannot escape their intended context"
└── "External resources cannot be reached through unauthorized server-side primitives"

Vulnerabilities become: violations of security properties
```

**Implementation**:
- `internal/property/` — Security property definitions and evaluation
- Properties are testable assertions about the target
- World model tracks which properties have been tested, where, with what confidence
- Hypothesis engine generates hypotheses framed as "property P may not hold on endpoint E"
- Experiment engine designs experiments to test properties

#### 2. Attack Graph (unlocks: chain discovery, escalation, novel combinations)

**Why highest leverage**: Without this, DOGE finds individual issues. With this, DOGE discovers that A+B+C = critical — which is where the most valuable real-world findings exist.

```
Principal → Identity → Capability → Resource → Weakness → Access → New Capability → New Resource → Impact
```

**Implementation**:
- `internal/attackgraph/` — Persistent directed graph
- Nodes: Principal, Capability, Resource, Weakness, Access, Impact
- Edges: enables, requires, leads_to, unlocks, chains_with
- Operations: FindPaths, FindChains, GetUnexploredEdges, CombineWeaknesses
- Continuous: "Can these apparently unrelated observations form a security-relevant chain?"

#### 3. Dynamic Mission Generation from World Model (unlocks: open-ended autonomous research)

**Why highest leverage**: Without this, the coordinator runs phases in hardcoded order. With this, DOGE autonomously decides what to investigate next based on what it knows, what it doesn't know, and what would be most valuable to learn.

```
World Model → Research Gaps → Information Gain Scoring → Mission Generation → Researcher Selection → Dispatch
```

**Implementation**:
- Connect existing ResearchGapDetector → V2 MissionBrief generation
- Score candidate missions by expected information gain
- Dynamic researcher selection based on gap type, not phase number
- Coordinator becomes a true research director, not a phase sequencer

---

### Phase 2: Multi-Vulnerability Benchmark + Workflow Research

**Second benchmark**: A synthetic application requiring DOGE to discover a vulnerability through **security property violation** that is NOT BOLA. Must require reasoning the vertical slice can't do.

Candidate: **Workflow state bypass** — skip a required approval step by manipulating state transitions directly.

```
Required: Cart → Checkout → Payment → Confirmation
Attack:   Cart → Confirmation (skip payment via direct state manipulation)
```

This requires:
- State machine discovery
- Workflow modeling
- Property: "Workflow transitions cannot be skipped"
- Experiment: Attempt direct transition to final state
- Evidence: Successful state skip

---

### Phase 3: LLM Integration + Anomaly Research

- Ollama provider adapter (wrapping existing reasoning package)
- OpenAI-compatible API provider adapter
- Anomaly-driven hypothesis generation ("I cannot explain this behavior → investigate")
- Replace DeterministicProvider routing for hypothesis generation and experiment design

---

### Phase 4: Persistent Research + Continuous Operation

- Session persistence (SQLite schema for V2 state)
- Pause/resume capability
- Memory compression for long-running sessions
- Change detection integration
- CLI: `doge hunt`, `doge pause`, `doge resume`, `doge status`

---

### Phase 5: Benchmark Curriculum + Self-Improvement

- Levels 1-7 of benchmark curriculum
- Trajectory analyzer
- Regression suite
- Research policy optimization through benchmark performance analysis

---

## Architecture Principles

### 1. Loop-First Development
Never implement a subsystem without proving it works in the complete loop.

### 2. Prove Before Breadth
Each new capability must be demonstrated against a benchmark before adding the next.

### 3. Intelligence > Infrastructure
The intelligence is: research prioritization, hypothesis quality, experiment quality, evidence quality, learning. Not: more agents, more models, more tokens.

### 4. Lightweight Core
DOGE must run on a developer laptop. Scale when available, never require it.

### 5. Model-Agnostic
Every model-dependent component must work (at reduced capability) with the deterministic provider.

### 6. Evidence Is The Product
Every finding requires: observation → hypothesis → experiment → evidence → exploit → reproduction → validation → impact → proven finding.

### 7. Continuous Improvement Requires Measurement
No capability claimed without benchmark evidence. No regression accepted without trajectory analysis.
