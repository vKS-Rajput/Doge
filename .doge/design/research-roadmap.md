# DOGE Research Roadmap

## Guiding Question

Before implementing ANY feature:

> Does this make DOGE better at autonomous security research?
> Does it increase its ability to discover unknowns?
> Does it improve hypothesis generation? Experiment selection? Attack-chain discovery?
> Does it improve validation? Learning? Long-running research? Efficiency? Safety?
> Does it improve generalization to unseen vulnerabilities?

If not: **do not build it.**

---

## Milestone 1: Security Property Engine ← NEXT

**Goal**: DOGE reasons about security properties, not vulnerability classes.

**Benchmark**: Synthetic app with workflow state bypass (skip payment step).
DOGE discovers the violation by testing the property "workflow transitions cannot be skipped."

**Files**:
- `internal/property/property.go` — SecurityProperty definition
- `internal/property/evaluator.go` — Property evaluation against world model
- `internal/property/catalog.go` — Built-in property catalog (authorization, isolation, workflow, input, secrets)
- `internal/researcher/workflow.go` — WorkflowResearcher
- `internal/benchmark/synthetic_workflow.go` — Synthetic app with state bypass vulnerability

**Success criterion**: DOGE discovers workflow bypass through property reasoning, not pattern matching.

---

## Milestone 2: Attack Graph + Chain Discovery

**Goal**: DOGE discovers that individually weak observations form a critical attack chain.

**Benchmark**: Synthetic app where:
- SSRF exists (low severity alone)
- Internal admin endpoint exists (not directly accessible)
- SSRF + internal admin = critical (chain)

**Files**:
- `internal/attackgraph/graph.go` — Persistent attack graph
- `internal/attackgraph/chain.go` — Chain search algorithms
- `internal/attackgraph/scorer.go` — Chain impact scoring
- `internal/researcher/chain.go` — ChainResearcher
- `internal/benchmark/synthetic_chain.go` — Synthetic app requiring chain discovery

**Success criterion**: DOGE connects SSRF + internal admin into an attack chain with demonstrated impact.

---

## Milestone 3: Dynamic Mission Generation

**Goal**: Coordinator generates missions from world model state, not hardcoded phases.

**Benchmark**: Same synthetic apps, but coordinator decides research order autonomously. Measure: experiments per finding vs Phase 0 baseline.

**Files**:
- `internal/coordinator/gap_analyzer.go` — Analyze world model for research opportunities
- `internal/coordinator/mission_generator.go` — Generate candidate missions from gaps
- `internal/coordinator/scorer.go` — Score missions by expected information gain
- `internal/coordinator/dispatcher.go` — Dynamic researcher selection

**Success criterion**: Coordinator autonomously discovers vulnerabilities without hardcoded phase order.

---

## Milestone 4: LLM Integration

**Goal**: Real model providers replace deterministic heuristics for hypothesis generation and experiment design.

**Files**:
- `internal/model/ollama.go` — Ollama provider (wrapping existing reasoning/ollama.go)
- `internal/model/openai.go` — OpenAI-compatible API provider
- `internal/model/config.go` — Model configuration and selection

**Success criterion**: LLM-augmented hypothesis generation discovers vulnerabilities the deterministic provider cannot.

---

## Milestone 5: Continuous Research + Persistence

**Goal**: DOGE can pause, resume, and operate for hours.

**Files**:
- `internal/persistence/state.go` — Serialize/deserialize research state
- `internal/coordinator/session.go` — Session management with pause/resume
- `internal/coordinator/memory_compressor.go` — Compress old research memory
- `cmd/workspace/hunt.go` — `doge hunt` command

**Success criterion**: DOGE paused and resumed discovers the same vulnerability as a single continuous run.

---

## Milestone 6: Multi-Vulnerability Benchmark Suite

**Goal**: DOGE discovers multiple vulnerability types in a single engagement without being told what to look for.

**Benchmark**: Application containing 3+ different vulnerability types:
- BOLA (authorization)
- Workflow state bypass (logic)
- SSRF (input validation)

**Success criterion**: DOGE discovers all three through research, not enumeration.

---

## Milestone 7: Anomaly-Driven Novel Research

**Goal**: DOGE can say "I don't know what this is yet" and investigate.

```
Unexpected behavior → Anomaly → Security property hypothesis → Competing explanations
→ Discriminating experiment → Novel mechanism → Proof → Validation → Novel finding
```

**Success criterion**: DOGE discovers a planted novel vulnerability that doesn't match any standard vulnerability class in its catalog.

---

## Milestone 8: Self-Improvement Through Benchmarks

**Goal**: DOGE analyzes its own research trajectories and improves its research policy.

```
Experience → Trajectory analysis → Failure analysis → Research policy insight
→ Candidate strategy → Benchmark evaluation → Regression evaluation → Accept improvement
```

**Success criterion**: DOGE v(N+1) measurably outperforms v(N) on the benchmark curriculum.

---

## Milestone 9: Browser-Native Research

**Goal**: DOGE can reason about DOM, JavaScript, client-side state.

**Success criterion**: DOGE discovers a DOM XSS through browser-native research.

---

## Milestone 10: Source-Aware Research

**Goal**: DOGE integrates source code evidence with runtime evidence.

**Success criterion**: DOGE uses source code analysis to guide hypothesis generation, then proves runtime exploitability.

---

## Long-Term Research Program

| Goal | Category |
|---|---|
| Known vulnerability in known location | Benchmark Level 1 |
| Known vulnerability in unknown location | Benchmark Level 2 |
| Multi-step vulnerability | Benchmark Level 4 |
| Business logic vulnerability | Benchmark Level 5 |
| Attack chain (individually harmless → critical) | Benchmark Level 8 |
| Novel variant of known class | Benchmark Level 9 |
| Novel mechanism | Benchmark Level 10 |
| Previously unknown vulnerability | Benchmark Level 14 |
