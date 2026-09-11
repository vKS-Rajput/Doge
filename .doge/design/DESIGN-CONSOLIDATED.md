# DOGE Architecture — Consolidated Design Document

**Status**: Complete  
**Sources Integrated**: design.md (File 1 — scientific core), deep-research-report.md (File 2 — multi-agent survey), doge-next-report.md (spec), architecture.md, README.md, DOGE_CURRENT_STATE.md  
**Date**: 2026-09-11

---

## The Core Architectural Thesis

DOGE is an **autonomous security research system** — not an LLM agent wrapper. It treats vulnerability discovery as **algorithmic scientific discovery** with:

1. **MDL anomaly detection** — observations that resist explanation under current ontology
2. **Ontology expansion** (ρ operator) — promoting validated anomalies to new concepts  
3. **Causal experimentation** — structured hypothesis falsification via differential testing  
4. **Unified world-model graph** — all knowledge in one typed structure (W_t = (V_t, E_t, τ))  
5. **LLM bounded to naming/grounding only** — zero authority, zero correctness impact

The 7 previously deleted design files (architecture-evolution.md, benchmark-roadmap.md, capability-map.md, open-research-problems.md, representation-discovery.md, research-roadmap.md, ultimate-vision.md) have their content incorporated below. They were deleted because this document supersedes them.

---

## 1. What Was Integrated (Deleted Files)

### architecture-evolution.md
Phase 0: Vertical slice — BOLA discovery through full loop (4 missions, 48 requests, 1 finding in 6ms). Phase 1: Security Property + Attack Graph + Dynamic Dispatch. Phase 2: Benchmark + Workflow. Phase 3: Multi-vuln benchmark. Phase 4: LLM Integration.

### benchmark-roadmap.md
Benchmark framework A–J with critical stress tests C (unmodeled vulnerability class) and J (genuinely novel mechanism). Falsification: algorithm-only DOGE must outperform fuzzing on C/J.

### capability-map.md
Module inventory: Coordinator, World Model, Property Catalog, Gap Analyzer, Invariant Miner, Metamorphic Prober, Dimension Miner, Causal SCM, CEGAR Synthesizer, Ontology Expander, 6 Researchers, Independent Verifier, Model Router, Learning System.

### open-research-problems.md
(1) Cross-target structural isomorphism (G_A ≅ G_B at abstract level). (2) Strategy DSL + program synthesis. (3) Meta-learning loop. (4) Non-stationary target adaptation.

### representation-discovery.md
Pipeline: Detect → Abstract (typed relation) → Cluster (structural similarity, not text) → Name (LLM labeling ONLY) → Generalize (experiment-family template).

### research-roadmap.md
Milestones 1–4: Security Property Engine → Attack Graph → Dynamic Mission Generation → LLM Integration. Guiding question: "Does this make DOGE better at discovering unknowns?"

### ultimate-vision.md
Vision: "Can DOGE automatically discover, evaluate, and transfer entirely new security-research strategies across unseen targets with zero LLM availability?" Connects ontology → transfer → strategy discovery → meta-learning.

---

## 2. Design vs. Implementation — Verification Status

| Design Element | Implementation | Status |
|---------------|---------------|--------|
| Research Coordinator with loop | `internal/coordinator/coordinator.go` | DONE |
| World Model (unified typed graph) | `internal/worldmodel/worldmodel.go` | DONE |
| Gap Detector | `internal/coordinator/gap_analyzer.go` | DONE |
| Security Properties | `internal/property/` | DONE |
| Invariant Miner | `internal/invariant/` | DONE |
| Dimension Miner | `internal/dimension/` | DONE (5 dimensions) |
| Metamorphic Prober | `internal/metamorphic/` | DONE (3-way differential) |
| Causal SCM | `internal/causal/` | DONE |
| CEGAR Synthesizer | `internal/synthesis/cegar.go` | DONE (4 dimension predicates) |
| Ontology Expander | `internal/ontology/expander.go` | DONE (concept growth + LLM naming) |
| Researchers (6) | `internal/researcher/` | DONE (Auth, Anomaly, Workflow, Recon, Validation, Impact) |
| Independent Verifier | `internal/verification/verifier.go` | DONE (7-layer deterministic) |
| Model Router | `pkg/ai/` | DONE (multi-provider, deterministic fallback) |
| Benchmark Suite | `internal/benchmark/` | DONE (7 synthetic scenarios) |
| Session + Budget | `internal/session/` | DONE |

---

## 3. LLM Boundaries — Enforced in Code

Per the design hard rule: LLM touches **only one line** — concept naming.

- `ontology/expander.go:55-63` — LLM used ONLY for `TaskConceptNaming`
- `verification/verifier.go:19` — "The Verifier is deterministic. No LLM is used."
- `coordinator/coordinator.go:139-140` — `NewModelRouter("deterministic_brain")` with deterministic provider registered

**What LLM never does (enforced by architecture, not policy):**
- Authorization → Experiment DSL type-checks against `AuthorizedAction`
- Validation → `verifier.Verify()` is deterministic
- Execution → Only `HTTPClient` runs requests
- Scope → Coordinator hardcodes budgets and targets
- Finding truth → Only verified evidence produces `ProvenFinding`

---

## 4. The Research Loop (Mathematical)

```
while budget_remaining and not Stop(W, budget):

    O = observe_authorized(select_probe(W))          # deterministic, scoped
    W.update(O)                                       # unified graph update

    anomalies = mdl_anomaly_scan(W)                    # Part 6
    for a in anomalies:
        relation = abstract(a, W)                       # typed relation
        match = structural_match(relation, W.concepts)  # graph similarity
        if match is None:
            concept = provisional_concept(relation)      # new node
            W.concepts.add(concept)
            H = spawn_hypothesis(concept)
        else:
            H = refine_hypothesis(match, relation)       # version-space narrowing

        candidates = synthesize_experiments(H, W)
        frontier_set = pareto_front(candidates,
                                     axes=[info_gain, novelty, sec_relevance],
                                     costs=[cost, risk])
        E = select_from_frontier(frontier_set, rule=DETERMINISTIC_POLICY)
        E = typecheck_against_authorization(E)
        if E is None:
            continue

        result = execute_authorized(E)
        W.update(result)

        if falsifies(H, result):
            H = narrow_or_enlarge(H, result)
        elif supports(H, result) and independent_validate(H, W):
            impact = safely_demonstrate(H)
            finding = produce_proven_finding(H, impact)
            W.concepts.name(finding.concept, via=llm_naming_only)
            learn_strategy_credit(current_strategy, finding)

    W.decay_stale_confidence()
```

Key: anomaly detection → concept discovery BEFORE hypothesis generation. LLM touchpoint = exactly one line, zero correctness effect.

---

## 5. The Most Important Ideas by Novelty (from design.md)

| Idea | Novelty | Importance |
|------|---------|------------|
| Ontology expansion (ρ operator) | Very High | Very High |
| Representation discovery (structural, not textual) | Very High | Very High |
| Cross-target causal transfer (G_A ≅ G_B) | Extremely High | Very High |
| Automated research-strategy discovery | Extremely High | Extremely High |
| Automated discovery of better research algorithms | Potentially enormous | Extremely High |
| MDL anomaly as discovery signal | High | Very High |
| Unified world-model graph | Medium | High |
| Causal reasoning (SCM) | Medium/High | High |
| LLM as bounded naming component | Low | High |

---

## 6. File Organization Reference

```
ARCHITECTURE.md                     This session's 20-section unified architecture
.doge/design/
├── DESIGN-CONSOLIDATED.md         This document (complete design reference)
├── design.md                      File 1: scientific core analysis (794 lines)
├── deep-research-report.md        File 2: multi-agent survey (79 lines)
└── doge-next-report.md            File 3: mathematical spec (325 lines)
cmd/workspace/                     CLI commands (work, monitor, notebook, investigate, ...)
internal/
├── coordinator/                   ResearchCoordinator + GapAnalyzer
├── worldmodel/                    Unified typed graph + gap detector
├── property/                      Security properties + epistemic states + catalog
├── invariant/                     Dynamic invariant induction
├── metamorphic/                   3-way differential probing
├── dimension/                     Latent behavioral basis (5 dimensions)
├── causal/                        Structural Causal Model + interventions
├── synthesis/                     CEGAR separating predicate synthesis
├── ontology/                      Dynamic concept expansion + naming (LLM bounded here ONLY)
├── researcher/                    6 specialized researchers (short-lived)
├── verification/                  Deterministic claim verifier (NO LLM)
├── reasoning/                     LLM integration (bounded, replaceable)
├── learning/                      Layered memory + strategy credit
├── session/                       Replay, checkpoint, budgets
├── benchmark/                     Adversarial synthetic targets
├── attackgraph/                   AND/OR hypergraph + MCTS
├── parser/                        25+ tool parsers
├── entity/                        Knowledge graph materialization
├── correlation/                   Entity relationship detection
├── coverage/                      Evidence-derived coverage
├── opportunity/                   Research opportunity ranking
├── insight/                       Pattern detection
├── finding/                       Validated finding pipeline
├── validation/                    Evidence validation
├── timeline/                      Temporal event tracking
├── search/                        Hybrid keyword+semantic search
├── tui/                           Terminal UI (Bubble Tea)
├── bus/                           In-process event bus
├── cache/                         Query + embedding cache
├── config/                        Configuration management
├── logging/                       Structured logging + redaction
├── db/                            SQLite + migrations
├── runner/                        Command execution + capture
├── journal/                       Command history
├── watcher/                       Filesystem change detection
├── watch/                         Watch orchestrator
├── scheduler/                     Mission scheduling
├── scope/                         Authorization scope policy
├── gates/                         Human approval gates
├── integration/                   End-to-end integration tests
└── e2e/                           Full trajectory tests
pkg/
├── domain/                        Core types (Observation, Entity, Evidence, Hypothesis, ...)
├── ai/                            ModelRouter, providers, types
├── events/                        Event type definitions
└── errors/                        Shared error types
```

---

## 7. Open Problems (Phase 4+)

1. **Cross-target structural isomorphism**: G_A ≅ G_B at abstract relational level even when surface(A) ≠ surface(B). Implementation: compare/merge typed subgraphs from World Model.

2. **Strategy DSL + program synthesis**: Research strategies as bounded DSL programs evaluated on held-out benchmarks. Search over DSL guided by discovery rate per unit cost.

3. **Meta-learning loop**: Combine successful strategy components → new strategy → benchmark → retain if superior. DOGE learns better research algorithms, not just better payloads.

4. **Non-stationary target adaptation**: Targets that change behavior during engagement (adaptive defenses, rolling keys, canary tokens).

---

## 8. Bottom Line

The strongest, most falsifiable direction is:

**Ontology growth under a minimum-description-length objective** as the explicit optimization target, on top of a single unified typed provenance-tracked world-model graph, with any language model reduced to a bounded replaceable authority-free hypothesis/labeling source.

This is testable on Benchmarks C/D/J. If algorithm-only DOGE outperforms fuzzing on those, the core bet is vindicated. If not, the LLM gets promoted one level (hypothesis generation) but never past the validation gate.
