# DOGE Capability Map

## Capability Maturity Matrix

Each capability is rated:
- **0** — Not present
- **1** — Prototype/stub
- **2** — Working in isolation
- **3** — Integrated into research loop
- **4** — Production-quality, benchmarked
- **5** — Self-improving, exceeds XBOW-class

| # | Capability | Current State | XBOW-Level | DOGE Ultimate | Gap | Priority |
|---|---|---|---|---|---|---|
| **RESEARCH LOOP** |
| 1 | Complete research loop (target → proven finding) | **3** — V2 vertical slice proven | 4 | 5 | Loop works but with deterministic routing; needs LLM + dynamic dispatch | P0 |
| 2 | Dynamic researcher selection | **1** — Coordinator hardcodes phase order | 4 | 5 | Need world-model-driven mission generation | P0 |
| 3 | Continuous operation (hours/days) | **0** | 4 | 5 | No session persistence, no pause/resume, no memory compression | P1 |
| 4 | Multi-target concurrent research | **0** | 3 | 4 | Single target per coordinator | P2 |
| **WORLD MODEL** |
| 5 | Entity model (endpoints, users, objects, params) | **3** — Existing worldmodel package is rich | 4 | 5 | Needs integration with V2 coordinator | P0 |
| 6 | Relationship graph (owns, accesses, requires) | **3** — WorldRelationship system exists | 4 | 5 | Needs queryable graph operations | P1 |
| 7 | 8 knowledge categories (found/tried/failed/believed/disproved/untested/unexplained/changed) | **2** — In coordinator ResearchState | 4 | 5 | Need formal Knowledge type with persistence | P0 |
| 8 | Coverage tracking | **2** — TestedSurface exists in investigation.go | 3 | 5 | Need integration with research gap system | P1 |
| 9 | Research gaps (automated detection) | **3** — ResearchGapDetector exists in worldmodel | 4 | 5 | Need to drive mission generation from gaps | P0 |
| 10 | Confidence & uncertainty modeling | **1** — Hypothesis confidence exists | 3 | 5 | Need formal uncertainty over world model elements | P1 |
| 11 | Target change detection | **2** — Insight types exist (InsightNewEndpoint, etc.) | 4 | 5 | Need integration with continuous research | P2 |
| **HYPOTHESIS ENGINE** |
| 12 | Hypothesis generation (regex/pattern) | **3** — Existing hypothesis engine | 3 | 4 | Already solid foundation | P0 |
| 13 | Hypothesis generation (LLM-augmented) | **1** — DeterministicProvider has heuristics | 4 | 5 | Need real LLM integration | P0 |
| 14 | Competing hypotheses | **3** — Competition/clustering exists | 4 | 5 | Need integration with experiment selection | P1 |
| 15 | Discriminating experiments | **2** — Framework exists | 4 | 5 | Need information-gain-based selection | P1 |
| 16 | Security property reasoning | **0** | 3 | 5 | Need formal property definitions | P0 |
| **RESEARCHERS** |
| 17 | Recon researcher | **3** — Working in V2 | 4 | 4 | Needs more tool integration | P1 |
| 18 | Authorization researcher | **3** — Working in V2, finds BOLA | 4 | 5 | Needs generalization beyond BOLA | P0 |
| 19 | Validation researcher | **3** — Independent validation works | 4 | 5 | Solid foundation | P1 |
| 20 | Impact researcher | **3** — Demonstrates impact extent | 4 | 5 | Needs attack-graph integration | P1 |
| 21 | API researcher | **0** | 4 | 5 | NEW — Parameter discovery, input testing | P1 |
| 22 | Business logic/workflow researcher | **0** | 3 | 5 | NEW — State machine analysis | P1 |
| 23 | Injection researcher | **0** | 4 | 5 | NEW — SQL, command, template injection | P1 |
| 24 | SSRF researcher | **0** | 4 | 5 | NEW — URL parameters, SSRF detection | P1 |
| 25 | Browser researcher | **0** | 3 | 5 | NEW — DOM, XSS, client-side | P2 |
| 26 | Exploit development researcher | **0** | 4 | 5 | NEW — PoC construction | P1 |
| 27 | Chain researcher | **0** | 4 | 5 | NEW — Multi-step attack paths | P0 |
| 28 | Anomaly researcher | **0** | 2 | 5 | NEW — Unexplained behavior investigation | P1 |
| **EXPERIMENT ENGINE** |
| 29 | Experiment design | **2** — Researchers design inline | 4 | 5 | Need central experiment engine | P1 |
| 30 | Information gain scoring | **0** | 3 | 5 | Critical for intelligent experiment selection | P0 |
| 31 | HTTP client with evidence capture | **3** — Working in V2 | 4 | 4 | Solid foundation | — |
| 32 | Differential experiment generation | **2** — Auth researcher does differential | 4 | 5 | Need generalization to all researcher types | P1 |
| **ATTACK GRAPH** |
| 33 | Attack graph data structure | **0** | 4 | 5 | NEW | P0 |
| 34 | Chain discovery (BFS/DFS) | **0** | 4 | 5 | NEW | P0 |
| 35 | Unexplored edge tracking | **0** | 3 | 5 | NEW | P1 |
| 36 | Impact propagation | **0** | 3 | 5 | NEW | P1 |
| 37 | Low→high escalation research | **0** | 4 | 5 | NEW | P1 |
| **EVIDENCE & VALIDATION** |
| 38 | Evidence chain (observation → proof) | **3** — EvidenceChain exists in finding.go | 4 | 5 | Need V2 ExperimentEvidence → EvidenceChain bridge | P1 |
| 39 | Independent validation | **3** — Validation researcher works | 4 | 5 | Solid | P1 |
| 40 | Reproduction steps | **3** — ReproductionStep exists | 4 | 4 | Good foundation | — |
| 41 | Impact assessment | **3** — ImpactAssessment exists in finding.go | 4 | 5 | Need structured C/I/A with attack-graph integration | P1 |
| 42 | CWE classification | **0** | 4 | 4 | Need automated classification | P2 |
| **LEARNING** |
| 43 | Layered memory | **3** — Existing learning package | 3 | 5 | Need target-specific isolation | P1 |
| 44 | Technique effectiveness tracking | **2** — Feedback engine exists | 3 | 5 | Need per-researcher, per-target tracking | P1 |
| 45 | Cross-session learning | **0** | 3 | 5 | Need persistent memory across engagements | P2 |
| 46 | Research policy self-improvement | **0** | 2 | 5 | Long-term capability | P3 |
| **SAFETY** |
| 47 | Scope engine | **3** — Existing scope package with InScope check | 4 | 4 | Solid | — |
| 48 | Runtime policy (rate limit, concurrency) | **3** — RuntimePolicy exists | 4 | 4 | Solid | — |
| 49 | Human gates | **2** — Gates package exists | 3 | 4 | Need mission-level gates | P1 |
| 50 | Budget engine (multi-dimensional) | **1** — MaxRequests in brief | 3 | 5 | Need time, token, request, action budgets | P1 |
| 51 | Safety judge | **0** | 4 | 5 | Need deterministic pre-execution safety check | P1 |
| 52 | Emergency stop | **0** | 4 | 4 | Need immediate halt mechanism | P1 |
| 53 | Audit log | **2** — Timeline/journal exist | 4 | 4 | Need V2 integration | P2 |
| **MODEL ABSTRACTION** |
| 54 | Model router | **2** — Working with DeterministicProvider | 4 | 5 | Need real LLM providers | P0 |
| 55 | Multi-provider support | **1** — Interface defined | 4 | 5 | Need Ollama + OpenAI-compatible adapters | P0 |
| 56 | Role-based routing | **2** — ModelRole enum defined | 4 | 5 | Need actual routing logic | P1 |
| **BENCHMARK** |
| 57 | Synthetic benchmark apps | **3** — BOLA app works | 3 | 5 | Need more vulnerability types | P0 |
| 58 | Trajectory analysis | **2** — E2E test has quality metrics | 3 | 5 | Need formal TrajectoryAnalyzer | P1 |
| 59 | Benchmark curriculum (levels 1-14) | **1** — Level 6 only (BOLA) | 3 | 5 | Need progressive difficulty | P1 |
| 60 | Regression suite | **0** | 3 | 5 | Every finding becomes regression | P2 |
| 61 | Randomized benchmark generation | **0** | 3 | 5 | Prevent memorization | P2 |
| **INFRASTRUCTURE** |
| 62 | Persistence (SQLite) | **3** — Existing db package | 4 | 4 | Need V2 schema extensions | P1 |
| 63 | CLI/TUI | **3** — Existing workspace commands | 4 | 5 | Need hunt/pause/resume/status/replay | P2 |
| 64 | Source code analysis | **0** | 2 | 5 | Grey/white-box research modes | P3 |
| 65 | Browser automation | **0** | 3 | 5 | DOM/XSS/client-side research | P3 |

## Capability Summary

| Category | Capabilities | Avg Maturity | Target |
|---|---|---|---|
| Research Loop | 4 | 1.0 | 5.0 |
| World Model | 7 | 2.0 | 5.0 |
| Hypothesis Engine | 5 | 1.8 | 5.0 |
| Researchers | 12 | 1.0 | 5.0 |
| Experiment Engine | 4 | 1.3 | 5.0 |
| Attack Graph | 5 | 0.0 | 5.0 |
| Evidence & Validation | 5 | 2.4 | 4.8 |
| Learning | 4 | 1.3 | 5.0 |
| Safety | 7 | 1.6 | 4.4 |
| Model Abstraction | 3 | 1.7 | 5.0 |
| Benchmark | 5 | 1.2 | 5.0 |
| Infrastructure | 4 | 1.5 | 4.8 |

## What We Have That XBOW Doesn't (Public)

1. **Epistemic ladder** — DOGE has a formal hierarchy: Observation → Correlation → Novelty → Opportunity → Hypothesis → Validation → Candidate → Finding. This is more structured than what XBOW publicly describes.
2. **Research gap detection** — Automated detection of untested surfaces with uncertainty scoring.
3. **Differential engine** — Existing cross-principal differential testing framework.
4. **Workflow/state machine modeling** — State nodes and transitions in the world model.
5. **Verification engine** — AI responses pass through verification before acceptance.
6. **Context builder with trust boundaries** — TRUSTED/OBSERVED/DERIVED content separation in LLM context.
7. **Contradiction detection** — Existing ability to detect conflicting claims.
