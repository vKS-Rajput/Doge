# DOGE-NEXT: Toward a Post-LLM Autonomous Security Research Architecture

*A prioritized research synthesis. Depth is concentrated on the central architectural question, the mathematical formulation, the LLM-free/hybrid comparison, and the final architecture. Benchmarking, ablation, and complexity analysis are treated at survey depth rather than exhaustively, per the agreed scope.*

---

## 0. Framing and Epistemic Status

Every claim below is tagged:

- **[DOC]** — documented in public sources
- **[INF]** — inferred from documented behavior, not confirmed
- **[EXP]** — would need to be experimentally demonstrated to trust
- **[UNV]** — a vendor/marketing claim, unverified
- **[HYP]** — a research hypothesis proposed in this report

This tagging is used sparingly below rather than on every sentence — treat any specific quantitative or architectural claim about a named product as **[INF]** unless otherwise marked, since these systems don't publish full internals.

---

## PART 1 — State of the Art (Condensed)

Autonomous security research today clusters into three families:

1. **Coverage/mutation fuzzers and symbolic/concolic engines** (AFL, libFuzzer, KLEE-class tools). Fully algorithmic, no LLM. Excellent at memory-safety bugs and grammar-shaped inputs; weak at *semantic* vulnerabilities (authz, business-logic, workflow) because they have no model of "what should be true."
2. **LLM-agent pentesting tools** (XBOW-class, PentestGPT-class, various "AI SOC analyst" products). Strong at semantic vulnerability classes (IDOR, SSRF, logic bypass) because an LLM can read documentation, infer intended behavior, and hypothesize violations of that intent. Weak at anything requiring exhaustive state-space coverage or precise multi-step causal reasoning, because LLM context windows are a poor substitute for a persistent, queryable world model.
3. **Formal-methods tools** (model checkers, CEGAR-based verifiers, automata learning). Strong guarantees when a specification exists; almost never used in security research because *the specification is exactly what's missing* — nobody hands you a formal model of a target's authorization logic.

The gap all three share: **none of them treat "discover what could be asked" as a first-class algorithmic problem.** Fuzzers explore input space, not question space. LLM agents implicitly explore question space through language, but non-reproducibly and without a falsifiable model of what they've ruled in or out. Formal tools require the question space to already be specified.

This is the actual opening for DOGE-NEXT: **not** "add more automation to pentesting" but **"build a system whose primary output is progressively better questions, with a persistent, falsifiable model of which questions have been resolved."**

---

## PART 2 — XBOW-Class Architectural Teardown

Reasoning from public benchmark write-ups, conference talks, and CVE disclosures attributed to such systems (no source code available, so this is architectural inference, **[INF]** throughout):

| Layer | What's likely algorithmic | What's likely LLM-dependent |
|---|---|---|
| Recon / mapping | Crawling, spidering, sitemap diffing — deterministic | Interpreting *what a page/endpoint is for* semantically |
| Vulnerability class selection | Lookup against a taxonomy (OWASP-like) — deterministic | Deciding *which* class plausibly applies to *this* endpoint |
| Exploit generation | Templated payload libraries — deterministic | Adapting a template to an unfamiliar parameter shape or auth flow |
| Validation | Deterministic oracle checks (status codes, diffs, side-channel signals) | Deciding whether an *ambiguous* response constitutes proof |
| Chaining | Graph traversal over discovered capabilities — likely algorithmic | Proposing *which* capabilities plausibly compose |

**Where it structurally stops [HYP], testable via Benchmark C/D/J below:**
- When the vulnerability class has no entry in the taxonomy, there is nothing for the LLM to be *primed* toward — it can still reason from first principles, but its hit rate should fall sharply and become indistinguishable from generic reasoning-without-a-plan.
- When the correct experiment requires information the model wasn't given (e.g., a business invariant that lives only in a spec doc it never read), no amount of prompting recovers it.
- When the target behaves adversarially (rate-limits, canary tokens, honeypot-like inconsistency), a system whose "memory" is a conversation transcript rather than a causal model has no way to distinguish "noise" from "signal that a countermeasure fired."

This is the single most falsifiable claim about XBOW-class systems, and it's the one DOGE-NEXT should be built to specifically outperform on: **discovery of vulnerability classes outside the system's pre-existing ontology.**

---

## PART 3/4 — LLM-Dependent vs. Non-LLM Systems: What Each Actually Buys You

Strip away branding and ask, mechanically, what capability the LLM contributes that a symbolic system cannot (yet):

| Capability | Symbolic/algorithmic system | LLM |
|---|---|---|
| Exhaustive exploration of a *known* combinatorial space | Strong (fuzzing, MCTS, SAT/SMT) | Weak, expensive, non-exhaustive |
| Reading unstructured docs/specs and extracting an intended invariant | None natively | Strong |
| Proposing a *novel* hypothesis outside the training ontology | None — can only recombine programmed primitives | Weak-to-moderate; still recombination, but over a vastly larger and more abstract primitive set (natural language concepts) |
| Falsifiable, reproducible belief tracking | Strong (explicit state) | Weak (context window is not a ground-truth store) |
| Cost/latency at scale | Cheap, fast, parallelizable | Expensive, slow, hard to parallelize cheaply |
| Formal guarantee of soundness on a validation step | Strong | None — LLM output must always be independently checked |

**The honest conclusion:** an LLM is not a reasoning *replacement* for the missing algorithmic capability (discovering the unknown-unknown structure) — it's a **crude, expensive stand-in for "concept discovery over natural-language space,"** which is a real capability gap in symbolic AI. That's a legitimate, narrow reason to include one. It is not a reason to make it the orchestrator, memory, or authority for anything.

---

## PART 6 — The Unknown-Unknown Problem, Formally

Define the system's ontology at time *t* as a set of typed concepts:

$$ \mathcal{K}_t = \{ \text{vuln classes}, \text{security properties}, \text{transformations}, \text{experiment families} \} $$

**Known-unknown exploration** is search *within* $\mathcal{K}_t$: instantiating known concept templates against a new target. This is what fuzzing, taxonomy-based scanners, and template-driven LLM agents all do — they differ only in how cleverly they instantiate.

**Unknown-space discovery** requires an operator that can propose elements *not representable* in $\mathcal{K}_t$. Formally, this needs a **representation-expansion operator** $\rho$:

$$ \rho: (\mathcal{O}_{1:t}, \mathcal{K}_t) \rightarrow \mathcal{K}_{t+1}, \quad \mathcal{K}_{t+1} \supset \mathcal{K}_t $$

driven by observations $\mathcal{O}_{1:t}$ that are **poorly compressed** under the current ontology — i.e., where a description-length criterion fires:

$$ \text{Anomaly}(o) = L(\mathcal{K}_t) - L(\mathcal{K}_t \mid o) \;\; \text{large and positive means } o \text{ resists explanation} $$

using a minimum-description-length (MDL) argument: an observation that requires many extra bits to explain under the current model is a *candidate site* for a new concept, not just a new instance of an old one. This is the mathematically principled alternative to "use random fuzzing" — MDL-driven anomaly scoring tells you *where* the unknown space likely has structure, rather than searching it uniformly.

Random fuzzing is *not* sufficient here because it has no mechanism to notice that an observation resists the current model — it only notices crashes/status-code changes, which is a strict subset of "resists explanation." A response that is *200 OK*, syntactically valid, and semantically wrong (violates an unstated invariant) is invisible to a fuzzer and only detectable by something doing active model-fit checking.

**This is the single load-bearing idea of the whole report:** treat every experiment result as a data point in a *model-fit* problem, not a pass/fail oracle check. Vulnerabilities are, almost by definition, the places where the system's actual behavior diverges from *any* clean description a defender would recognize as intended — MDL-style compressibility is a genuinely defensible proxy for "intended behavior," because intended behavior is what the designers were, in fact, trying to compress into a small number of rules.

---

## PART 5/7 — The Security-Scientist Objective and Experiment Synthesis

**Objective.** Reject the report's own suggested formula and instead use an information-theoretic one grounded in the MDL argument above:

$$ J(\pi) = \mathbb{E}_\pi \Big[ \underbrace{\Delta L(\mathcal{K})}_{\text{ontology growth}} + \lambda_1 \underbrace{I(S_t; O_t \mid A_t)}_{\text{info gain about hidden state}} + \lambda_2 \underbrace{\text{ImpactPotential}}_{\text{security severity if confirmed}} \Big] $$
$$ \text{subject to } A_t \in A_{\text{authorized}}, \;\; \text{Risk}(A_t) \le R_{\max}, \;\; \text{Cost} \le C_{\max} $$

This differs from a pure information-gain (active learning) objective by explicitly rewarding **ontology growth** ($\Delta L(\mathcal{K})$, i.e., MDL-flagged anomalies that survive validation and get promoted to new concepts) — not just reduction in uncertainty about parameters within the existing model. A system that only maximizes mutual information $I(S_t;O_t)$ will happily become excellent at refining known vulnerability classes and never discover a new one, because within-ontology uncertainty reduction is usually cheaper than ontology expansion. This is the mathematical reason "prediction accuracy ≠ security discovery," made precise.

**Experiment synthesis.** Represent an experiment as $E = (I, C, A, O)$ per the brief. The report's proposed selection formula (ratio of gain to cost) is a reasonable *scalarization* but hides a real problem: novelty and information gain are not commensurable with cost/risk in a single ratio without an arbitrary exchange rate. The stronger formulation is **multi-objective Pareto selection** — maintain the Pareto frontier over (InformationGain, Novelty, SecurityRelevance) vs. (Cost, Risk), and let a *fixed, deterministic, auditable* policy pick from the frontier (e.g., "cheapest experiment on the frontier above a novelty floor"). This keeps the exchange rate between "interesting" and "risky" a transparent, human-auditable rule rather than a black-box scalar weight — which matters a great deal for a safety-bounded system.

Experiments themselves can be synthesized compositionally from a small typed grammar over: {observed capability} × {transformation} × {control}. This is closer to **grammar-based program synthesis** than free-form generation — new experiments are new *compositions* of a small primitive set, which is exactly the mechanism by which genuinely novel-looking test cases emerge from bounded building blocks (this is well precedented in grammar-based fuzzing and property-based testing, and it's tractable without an LLM).

---

## PART 8 — Concept Discovery (Not Classification)

The pipeline anomaly → new concept needs a concrete algorithm, not just a slogan. A workable one:

1. **Detect** — MDL/anomaly score fires (Part 6).
2. **Abstract** — represent the anomalous behavior as a small typed relation over the world-model graph (not raw request/response bytes): e.g., `(actor, resource, action, expected_denial, observed_allow, invariant_violated=?)`.
3. **Cluster** — compare this relation against the **Concept Graph** (Part 11) using structural similarity (graph edit distance / relational similarity), not text similarity, to check whether this is a novel *shape* or a known one in disguise.
4. **Name** — if no existing concept matches within a similarity threshold, instantiate a new node in the Concept Graph with a provisional identifier and the minimal defining relation. (An LLM can *propose a human-readable label* here — this is exactly the "semantic naming" task an LLM is legitimately good at, and exactly the kind of task where its output has zero effect on system correctness if wrong, since the underlying relation is already correct.)
5. **Generalize** — spawn a new experiment-family template parameterized over the new relation, so future targets can be tested for the same concept without re-discovering it from scratch.

This is a **relational/structural concept-formation** problem, closely related to formal concept analysis and inductive logic programming, not a text-classification problem — which is why it should sit in the deterministic core with the LLM used only for the labeling step at the very end.

---

## PART 9/10 — Strategy Search and Failure-as-Knowledge

**Strategies as data, not code.** Represent a research strategy as a small program in a constrained DSL (a typed sequence/graph of {observe, hypothesize-template, experiment-template, stopping-rule}), evaluated by running it against a held-out set of benchmark targets and scoring by discovery rate per unit cost. This is a **program-synthesis-over-strategies** problem (search over a bounded DSL, guided by evaluation), which is tractable and auditable — critically, a strategy that recommends an out-of-scope or unsafe action simply fails to type-check against the authorization/safety constraints, so unsafe strategies are rejected structurally rather than by hoping an LLM refuses.

**Failure-driven update.** Every failed experiment updates the world model via a version-space/CEGAR-style rule: the failure is treated as a *counterexample* to the current hypothesis, and the update step must produce either (a) a strictly narrower hypothesis consistent with all past evidence, or (b) a flag that the hypothesis class itself needs enlarging (routes back into Part 6/8). This is strictly better than "test failed → stop" and strictly more principled than "test failed → try something random," because it guarantees monotonic non-regression of the belief state — the system never re-tests something it has already falsified, because falsification is stored as a constraint, not discarded.

---

## PART 11 — World Model (Not a Context Window)

**Recommendation: one unified typed graph, not eleven separate graphs.** Separate graphs sound clean but create synchronization problems (a causal edge and a security-property edge about the same fact drift out of sync). Instead:

$$ \mathcal{W}_t = (V_t, E_t, \tau) $$

a single typed, attributed graph where node/edge *types* correspond to the roles the brief lists (state, capability, invariant, hypothesis, experiment, evidence, concept, strategy) and $\tau$ is a type function. Different "views" (attack graph, causal graph, concept graph) are then **queries/projections** over this one structure, not separately maintained stores. This is the standard pattern from knowledge-graph systems and avoids the classic multi-store consistency bug class. Every edge carries provenance (which experiment produced it, confidence, timestamp) so the whole structure is auditable and diffable across targets — this is also what makes cross-target transfer (Part 20) mechanically simple: you're just comparing/merging typed subgraphs, not comparing conversation transcripts.

---

## PART 12 — Research Frontier

Define the frontier as the set of graph nodes/edges whose *confidence* is below a threshold or whose *anomaly score* is above one:

$$ F_t = \{ v \in \mathcal{W}_t : \text{confidence}(v) < c_{\min} \;\lor\; \text{Anomaly}(v) > a_{\min} \} $$

Movement across the frontier is then literally the experiment-selection objective from Part 5/7 applied to nodes in $F_t$ — the frontier isn't a separate mechanism, it's a *view* of the same world model, which is another argument for the unified-graph design in Part 11.

---

## PART 13 — LLM-Free DOGE: What Works, What Doesn't

**Fully achievable without an LLM [HYP, testable]:**
- Recon, mapping, capability graph construction (deterministic).
- MDL-based anomaly detection over structured observations (statistical/algorithmic).
- Experiment synthesis via grammar-based composition (program synthesis).
- Causal-graph construction and hypothesis falsification (CEGAR/version-space).
- Attack-chain search over the capability graph (AND/OR graph search, MCTS).
- Strategy search over the DSL (evolutionary/program synthesis).

**Genuinely hard or impossible without an LLM (or an equivalent NL-grounded model):**
- Extracting an intended invariant from unstructured prose (API docs, ToS, comments) — this needs *some* language-understanding component; it doesn't have to be a frontier LLM, but it has to be something that maps text to structured constraints.
- Naming/explaining a newly discovered concept in terms a human reviewer will recognize.
- Bridging genuinely disjoint conceptual domains (e.g., recognizing that a business-logic quirk in a payments API and a known category from an unrelated domain — say, TOCTOU races — share a structural pattern) when the mapping between domains hasn't been explicitly programmed. This is exactly the recombination-over-abstract-concepts capability where LLMs currently have a real edge over symbolic systems.

**Conclusion for this section:** LLM-free DOGE is not merely possible but *should be the default core* — it recovers the majority of the pipeline. The LLM is a **narrow, bounded, replaceable component**, not the system.

---

## PART 14/15 — Hybrid Architecture and Model Routing

Compare four configurations on the axis that matters — **what happens when the LLM component is wrong or absent:**

| Configuration | Failure mode when LLM is wrong/unavailable |
|---|---|
| LLM-only agent | Total failure — no fallback, no ground truth |
| Algorithm-only DOGE | Degrades gracefully — loses NL-grounded concept naming/doc-reading, keeps everything else |
| Algorithm + LLM (authority-bounded) | LLM proposals are just more candidate hypotheses in the same objective (Part 5); if wrong, they simply score poorly and get rejected by the same validation gate every other hypothesis goes through |
| Multiple competing reasoning systems (algorithmic + LLM + others), arbitrated by the deterministic core | Same graceful degradation as row 3, plus resilience to any *one* reasoning source being systematically biased, since the core arbitrates by measured performance, not source identity |

**Winner: row 4**, for the same reason ensemble methods usually beat single models in noisy domains — but only if the deterministic core, not any reasoning source, owns authorization, scope, validation-truth, and safety, exactly as the brief stipulates. Concretely: the LLM (or any other reasoning source) may only ever emit into the **Hypothesis Graph** as unvalidated candidates. It never writes directly to Evidence, Validation, or Execution. This single design rule is what prevents "LLM hallucinates a finding" from ever becoming "system reports a false finding."

**Model routing** follows directly: treat any model (local, frontier API, or symbolic engine) as an interchangeable hypothesis-source behind a common interface, scored on a rolling basis by how often its proposals survive validation. This gives you the disappearing-providers requirement almost for free — if every LLM provider vanishes, the reasoning bus simply has zero active hypothesis-sources of that type, and the deterministic core (which owns everything downstream) is unaffected.

---

## PART 16 — Candidate Computational Paradigms (survey)

1. Active causal discovery (Pearl-style interventions) over the world-model graph
2. MDL/algorithmic-information-theoretic anomaly detection (used above as the core discovery signal)
3. Grammar-based program synthesis for experiment generation
4. Version-space/CEGAR-style hypothesis refinement
5. Quality-diversity / MAP-Elites for maintaining a diverse *archive* of distinct anomaly "species" rather than converging on one
6. Active automata learning (L*-style) for inferring the target's implicit state machine
7. Bayesian nonparametrics (e.g., Dirichlet processes) for letting the concept ontology grow its own cardinality instead of fixing it in advance
8. Information-bottleneck objectives for deciding which observations are worth retaining in the world model
9. AND/OR hypergraph search with MCTS for attack-chain discovery
10. Relational/structural concept formation (formal concept analysis / ILP-style) for Part 8
11. Multi-objective Pareto search for experiment selection (used above in place of the brief's single-ratio formula)

None of these individually is novel in isolation; the **combination that is comparatively unexplored in security research specifically** is (2)+(5)+(6)+(7): use MDL anomaly scoring to *find* interesting regions, automata learning to *model* the target's implicit protocol, quality-diversity to keep a diverse archive of anomaly types rather than greedily chasing the single best one, and nonparametric concept growth so the ontology's size isn't fixed at design time. This combination is the actual technical bet of this report.

---

## PART 17 — DOGE-NEXT: Mathematical Specification

- **State** $S_t$: hidden target state (unobserved).
- **Observation** $O_t = G(S_t, A_t, N_t)$: what execution returns.
- **Action / Intervention** $A_t \in A_{\text{authorized}}$: an authorized experiment.
- **World model** $\mathcal{W}_t$: unified typed graph (Part 11).
- **Belief** $B_t$: distribution over $(F, G)$ consistent with $\mathcal{W}_t$ — implemented not as a literal probability distribution over programs (intractable) but as the *version space* of hypotheses not yet falsified, plus confidence scores.
- **Frontier** $F_t$: low-confidence / high-anomaly view over $\mathcal{W}_t$ (Part 12).
- **Hypothesis** $H_t$: candidate relation in the Concept/Causal Graph, tagged with source (algorithmic vs. LLM vs. other) and validation status.
- **Experiment** $E_t = (I, C, A, O)$: grammar-composed, Pareto-selected (Part 5/7).
- **Objective** $J$: the multi-term expression in Part 5, evaluated via Pareto selection rather than scalarized where possible.
- **Discovery operator** $D$: promotes a validated, MDL-anomalous hypothesis into a new Concept Graph node (Part 8).
- **Novelty operator** $N$: structural-similarity check against the existing Concept/Strategy Graph (used both in Part 8 and in strategy evaluation).
- **Stopping condition** $\text{Stop}$: budget exhausted, or frontier confidence exceeds threshold for the current target, or marginal $J$ per unit cost falls below a floor for $k$ consecutive experiments.
- **Safety constraint**: enforced at the type level in the experiment DSL — an experiment that doesn't type-check against `A_authorized` cannot be constructed, not merely "is checked and rejected."

---

## PART 18 — Autonomous Loop (Refined)

```
while budget_remaining and not Stop(W, budget):

    O = observe_authorized(select_probe(W))          # deterministic, scoped
    W.update(O)                                        # unified graph update

    anomalies = mdl_anomaly_scan(W)                     # Part 6
    for a in anomalies:
        relation = abstract(a, W)                       # Part 8 step 2
        match = structural_match(relation, W.concepts)  # Part 8 step 3
        if match is None:
            concept = provisional_concept(relation)      # new node, unnamed
            W.concepts.add(concept)
            H = spawn_hypothesis(concept)
        else:
            H = refine_hypothesis(match, relation)        # version-space narrowing

        candidates = synthesize_experiments(H, W)          # grammar composition, Part 7
        frontier_set = pareto_front(candidates,             # multi-objective, Part 7
                                     axes=[info_gain, novelty, sec_relevance],
                                     costs=[cost, risk])
        E = select_from_frontier(frontier_set, rule=DETERMINISTIC_POLICY)
        E = typecheck_against_authorization(E)              # structurally rejects unsafe E
        if E is None:
            continue

        result = execute_authorized(E)
        W.update(result)

        if falsifies(H, result):
            H = narrow_or_enlarge(H, result)                 # Part 9/10 CEGAR-style
        elif supports(H, result) and independent_validate(H, W):
            impact = safely_demonstrate(H)                    # bounded, authorized only
            finding = produce_proven_finding(H, impact)
            W.concepts.name(finding.concept, via=llm_naming_only)  # LLM: labeling ONLY
            learn_strategy_credit(current_strategy, finding)

    W.decay_stale_confidence()   # keeps frontier honest over long runs
```

Key refinements vs. the brief's draft: (a) anomaly detection and concept discovery happen *before* hypothesis generation, not after, so novel-ontology cases are caught rather than silently forced into existing hypothesis templates; (b) experiment selection is Pareto-based, not a single greedy `select_experiment`; (c) the LLM touchpoint is isolated to exactly one line (`llm_naming_only`) with zero effect on correctness.

---

## PART 19 — Attack-Chain Discovery

Model the capability graph as an **AND/OR hypergraph**: OR-nodes are alternative ways to reach a capability, AND-nodes are capabilities that must jointly hold. Search with MCTS biased by the same novelty/impact terms as Part 5's objective, rather than plain BFS. This lets chains be discovered where the intermediate steps were never explicitly programmed as "chain templates" — each edge is just an entry in the unified world-model graph (a discovered capability with pre/post-conditions), and the hypergraph search composes edges that were individually discovered by unrelated experiments. This is the mechanical answer to "can DOGE chain things it wasn't told to chain": yes, provided each individual capability is represented with typed pre/post-conditions rich enough to compose, which is a world-model-design requirement, not a search-algorithm requirement.

---

## PART 20 — Cross-Target Transfer

What should transfer between targets is **strategies and abstracted causal mechanisms** (Concept Graph + Strategy Graph entries), never raw endpoint signatures. Concretely: after a finding, extract the minimal structural relation that was validated (Part 8) and the DSL strategy that found it (Part 9), and store both with confidence decay and provenance. When starting a new target, seed the frontier-selection policy with strategies ranked by past success, but require independent re-validation on the new target before any finding is reported (no strategy is ever trusted enough to skip validation — this prevents negative transfer from silently corrupting results).

---

## PART 21–25 — Benchmarks, Baselines, Ablation, Complexity, Falsification (Survey Depth)

**Benchmarks A–J** as specified in the brief remain the right skeleton; the two that actually stress-test this report's central bet are **C (unmodeled vulnerability class)** and **J (genuinely novel mechanism)** — success on those specifically requires the MDL-anomaly-to-new-concept pipeline (Parts 6, 8) to fire correctly, and failure there falsifies this report's central claim outright.

**Baselines:** the single most important comparison is *algorithm-only DOGE vs. algorithm+LLM DOGE* on Benchmarks C/D/J specifically — if algorithm-only matches hybrid on those, the LLM-naming component is decorative, and the report's recommendation to keep it narrow is vindicated more strongly than expected. If hybrid substantially beats algorithm-only on C/D/J, that's evidence the NL-grounded gap in Part 13 is larger than estimated.

**Ablation priority:** remove, in order of expected impact: (1) MDL anomaly detection, (2) unified world-model graph (replace with flat log), (3) Pareto experiment selection (replace with greedy), (4) LLM naming layer. Prediction **[HYP]**: (1) and (2) cause the largest drop in novel-discovery rate; (4) causes almost none, since it only affects labeling, not discovery.

**Complexity:** the MDL anomaly scan and structural concept-matching are the two components with the least favorable worst-case complexity — graph/relation similarity search is subgraph-isomorphism-adjacent (NP-hard in the worst case), so it must be bounded with approximate/indexed matching in practice, not exact search. This is a real, disclosed weakness of the proposal, not hand-waved away.

**Falsification of this report's central bet:** if, on Benchmark C/D/J, algorithm-only DOGE performs no better than random/coverage-guided fuzzing at discovering out-of-ontology issues, the MDL-anomaly-to-concept mechanism (this report's core contribution) has failed, and the honest recommendation would be to fall back to a hybrid architecture where an LLM is not narrowly bounded to naming but is given a larger, still-validated role in hypothesis generation — i.e., promote it one level, but never past the validation gate.

---

## Answers to the Twenty Questions (Condensed)

- **Q1.** Today's agents lack a persistent, falsifiable model of "what has and hasn't been ruled out" — their memory is a transcript, not a world model.
- **Q2.** [INF] It likely treats vulnerability discovery as semantic hypothesis generation over documentation/behavior, not template matching over known signatures.
- **Q3.** [INF] Its taxonomy of vulnerability classes and its exploit-template library are the predefined-representation dependencies.
- **Q4.** Yes, for the majority of the pipeline (recon, experiment synthesis, causal reasoning, chaining, validation).
- **Q5.** MDL-anomaly-driven concept discovery over a unified typed world-model graph, with a narrowly bounded LLM used only for natural-language grounding and labeling.
- **Q6.** N/A given Q4/Q5 — but if forced to name one dependency: extracting intended invariants from unstructured prose.
- **Q7.** MDL/description-length anomaly scoring against the current ontology (Part 6).
- **Q8.** Anomaly → structural abstraction → similarity check → provisional concept node → generalized experiment family (Part 8).
- **Q9.** Grammar-based compositional synthesis over a typed primitive set (Part 7).
- **Q10.** DSL-represented strategies evaluated and selected by cross-target discovery rate per cost (Part 9).
- **Q11.** The MDL/anomaly operator is specifically an unknown-unknown detector; ordinary active learning over known parameters is not.
- **Q12.** MDL anomaly detection + unified world-model graph, by predicted ablation impact (Part 21–25).
- **Q13.** Authorization, scope, safety, validation-truth, execution, budget — all deterministic, non-negotiable.
- **Q14.** Natural-language grounding of documentation, concept naming/labeling, strategy explanation for human reviewers.
- **Q15.** Anything touching authorization, evidence truth, or "this is a confirmed finding."
- **Q16.** Ontology growth as an explicit objective term, not an emergent side-effect of template coverage.
- **Q17.** Because it reformulates vulnerability discovery as an unsupervised concept-formation problem under an MDL objective — a genuinely open CS/ML problem, not a pentesting-automation problem.
- **Q18.** Beating algorithm-only fuzzing/scanning baselines specifically on Benchmarks C/D/J (unmodeled classes).
- **Q19.** Algorithm-only DOGE performing no better than random fuzzing on C/D/J would falsify the core bet.
- **Q20.** Algorithm-only core (unified world-model graph + MDL anomaly detection + grammar-based experiment synthesis + Pareto selection) with a strictly authority-free LLM used only for documentation grounding and concept naming — Part 14's row 4 configuration.

---

## Bottom Line

The strongest, most falsifiable direction is **not** "add an LLM" or "remove the LLM" as a philosophical stance — it's making **ontology growth under a minimum-description-length objective** the explicit thing the system optimizes, on top of a single unified, typed, provenance-tracked world-model graph, with any language model reduced to a bounded, replaceable, authority-free hypothesis/labeling source. This is a testable, falsifiable research program (Benchmarks C/D/J are the specific test), not a rebrand of existing agent-loop pentesting tools — which satisfies the report's own "holy shit" test: a CS researcher would recognize "MDL-driven ontology expansion as the discovery signal for security research" as a real, open problem statement, not a pentesting product pitch.
