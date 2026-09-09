# DOGE ULTIMATE — BREAKTHROUGH RESEARCH MISSION 3
## Representation Discovery: The Algorithmic Layer Beyond Invariant Induction

**Author**: Engineering & Research Supervisor for DOGE  
**Date**: September 2026  
**Status**: Foundational Research Specification & Architectural Blueprint  
**Target Milestone**: DOGE Ultimate Phase 3  

---

## Executive Summary

DOGE Phase 1 proved that autonomous research can operate via **Security Property Reasoning** and **State Machine Mapping** rather than static vulnerability checklists. DOGE Phase 2 proved that an autonomous system can discover a vulnerability absent from its vulnerability catalog (**Batch Pipeline Context Bleed**) via **Dynamic Invariant Induction**, **Metamorphic Relation Probing**, and **Dual-Policy Exploration/Exploitation**.

However, Phase 2 leaves one critical hidden dependency intact:
> **DOGE still relied on a human engineer's representation of what to project and compare.**

The system compared operation ordering and identity context because the invariant miner was given projection functions over ordering and headers. Had the vulnerability resided in millisecond-scale lock races, cache key normalization differences, asynchronous queue deadletter re-queuing, or floating-point truncation in pagination, Phase 2 would have failed because **the relevant behavioral dimension was not present in the observational projection**.

This research specification formulates **Phase 3: Representation Discovery & Causal Intervention**. We design an algorithmic system that discovers the **latent dimensions of behavior** along which a software system varies, synthesizes novel interventions, and expands its own ontological representation without pre-configured security templates.

---

# PART I: COMPETITIVE RESEARCH & STATE OF THE ART

To ensure DOGE does not replicate existing patterns or mistake known techniques for novel breakthroughs, we systematically analyze the state of autonomous cyber reasoning and scientific discovery systems.

| System | What it Represents | What it Searches | What it Assumes | How it Generates Hypotheses | How it Chooses Experiments | Concept Discovery? | Ontology Expansion? | Transformation Invention? | Unknown Unknowns? | Fundamental Bottleneck |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **XBOW** (Public Architecture & Docs) | State graphs, application flows, API schemas, target-specific reproduction scripts | Exploit trajectories, parameter payloads, authorization boundaries | Web/API semantics, HTTP primitives, standard security invariants | LLM-guided abduction from observations | Coordinator-driven mission dispatch to specialized worker agents | No (bound to known vulnerability taxonomies) | No (pre-defined finding structures) | Limited (heuristic mutation & parameter tampering) | Low (bounded by LLM training distribution) | Dependent on LLM parametric memory for vulnerability classes; cannot invent new execution dimensions. |
| **OpenAI Aardvark** (Agentic Security Research) | Tool call traces, system prompts, application interaction logs | Tool invocation sequences, exploit payload variants | Target conforms to tool capabilities; vulnerabilities match LLM reasoning priors | In-context LLM reasoning over HTTP request/response transcripts | LLM next-action sampling (ReAct / Chain-of-Thought) | No | No | No (generates string payloads via prompts) | Low (fails on non-intuitive, emergent flaws) | Suffers from hallucination, context window exhaustion, and inability to systematically sample sparse interventional spaces. |
| **DARPA AIxCC Systems** (e.g., Team Atlanta, Shellphish) | Program AST, CFG, DFG, memory models, coverage bitmaps, sanitizers | Crash-inducing inputs, patch spaces, reachability constraints | Source code access (C/Java), crash or memory sanitizer as oracle (ASan/UBSan) | Symbolic query generation, directed fuzzing distance heuristics | Coverage-guided evolutionary fuzzing (AFL/LibFuzzer) + LLM symbolic seeding | No | No | Synthesizes input mutations via mutator engines | Medium (discovers memory safety bugs, but not logical/semantic flaws) | Source-code reliant; bound to boolean sanitizer signals. Cannot discover multi-tenant isolation or logical business-flaws without sanitizers. |
| **Trail of Bits / Theori Automated Research** | Intermediate Representation (LLVM/eBPF/Wasm), formal verification models | Symbolic path constraints, binary state transitions | Formal specification of invariants or binary memory invariants | SMT solver constraint falsification | Z3/CVC5 constraint satisfaction queries | Limited (infers path constraints) | No | Symbolic input generation | Low (only finds violations of explicitly modeled constraints) | Requires complete formal specifications; intractable state explosion on real-world multi-tier web applications. |
| **Protocol Inference Systems** (LearnLib, AAut) | Deterministic Finite Automata (DFA), Mealy Machines, Extended FSMs | Output alphabet discrepancies given input sequences | Target is a synchronous, discrete-state automaton with fixed alphabet $\Sigma$ | State equivalence queries (Angluin $L^*$, W-method, Rivest-Schapire) | Distinguishing sequences ($W$-set) that separate states | Partial (discovers unseen states in DFA) | No (alphabet $\Sigma$ is fixed) | No (input tokens are fixed in advance) | Medium (finds state skips in modeled protocols) | Exponential complexity in state variables; cannot discover variables outside the alphabet $\Sigma$. |
| **AI Scientists & Automated Discovery** (The AI Scientist, Robot Scientist Adam/Eve) | Hypothesis graphs, experimental designs, biological/mathematical models | Experimental condition space, scientific literature, code templates | Environment obeys mathematical or biochemical regularities with measurable assays | Abductive literature synthesis + symbolic regression | Bayesian experimental design, active learning acquisition functions | Yes (infers equations & gene functions) | Limited (expands scientific graphs) | Yes (synthesizes lab protocols) | High (within physical assay bounds) | Relies on external wet-lab assays or Python execution; lacks the adversarial, security-violating objective function. |
| **Open-Ended Learning** (POET, Quality-Diversity, MAP-Elites) | Behavioral descriptors (niches), environment genomes, agent policies | Behavioral space coverage, Pareto-optimal quality within niches | Continuous or structured behavioral embedding space exists | Mutation of agent policies and environment challenges | Intrinsic motivation, novelty metric distance to nearest neighbors | Yes (discovers emergent behavioral gaits) | Partial (can expand niche boundaries) | Yes (evolves environment parameters) | High (demonstrates emergent novelty) | Has never been formalized for security research; requires defining meaningful behavioral distance without an oracle. |

---

# PART II: THE MISSING LAYER & MATHEMATICAL FORMULATIONS

## Section A: The Missing Layer

In DOGE Phase 2, the transition from observation to candidate vulnerability was:
$$\text{Raw Traces } \mathcal{T} \xrightarrow{\Pi_{\text{fixed}}} \text{Projected Features } \mathcal{X} \xrightarrow{\text{Miner}} \text{Invariants } \mathcal{I} \xrightarrow{\text{Prober}} \text{Violations } \mathcal{V}$$

The critical flaw is the operator $\Pi_{\text{fixed}}$. In Phase 2:
$$\Pi_{\text{fixed}}(t) = (\text{Method}(t), \text{Endpoint}(t), \text{Order}(t), \text{Identity}(t))$$

If an enterprise system contains a vulnerability where:
1. **Timing Jitter**: An asynchronous encryption job takes $150\text{ms}$ to rotate a token, during which a stale token window exists.
2. **Serialization Mismatch**: A JSON parser allows duplicate keys `{"id": 1, "id": 2}` handled differently by gateway vs backend.
3. **Cache-Key Normalization Collision**: `/api/v1/user/100` and `/api/v1/user/100%20` are cached identically by the reverse proxy but routed to different tenants by the application server.
4. **Idempotency Context Reuse**: An `Idempotency-Key` header re-plays financial settlement across different account sessions.

DOGE Phase 2 **cannot observe these vulnerabilities**. They do not exist in $\Pi_{\text{fixed}}$. To discover them, DOGE must invent the projection function itself:
$$\Pi^* = \arg\max_{\Pi \in \mathcal{H}_\Pi} \mathcal{S}(\Pi, \text{Target})$$
where $\mathcal{S}$ measures the **causal variance and security relevance** revealed under intervention along the induced dimension.

---

## Section B: Three Candidate Mathematical Formulations

### Candidate Formulation 1: Structural Causal Model with Active Interventional Basis Discovery (SCM-IBD)

#### 1. Formal Definition
We formulate the target software system as a Partially Observable Structural Causal Model (PO-SCM):
$$\mathcal{M} = \langle \mathcal{U}, \mathcal{V}, \mathcal{F}, P(\mathcal{U}) \rangle$$
where $\mathcal{V} = \{V_1, \dots, V_n\}$ are observed variables (headers, statuses, latency, body fields), $\mathcal{U} = \{U_1, \dots, U_m\}$ are unobserved latent variables (thread IDs, memory states, cache entries, mutex locks), and $\mathcal{F} = \{f_1, \dots, f_n\}$ are structural equations:
$$V_i = f_i(\text{PA}_i, U_{\text{pa}_i})$$

An experiment is a Pearlian hard intervention:
$$\text{do}(X = x), \quad X \subseteq \mathcal{V}$$
which replaces structural equations $f_x$ with constant values $x$, severing incoming causal edges to $X$.

#### 2. Objective Function
$$\mathcal{J}_{\text{SCM}}(\text{do}(X=x)) = \underbrace{D_{\text{KL}}\left(P(Y \mid \text{do}(X=x)) \parallel P(Y \mid \text{do}(X=x'))\right)}_{\text{Causal Discrepancy (Surprise)}} \times \underbrace{\text{SecRel}(Y)}_{\text{Security Sensitivity}} - \lambda \cdot \text{Cost}(X)$$

#### 3. State & Action Representation
- **State**: Causal graph estimate $\hat{\mathcal{G}} = (\mathcal{V} \cup \hat{\mathcal{U}}, \mathcal{E})$, with edge confidences $w_{ij} \in [0, 1]$.
- **Action**: Atomic intervention $\text{do}(X=x)$ or interventional pair $(\text{do}(X=x), \text{do}(X=x'))$ varying a parameter along candidate dimension $d$.

#### 4. Optimization & Complexity
- Optimization via Active Invariant Causal Prediction (ICP) and Greedy Interventional Equivalence Search (GIES).
- Complexity: $\mathcal{O}(|\mathcal{V}|^k)$ where $k$ is the intervention arity. For sparse HTTP interaction graphs, bounded by $\mathcal{O}(|\mathcal{V}|^2 \cdot \log |\mathcal{V}|)$.

#### 5. Trade-offs
- **Advantages**: Sound mathematical foundation; distinguishes true security cause-and-effect from incidental correlations (eliminating false positives).
- **Weaknesses**: Continuous latency or asynchronous race conditions are difficult to discretize into static DAG nodes without temporal extensions.

---

### Candidate Formulation 2: Active Automata Learning with Relational Predicate Synthesis (AAL-RPS)

#### 1. Formal Definition
We model the target as an Extended Finite State Machine (EFSM):
$$\mathcal{E} = \langle Q, q_0, \Sigma, \Gamma, \mathcal{D}, \mathcal{P}, \delta, \lambda \rangle$$
where $\mathcal{D}$ is the data domain, and $\mathcal{P} = \{p_1, \dots, p_k\}$ is a dynamically expanding set of boolean predicates over $\mathcal{D} \times \mathcal{D}$ (e.g., $p(t_1, t_2) \equiv (\text{req}_1.\text{user} == \text{req}_2.\text{user})$ or $(\Delta t < 50\text{ms})$).

The discovery of a new dimension is formulated as the **synthesis of a separating predicate** $p^* \in \mathcal{P}$ when an output inconsistency counterexample $w \in \Sigma^*$ is detected during equivalence checking:
$$\delta(q, a \mid p^*) \neq \delta(q, a \mid \neg p^*)$$

#### 2. Objective Function
$$\mathcal{J}_{\text{AAL}}(p) = \text{MDL}(\mathcal{E} \cup \{p\}) - \text{MDL}(\mathcal{E}) + \alpha \cdot \text{Violations}(p)$$
where $\text{MDL}$ is the Minimum Description Length of the state machine, penalizing bloated state graphs while rewarding state splits that expose privilege escalations.

#### 3. State & Action Representation
- **State**: Observation table $(S, E, T)$ where $S \subseteq \Sigma^*$ is the prefix set and $E \subseteq \Sigma^*$ is the suffix distinguishing set.
- **Action**: Membership query $\sigma \in \Sigma^*$ or Conformance Test (Wp-method).

#### 4. Optimization & Complexity
- Optimization: Angluin $L^*$ algorithm augmented with Counterexample-Guided Abstraction Refinement (CEGAR) and Inductive Logic Programming (ILP) for predicate synthesis.
- Complexity: Polynomial in number of states $n$ and alphabet $|\Sigma|$, but predicate space $|\mathcal{P}|$ can explode exponentially without grammar pruning.

#### 5. Trade-offs
- **Advantages**: Proven convergence guarantees; directly produces state machines that human researchers and formal validators can audit.
- **Weaknesses**: Real-world web applications have non-deterministic elements (timestamps, CSRF tokens, UUIDs) that violate classical determinism assumptions of $L^*$, requiring heavy fuzzing stabilization.

---

### Candidate Formulation 3: Contrastive Causal Sensitivity over Behavioral Latent Embeddings (CCS-BLE)

#### 1. Formal Definition & The PCA Variance Trap
> **Critical Architectural Warning (The Variance Trap)**: Naive unsupervised dimensionality reduction (e.g., PCA or covariance matrix eigenvectors $\mathbf{\Sigma} = \mathbb{E}[(\phi(\tau) - \mu)(\phi(\tau) - \mu)^T]$) does **not** discover semantic security dimensions. In distributed web applications, benign stochastic noise (network jitter, timestamp progression, TCP window scaling, dynamic gzip compression ratios) exhibits massive statistical variance, while catastrophic security flaws (a single bit flipping an authorization context from 0 to 1, or a 2-byte tenant ID mismatch) exhibit minuscule statistical variance. Selecting high-variance eigenvectors wastes exploration budgets chasing network noise.

Therefore, we formalize **Contrastive Causal Sensitivity (CCS)**:
The target execution space is an infinite metric space $(\Omega, d_\Omega)$. We project execution traces through a contrastive encoder trained to separate interventional pairs:
$$\text{CCS}(d) = \frac{\mathbb{E}_{\tau}\left[ \mathcal{D}_{\text{sec}}(\tau, \text{do}(\tau \oplus \epsilon d)) \right]}{\|\epsilon d\|_{\mathcal{X}} + \delta} \times \text{Asymmetry}(d)$$
where $\mathcal{D}_{\text{sec}}$ specifically weights discrete security-relevant boundary shifts (HTTP $401/403 \to 200$, cross-tenant ID leakage, state transitions), and $\text{Asymmetry}(d) = |P(\text{Success} \mid \text{forward}) - P(\text{Success} \mid \text{reverse})|$ penalizes symmetric non-deterministic jitter to zero while elevating order- and state-dependent security breaches.

#### 2. Objective Function
Multi-objective MAP-Elites archive fitness:
$$\mathcal{F}(\tau) = \langle \text{Novelty}(\tau, \mathcal{A}), \text{Impact}(\tau), \text{CCS}(\text{Niche}(\tau)) \rangle$$
where $\text{Novelty}(\tau, \mathcal{A}) = \frac{1}{K} \sum_{i=1}^K \|\phi(\tau) - \phi(\tau_i)\|_2$ against the $K$-nearest neighbors in archive $\mathcal{A}$, filtered through causal sensitivity.

#### 3. State & Action Representation
- **State**: The MAP-Elites behavioral grid $\mathcal{G}_{\text{archive}}$ partitioned along the top discovered orthogonal contrastive dimensions.
- **Action**: Interventional mutation and recombination of HTTP execution sequences.

#### 4. Optimization & Complexity
- Optimization: Evolutionary multi-objective search (NSGA-II or CMA-ME) constrained by causal significance.
- Complexity: $\mathcal{O}(N \log N)$ per generation where $N$ is population size. Highly parallelizable.

#### 5. Trade-offs
- **Advantages**: Avoids the variance trap; isolates dimensions that exhibit causal asymmetry rather than noisy entropy; creative at finding unmodeled boundaries.
- **Weaknesses**: Requires baseline interventional calibration traces to distinguish true asymmetric effects from transient backend restarts.

---

# PART III: CANDIDATE CORE ALGORITHMS & THE WINNING SELECTION

## Section C: Ranking Candidate Approaches

We evaluate 5 concrete algorithmic paradigms across the required 7 criteria:

| Candidate Algorithm | (1) Novelty | (2) Feasibility | (3) Discovery Impr. | (4) Cost (Reqs) | (5) Complexity | (6) Benchmark | (7) Unknown-Unknowns | Total Rank |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Causal Intervention Discovery on Latent Graphs (CID-LG)** | 9/10 | 8/10 | 10/10 | Low ($\mathcal{O}(N \log N)$) | Moderate | High | 10/10 | **#1 (Winner)** |
| **2. CEGAR-Driven Separating Predicate Synthesis (CEGAR-SPS)** | 8/10 | 9/10 | 9/10 | Low ($\mathcal{O}(S \cdot |\Sigma|)$) | Low-Moderate | Very High | 8/10 | **#2 (Complement)** |
| **3. MAP-Elites Latent Dimension Evolution (MAP-LDE)** | 8/10 | 7/10 | 8/10 | High ($\mathcal{O}(P \cdot G)$) | Moderate | Moderate | 9/10 | **#3** |
| **4. Predictive State Representations with Subspace Tracking (PSR-ST)** | 9/10 | 5/10 | 7/10 | Very High | Very High | Low | 7/10 | **#4** |
| **5. Multi-Model Disagreement Committee (MMDC)** | 6/10 | 9/10 | 7/10 | Moderate | Low | High | 6/10 | **#5** |

---

## Section D: The Strongest Candidate: Causal Intervention Discovery on Latent Graphs (CID-LG)

### Why CID-LG Wins
In security research, **correlation is useless; only causation creates exploitability**.
- An attacker does not care that User A's profile happens to load slowly when User B logs in.
- An attacker cares if User A modifying field $X$ **causes** User B's authentication context to serialize into cache $Y$.

CID-LG formulates vulnerability discovery as **active causal discovery**:
1. It represents the target system not as static endpoints, but as a graph of observable variables $\mathcal{V}$ and latent variables $\mathcal{U}$.
2. When two execution traces produce divergent outcomes under identical request parameters, classical systems either discard it as jitter or declare an unexplainable anomaly. CID-LG asserts the existence of a **Latent Causal Variable** $U^*$.
3. It performs targeted interventional probes ($\text{do}(X)$) along candidate latent dimensions (temporal spacing, header encodings, thread interleaving) to isolate $U^*$.
4. Once $U^*$ is identified as causally controlling privilege, data access, or integrity, DOGE has discovered a **new dimension of behavior**.

---

## Section E: The Complementary Algorithm: CEGAR-Driven Predicate Synthesis (CEGAR-SPS)

While CID-LG isolates **which latent variable has causal power**, it does not synthesize the exact discrete symbolic rule that governs the vulnerability. 

**CEGAR-SPS** solves this:
- Once CID-LG determines that the temporal dimension $\Delta t$ or serialization key order causally alters state, CEGAR-SPS runs counterexample-guided abstraction refinement to synthesize the exact predicate:
$$\text{Predicate}^* \equiv \left(\text{Path}(\text{req}_1) == \text{Path}(\text{req}_2)\right) \land \left(t_2 - t_1 < 85\text{ms}\right) \land \left(\text{Tenant}(\text{req}_1) \neq \text{Tenant}(\text{req}_2)\right)$$
- This turns continuous causal signals into **sharp, deterministic, independently verifiable reproduction steps**.

---

# PART IV: THE CORE RESEARCH ALGORITHM: "AXIOM"

We formalize the combined architecture into a concrete, domain-specific algorithm:
**AXIOM**: **A**utonomous e**X**ploration of **I**nvariant **O**bservational **M**anifolds.

```
+-------------------------------------------------------------------------------+
|                                AXIOM ENGINE                                   |
+-------------------------------------------------------------------------------+
|                                                                               |
|   +----------------------+                     +--------------------------+   |
|   |  OBSERVATION BUFFER  |                     |   LATENT BASIS MINER     |   |
|   |  Traces tau in Omega | ----------------->  |   D_lat = CCS(Traces,Dsec)|  |
|   +----------------------+                     +--------------------------+   |
|             |                                                |                |
|             v                                                v                |
|   +----------------------+                     +--------------------------+   |
|   | CAUSAL GRAPH (SCM)   | <------------------ | INTERVENTION GENERATOR   |   |
|   | G = (V union U, E)   |                     | do(Dim = v_intervene)    |   |
|   +----------------------+                     +--------------------------+   |
|             |                                                |                |
|             v                                                v                |
|   +----------------------+                     +--------------------------+   |
|   | SURPRISE ARBITER     |                     | CEGAR PREDICATE SYNTH    |   |
|   | S(tau) = KL(P||Q)    | ----------------->  | Phi* = argmin MDL(Phi)   |   |
|   +----------------------+                     +--------------------------+   |
|             |                                                |                |
|             v                                                v                |
|   +----------------------+                     +--------------------------+   |
|   | ONTOLOGY EXPANDER    |                     | INDEPENDENT VALIDATOR    |   |
|   | Add Concept C_new    |                     | Negative Control & Impact|   |
|   +----------------------+                     +--------------------------+   |
|                                                              |                |
|                                                              v                |
|                                                +--------------------------+   |
|                                                | PROVEN FINDING + GRAPH   |   |
|                                                +--------------------------+   |
+-------------------------------------------------------------------------------+
```

## Section F: AXIOM Formal Specification & Pseudocode

### 1. Mathematical Definitions
- **Trace Space** $\Omega$: Each execution trace $\tau \in \Omega$ contains:
  $$\tau = \langle \text{ReqMethod}, \text{ReqURL}, \text{ReqHeaders}, \text{ReqBody}, \text{RespStatus}, \text{RespHeaders}, \text{RespBody}, t_{\text{start}}, t_{\text{latency}}, \text{ContextID} \rangle$$
- **Observational Basis** $\mathcal{B}_{\text{obs}}$: An orthonormal projection basis over extracted numerical and categorical trace features $\Psi(\tau) \in \mathbb{R}^D$.
- **Latent Dimension** $d \in \mathcal{D}_{\text{latent}}$: A directional vector in feature space along which interventional divergence occurs:
  $$\Delta_{\text{causal}}(d) = \mathbb{E}_{\tau}\left[ \| \Psi(\text{do}(\tau + \epsilon d)) - \Psi(\tau) \| \right]$$
- **Research Frontier** $\mathcal{F}_{\text{AXIOM}}$:
  $$\mathcal{F}_{\text{AXIOM}}(d, s) = \underbrace{U(s)}_{\text{Epistemic Uncertainty}} \times \underbrace{\Delta_{\text{causal}}(d)}_{\text{Causal Sensitivity}} \times \underbrace{\text{SecWeight}(s)}_{\text{Security Criticality}} \times \underbrace{\frac{1}{\sqrt{N(s, d) + 1}}}_{\text{Novelty / Unexploredness}}$$

### 2. AXIOM Core Execution Algorithm (Pseudocode)

```python
def AXIOM_Research_Loop(target, budget, safety_policy):
    """
    AXIOM: Autonomous eXploration of Invariant Observational Manifolds
    Discovers unmodeled behavioral dimensions, synthesizes interventions,
    induces new security concepts, and produces proven findings.
    """
    # 1. Initialize State
    causal_graph = SCMGraph()
    ontology = SecurityOntology.default()
    frontier = ResearchFrontier()
    proven_findings = []
    observation_archive = []
    
    # Baseline reconnaissance
    recon_traces = target.execute_baseline_recon()
    observation_archive.append(recon_traces)
    causal_graph.initialize_nodes(recon_traces)
    
    while budget.has_remaining() and not frontier.is_exhausted():
        # 2. Representation Discovery: Mine Latent Behavioral Dimensions
        candidate_dimensions = LatentBasisMiner.extract_dimensions(
            observation_archive, 
            causal_graph
        )
        # Dimensions include: TemporalDelta, SerializationOrder, KeyCasing,
        # PipelineInterleaving, IdempotencyReplay, BufferBoundary, etc.
        
        # 3. Frontier Prioritization
        active_target, active_dim = frontier.select_optimal_niche(
            candidate_dimensions, 
            causal_graph
        )
        
        # 4. Synthesize Interventional Experiment
        experiment = InterventionSynthesizer.generate(
            target=active_target,
            dimension=active_dim,
            graph=causal_graph,
            safety=safety_policy
        )
        
        # Execute controlled intervention pair: (Baseline vs Intervened)
        trace_baseline = target.execute(experiment.control)
        trace_intervened = target.execute(experiment.intervened)
        budget.consume(2)
        
        observation_archive.append([trace_baseline, trace_intervened])
        
        # 5. Measure Causal Divergence & Surprise
        surprise = CausalSurpriseEvaluator.compute_divergence(
            trace_baseline, 
            trace_intervened, 
            active_dim
        )
        
        if surprise.is_statistically_significant():
            # Update Causal Graph: Register new causal mechanism node
            latent_node = causal_graph.add_latent_variable(
                dimension=active_dim,
                cause=experiment.intervened.parameter,
                effect=surprise.affected_outputs
            )
            
            # 6. Check for Security Invariant Breakdown
            if surprise.violates_security_implication(ontology):
                # We observed unexpected behavior across the discovered dimension!
                # Synthesize separating predicate via CEGAR
                separating_predicate = CEGARPredicateSynthesizer.synthesize(
                    trace_baseline,
                    trace_intervened,
                    active_dim
                )
                
                # Formulate Emergent Candidate Vulnerability
                candidate = CandidateVulnerability(
                    title=f"Emergent {active_dim.name} Isolation Failure: {active_target.endpoint}",
                    dimension=active_dim,
                    predicate=separating_predicate,
                    reproduction_pair=(trace_baseline, trace_intervened)
                )
                
                # 7. Independent Validation Handoff
                # Validator uses fresh credentials and differential negative controls
                validation_result = IndependentValidator.verify(
                    candidate, 
                    target, 
                    safety_policy
                )
                budget.consume(validation_result.requests_made)
                
                if validation_result.is_confirmed():
                    # 8. Impact Demonstration
                    impact_result = ImpactResearcher.demonstrate(
                        candidate, 
                        target, 
                        validation_result.context
                    )
                    budget.consume(impact_result.requests_made)
                    
                    # 9. Synthesize Proven Finding
                    proven = ProvenFinding(
                        candidate=candidate,
                        validation=validation_result,
                        impact=impact_result,
                        causal_chain=causal_graph.extract_path(latent_node)
                    )
                    proven_findings.append(proven)
                    
                    # 10. Ontology Expansion: Introduce New Concept
                    if not ontology.contains_concept_for(active_dim):
                        new_concept = ontology.expand(
                            dimension=active_dim,
                            predicate=separating_predicate,
                            exemplar=proven
                        )
                        Logger.log(f"[ONTOLOGY EXPANSION] Learned new security concept: {new_concept.name}")
            
            # Reward frontier exploration along this productive dimension
            frontier.reward_dimension(active_dim, gain=surprise.magnitude)
        else:
            # Failure-driven learning: prune hypothesis space
            causal_graph.record_independence(
                experiment.intervened.parameter, 
                surprise.affected_outputs
            )
            frontier.penalize_niche(active_target, active_dim)
            
    return proven_findings, ontology, causal_graph
```

---

## Section G: Ontology Expansion Specification

When DOGE encounters behavior that violates security integrity across a previously unnamed dimension, it must **expand its ontology** rather than forcing the finding into a generic `UNKNOWN_VULNERABILITY` bucket.

### Concrete Expansion Workflow:
1. **Dimension Labeling**: The induced basis vector $d^*$ is projected onto structural tokens extracted from HTTP grammar (e.g., header names, parameter paths, status differentials). For instance, if intervening on request timing interval between frames reveals state bleed, the dimension is labeled `TemporalFrameJitter`.
2. **Invariant Synthesis**:
   $$\text{Invariant}_{\text{new}}(s) \equiv \forall t_1, t_2 \in \text{Pipeline}(s): \text{State}(t_2) \perp\!\!\!\perp \text{Identity}(t_1) \mid \Delta t$$
3. **Concept Formalization**:
   The ontology engine instantiates a new `SecurityConcept`:
   ```json
   {
     "concept_id": "CONCEPT_TEMPORAL_CONTEXT_LEAK",
     "dimension": "TemporalFrameJitter",
     "separating_predicate": "delta_t_ms < 120 && prior_auth != null",
     "violation_type": "STATE_CONFUSION",
     "severity": "high",
     "reproduction_template": "OrderInversionWithTimingInterval"
   }
   ```
4. **Permanent Registration**:
   The concept is added to `property.Catalog` and serialized into DOGE's persistent knowledge graph, allowing future missions on different targets to evaluate this newly invented property immediately.

---

## Section H: Experiment Synthesis Specification

Instead of choosing from a static hardcoded switch statement of test templates, AXIOM implements **Grammar-Guided Interventional Synthesis**:
Given a target endpoint and an induced dimension $d \in \mathcal{D}_{\text{latent}}$:
1. Parse the request schema into a typed Abstract Syntax Tree (AST):
   $$\text{AST}(\text{req}) = \langle \text{Method}, \text{URI\_Parts}, \text{Headers}, \text{Query}, \text{Body\_AST} \rangle$$
2. Identify AST nodes whose types intersect with dimension $d$:
   - If $d = \text{SerializationDuality}$: Apply duplicate key insertion with conflicting values `{"tenant_id": "alpha", "tenant_id": "beta"}` or unicode canonicalization mutation `admin` vs `adm\u0131n`.
   - If $d = \text{ConcurrencyRace}$: Synthesize synchronous HTTP/2 multiplexed frame bursts with zero-window TCP probing.
   - If $d = \text{IdempotencyReplay}$: Synthesize duplicate request replay with alternating authentication headers.
3. Compute semantic delta between mutated request and control request:
   $$\Delta_{\text{semantic}} = \text{AST}_{\text{mutated}} \ominus \text{AST}_{\text{control}}$$
4. The synthesized experiment is valid if and only if $\Delta_{\text{semantic}}$ isolates the single dimension $d$ while keeping all other variables constant (Pearl's condition for unconfounded causal effect identification).

---

## Section I: Unknown-Space Algorithm

To discover behaviors outside its current knowledge, DOGE implements **Maximal Discrepancy Active Falsification (MDAF)**:
1. Maintain an ensemble of two predictive models:
   - **Model $\mathcal{M}_{\text{nominal}}$**: Predicts standard RFC-compliant HTTP behavior.
   - **Model $\mathcal{M}_{\text{stateful}}$**: Predicts execution state retention across requests.
2. Formulate the unknown-space objective as finding inputs $x$ that maximize epistemic disagreement:
   $$x^* = \arg\max_{x \in \mathcal{X}_{\text{valid}}} D_{\text{JS}}\left(\mathcal{M}_{\text{nominal}}(x) \parallel \mathcal{M}_{\text{stateful}}(x)\right)$$
3. Execute $x^*$ against the real target:
   - If the target matches $\mathcal{M}_{\text{nominal}}$, uncertainty decreases.
   - If the target matches neither model, **an unknown-unknown has been encountered**. DOGE freezes the trace pair and triggers the Latent Basis Miner.

---

## Section J: Failure-Driven Learning Specification

In current tools, a failed test (e.g., HTTP 403 or 400) is treated as a dead end. In AXIOM, a failure is an **informative boundary constraint**:
1. **Causal Edge Pruning**: If intervening on parameter $X$ yields identical error responses (e.g., HTTP 400 `Invalid Schema`), the causal edge $X \to Y$ is zeroed out in the SCM. DOGE avoids testing mutations on $X$.
2. **Precondition Discovery**: If an endpoint returns 409 Conflict with body `{"error": "state must be pending_review"}`, the failure is parsed by the state inference engine to add a prerequisite transition:
   $$\text{Prerequisite}(\text{TargetEndpoint}) \leftarrow \text{State} == \text{"pending\_review"}$$
3. **Equivalence Class Collapse**: When an intervention fails, all input mutations sharing the same algebraic equivalence class are marked refuted simultaneously, preventing combinatorial fuzzing loops.

---

# PART V: BENCHMARK SUITE, ABLATION STUDY, & FALSIFICATION

## Section K: Benchmark Suite Design

To prove that AXIOM achieves representation discovery rather than brute-force luck, we specify two novel benchmarks representing vulnerabilities that **cannot be discovered by Phase 1 or Phase 2 DOGE**:

### Benchmark 1: BENCH-004 — Latent Race Window Serialization Collapse
- **Mechanism**: A wallet transfer endpoint `/api/v1/wallet/transfer` performs account balance checks and ledger updates asynchronously. If two transfers are submitted within a $40\text{ms}$ latency window, both balance checks evaluate to `true` before either deduction writes to storage.
- **Why Phase 1 & 2 Fail**: Phase 1 tests single-sequence workflow skips. Phase 2 tests batch sub-operation ordering. Neither has a temporal concurrency dimension.
- **AXIOM Success Condition**: AXIOM detects latency variance under repeated probe executions, induces the `TemporalConcurrency` dimension, synthesizes a synchronized packet pair, discovers negative balance collapse, validates with differential controls, and proves financial exploitation.

### Benchmark 2: BENCH-005 — Cache Key Collision Normalization Bleed
- **Mechanism**: Reverse proxy normalizes `/api/v1/reports/private/..%2Fpublic` to `/api/v1/reports/public` in its cache key, but forwards the raw URI to the backend. An unauthenticated attacker requesting the poisoned path receives cached confidential reports.
- **Why Phase 1 & 2 Fail**: The vulnerability is not in the API business logic or the state machine; it exists in the mismatch between proxy cache hashing and backend routing.
- **AXIOM Success Condition**: AXIOM intervenes on path encoding transformations, observes cache header differential hits (`X-Cache: HIT`), induces the `CacheNormalizationDuality` dimension, and exfiltrates confidential tenant reports.

### Quantitative Evaluation Metrics
1. **Dimensional Induction Efficiency**: Number of HTTP requests required to discover a novel dimension (Target: $< 50$ requests).
2. **Causal False Positive Rate**: Percentage of flagged anomalies that fail independent validation (Target: $< 5\%$).
3. **Representation Generalization**: Number of zero-day vulnerabilities discovered on un-modeled architectures without modifying source code.

---

## Section L: Ablation Study Design

To scientifically demonstrate which components produce the breakthrough, we evaluate 4 ablated configurations against BENCH-001 through BENCH-005:

| Configuration | Latent Basis Miner | Causal Interventional Arbiter | CEGAR Predicate Synthesizer | Expected Performance |
| :--- | :---: | :---: | :---: | :--- |
| **Full AXIOM** | **Yes** | **Yes** | **Yes** | 100% discovery across all 5 benchmarks with minimal request budget. |
| **Ablation 1 (No Causal Arbiter)** | Yes | No (Heuristic Scoring) | Yes | High false positive rate; wastes budget chasing benign HTTP jitter and timing fluctuations. |
| **Ablation 2 (No CEGAR Synthesizer)** | Yes | Yes | No (Raw Payload Replay) | Candidate reproduction fails validation; cannot synthesize sharp boundary predicates for complex bugs. |
| **Ablation 3 (No Latent Basis Miner)** | No (Fixed Phase 2 Dimensions) | Yes | Yes | **Completely fails BENCH-004 and BENCH-005**; bounded by Phase 2 ontology. |
| **Baseline (Phase 2 DOGE)** | No | No | No | Passes BENCH-001, 002, 003. Fails BENCH-004, 005. |

---

## Section M: Falsification Criteria (How This Hypothesis Could Be Wrong)

Scientific integrity requires stating in advance what experimental results would **falsify** this architecture:

1. **The Combinatorial Dimensionality Collapse**:
   - *Falsification Condition*: If the space of latent dimensions in enterprise web applications is so high-dimensional ($\mathcal{D} > 10^4$) that active causal intervention requires more than 5,000 requests per endpoint to isolate an invariant, active representation discovery is computationally intractable for black-box penetration testing.
   - *Abandonment Trigger*: If random mutation fuzzing discovers vulnerabilities faster than causal basis induction across a 20-app benchmark.

2. **The LLM Semantic Invariance Paradox**:
   - *Falsification Condition*: If modern foundation models with 2M token context windows can implicitly discover latent dimensions via pure in-context learning over raw HTTP histories without needing an explicit SCM or predicate synthesis engine.
   - *Abandonment Trigger*: If prompt-engineered GPT-5 / Claude 4.5 outperforms AXIOM on BENCH-004/005 zero-shot without structural scaffolding.

3. **Non-Determinism Jamming**:
   - *Falsification Condition*: If real-world cloud APIs possess enough stochastic noise (network jitter, distributed database replication lag, rate limits) to make causal conditional independence tests statistically undecidable within bounded request limits.

---

# PART VI: IMPLEMENTATION PLAN & PRIMARY LITERATURE

## Section N: Modular Architecture Plan for DOGE

To implement Phase 3 cleanly without disrupting existing Phase 1 & 2 components, we specify the following modular architecture:

```text
internal/
├── causal/                 # Structural Causal Model & Interventions
│   ├── scm.go             # Causal DAG representation (nodes, edges, weights)
│   ├── intervention.go    # do(X=x) interventional operators & atomic mutations
│   └── independence.go    # d-separation and conditional independence testing
├── dimension/              # Latent Behavioral Basis Induction
│   ├── basis.go           # Dimension interfaces & coordinate projections
│   ├── miner.go           # Discrepancy analysis & latent basis discovery
│   └── temporal.go        # Temporal jitter & race window basis extractors
├── synthesis/              # Program & Predicate Synthesis
│   ├── cegar.go           # Counterexample-Guided Abstraction Refinement loop
│   ├── grammar.go         # HTTP request/response AST grammar definitions
│   └── predicate.go       # Symbolic boolean predicate representations
├── ontology/               # Dynamic Security Concept Learning
│   ├── concept.go         # SecurityConcept models & epistemic state
│   ├── expander.go        # Automated ontology expansion engine
│   └── registry.go        # Dynamic concept persistence & lookup
└── benchmark/
    ├── race_app.go        # BENCH-004: Latent Race Window Benchmark
    └── cache_app.go       # BENCH-005: Cache Key Collision Benchmark
```

---

## Section O: Foundational Literature & Research References

1. **Judea Pearl (2009)**: *Causality: Models, Reasoning, and Inference* (Cambridge University Press).  
   *What DOGE learns*: The formal mathematical distinction between observational conditioning $P(Y \mid X)$ and interventional conditioning $P(Y \mid \text{do}(X))$. Essential for proving that an authorization bypass is causally produced by an attacker intervention rather than environment noise.

2. **Bernhard Schölkopf et al. (2021)**: *Toward Causal Representation Learning* (Proceedings of the IEEE).  
   *What DOGE learns*: How to learn low-dimensional causal representations from high-dimensional observational data. Provides the mathematical foundation for AXIOM's Latent Basis Miner.

3. **Dana Angluin (1987)**: *Learning Regular Sets from Queries and Counterexamples* (Information and Computation).  
   *What DOGE learns*: The $L^*$ algorithm for active automata inference using membership queries and equivalence queries. Adapted for black-box protocol and state-machine discovery.

4. **Edmund M. Clarke et al. (2003)**: *Counterexample-Guided Abstraction Refinement for Symbolic Model Checking* (Journal of the ACM).  
   *What DOGE learns*: The CEGAR loop. When an abstract system model produces a counterexample, analyze whether it is spurious; if spurious, synthesize a separating predicate that refines the abstraction.

5. **Kenneth O. Stanley & Joel Lehman (2015)**: *Why Greatness Cannot Be Planned: The Secret to the Breakthrough* (Springer).  
   *What DOGE learns*: Novelty Search. Proves mathematically that searching for novelty rather than an objective function frequently solves deceptive, complex tasks where intermediate steps do not resemble the final goal.

6. **Ross D. King et al. (2009)**: *The Automation of Science* (Science).  
   *What DOGE learns*: The "Robot Scientist" (Adam/Eve) architecture. Formulates the complete closed-loop scientific process: automated hypothesis formulation, active Bayesian experiment selection, physical execution, and deductive model refinement.

7. **Jonas Peters, Peter Bühlmann, & Nicolai Meinshausen (2016)**: *Causal inference by using invariant prediction: identification of causal mechanisms* (JRSS Series B).  
   *What DOGE learns*: Invariant Causal Prediction (ICP). A causal mechanism remains invariant across different experimental environments. If an invariant breaks across environments, a causal factor has changed.

---

# PART VII: FINAL DECISION

Here are the direct, unambiguous answers to the core research questions:

### 1. What is the single most important algorithmic capability DOGE currently lacks?
**Latent Behavioral Basis Discovery (Representation Discovery)**. DOGE currently lacks the computational mechanism to discover *which physical or logical dimension of execution* (timing intervals, encoding normalization, serialization key ordering, asynchronous task queue states) is causally responsible for system behavior when that dimension has not been pre-programmed into its projection functions.

### 2. What is the strongest existing scientific/technical approach for solving it?
**Active Causal Discovery on Latent Structural Causal Models (SCM) with Interventional Probing** (grounded in Pearl and Schölkopf's causal representation learning).

### 3. What second capability should be combined with it?
**Counterexample-Guided Abstraction Refinement with Predicate Synthesis (CEGAR-PS)** (grounded in Clarke's formal verification). Causal discovery identifies *which variable matters*; CEGAR synthesizes the *exact symbolic predicate and reproducible test case*.

### 4. What would the combined DOGE algorithm look like?
The **AXIOM Algorithm** (Autonomous eXploration of Invariant Observational Manifolds):
$$\text{Observe} \to \text{Mine Latent Basis} \to \text{Prioritize Frontier} \to \text{Intervene } \text{do}(X) \to \text{Measure Causal Surprise} \to \text{Synthesize Predicate} \to \text{Validate} \to \text{Demonstrate Impact} \to \text{Expand Ontology}$$

### 5. What experiment would prove that it actually works?
Deploying DOGE against **BENCH-004 (Latent Race Window Concurrency)** and **BENCH-005 (Cache Key Collision Normalization Bleed)** where:
- No concurrency or cache-key testing rules exist in DOGE.
- DOGE autonomously induces the timing/normalization dimension, synthesizes the interventional pair, validates the vulnerability with differential controls, exfiltrates confidential assets, and expands its security ontology.

### 6. What result would prove that the idea failed?
If on an un-modeled target, the Latent Basis Miner generates an intractably large feature space ($\mathcal{D} > 10^4$) where active causal intervention requires more HTTP requests than random mutation fuzzing, or if environmental non-determinism prevents conditional independence tests from converging within 5,000 requests.

### 7. Does this represent a genuine architectural advance over Phase 2, or is it merely another implementation layer?
It is a **fundamental epistemic advance**:
- **Phase 1** learned *what state machine transitions to test* (Property Reasoning).
- **Phase 2** learned *how to detect violations of inferred invariants* (Metamorphic Probing).
- **Phase 3 (AXIOM)** learns *what dimensions of reality exist in the target system and invents new security concepts* (Representation Discovery & Ontology Expansion).

### 8. What is the next research question after this one?
**Cross-Target Epistemic Transfer (Meta-Security Science)**: Once DOGE discovers a novel latent dimension and invents a new security concept on Target A, how can it transfer the *abstract causal mechanism* to Target B with completely different technology stacks, frameworks, and protocols without memorizing endpoint signatures or suffering negative transfer?

---

# PART VIII: THE THREE-TIER ARCHITECTURE & MODEL ROUTER SPECIFICATION

## 1. The Architectural Separation: LLM vs AXIOM vs DOGE

A fatal mistake in modern "AI security tools" is making the LLM the brain of the scanner:
$$\text{DOGE} \xrightarrow{\text{"what to test?"}} \text{LLM} \xrightarrow{\text{"send this request"}} \text{LLM}$$
This degenerates into an unfocused, non-deterministic prompt wrapper subject to hallucination, memory degradation, and unprincipled trial-and-error.

DOGE establishes a strict three-tier epistemic hierarchy:
- **LLM = Reasoning Substrate**: A specialized semantic engine called on demand for abstraction, semantic clustering, naming newly discovered concepts, explaining unmodeled application behavior, and generating seed hypotheses.
- **AXIOM = Research Algorithm**: The deterministic scientific research engine that owns the search frontier, causal graph, latent basis mining, CEGAR predicate synthesis, and invariant evaluation.
- **DOGE = Autonomous Research Operating System**: The parent operating system that owns the world model, persistent memory, attack graph, evidence vault, independent validation harness, and deterministic safety kernel.

```text
                         ┌──────────────────────┐
                         │      DOGE CLI        │
                         └──────────┬───────────┘
                                    │
                                    ↓
                         ┌──────────────────────┐
                         │   RESEARCH DIRECTOR  │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             ↓                      ↓                      ↓
       WORLD MODEL              AXIOM                 MEMORY
             │                      │                      │
             │              ┌───────┴───────┐              │
             │              ↓               ↓              │
             │        Representation     Causal            │
             │          Discovery       Discovery          │
             │              │               │              │
             └──────────────┼───────────────┼──────────────┘
                            ↓
                     HYPOTHESIS ENGINE
                            │
                            ↓
                    EXPERIMENT SYNTHESIS
                            │
                    ┌───────┴────────┐
                    ↓                ↓
             deterministic         LLM
             algorithms          reasoning
                    │                │
                    └───────┬────────┘
                            ↓
                       SAFETY GATE (DETERMINISTIC)
                            │
                            ↓
                    AUTHORIZED EXECUTION
                            │
                            ↓
                        OBSERVATIONS
                            │
                 ┌──────────┴──────────┐
                 ↓                     ↓
           CAUSAL ANALYSIS       EVIDENCE ENGINE
                 │                     │
                 └──────────┬──────────┘
                            ↓
                       VALIDATION (INDEPENDENT)
                            │
                            ↓
                     ATTACK GRAPH
                            │
                            ↓
                    PROVEN FINDING
                            │
                            ↓
                    LEARNING SYSTEM
                            │
                            └────────→ WORLD MODEL
```

---

## 2. Model-Provider Agnostic Architecture (`ModelRouter`)

DOGE is completely decoupled from any single AI vendor. The architecture exposes a unified Go interface:

```go
package ai

import "context"

// ReasoningModel is the universal interface implemented by all model providers.
type ReasoningModel interface {
    ProviderName() string
    ModelID() string
    Generate(ctx context.Context, req ReasoningRequest) (ReasoningResponse, error)
}
```

Behind this interface, `ModelRouter` routes reasoning queries dynamically based on task criticality, latency constraints, and operational privacy:

```text
DOGE
 │
 └── ModelRouter
       │
       ├── OpenRouter (Gateway to Claude 3.5 Sonnet, GPT-4o, Gemini 1.5 Pro)
       ├── OpenAI-Compatible Endpoint (Local vLLM, DeepSeek-Coder, LocalAI)
       ├── Local Ollama (Quantized Llama-3/Mistral/Qwen running completely offline)
       └── Custom Dedicated Inference Server
```

---

## 3. Division of Labor Matrix: Where AI is Used vs Where AI is Forbidden

To prevent stochastic AI errors from compromising security research integrity, DOGE enforces a rigid division of labor:

| Research Responsibility | Execution Engine | Rationale |
| :--- | :--- | :--- |
| **Fast Classification & Labeling** | Small / Local Model (e.g. Ollama Llama-3 8B) | High speed, zero token cost, routine categorization |
| **HTTP Semantic Interpretation** | Local / Specialized Model | Parses domain logic, field meanings, business context |
| **Novel Concept Naming & Grounding** | Frontier Model (Claude / GPT via OpenRouter) | High semantic abstraction and vocabulary synthesis |
| **Complex Hypothesis Generation** | Frontier Model (Claude / GPT via OpenRouter) | High-order abductive reasoning over causal surprises |
| **Code & Script Analysis** | Coding Model (e.g. DeepSeek-Coder / Claude Sonnet) | Precise AST and syntax understanding |
| **Mathematical Causal D-Separation** | **Deterministic Go Code (NO LLM)** | Requires exact graph conditional independence computation |
| **Statistical Significance Testing** | **Deterministic Go Code (NO LLM)** | Must be mathematically rigorous (p-values, KL divergence) |
| **Scope & Authorization Enforcement** | **Deterministic Go Code (NO LLM)** | Zero tolerance for AI hallucination over authorized boundaries |
| **Safety Gate & Rate Limiting** | **Deterministic Go Code (NO LLM)** | Hard security boundaries cannot be influenced by LLM output |
| **Evidence Cryptographic Integrity** | **Deterministic Go Code (NO LLM)** | SHA-256 raw request/response byte records are immutable |
| **Independent Reproduction Validation** | **Deterministic Go Code (NO LLM)** | Separate researcher must confirm exploitability empirically |

---

## 4. Formal Definition of Autonomy in DOGE

We establish the foundational definition of research autonomy:

> **DOGE autonomy means that DOGE autonomously chooses what security question to investigate next, why that question is valuable, what experiment can answer it, how empirical evidence alters its internal beliefs, and whether the resulting anomaly deserves validation, while deterministic policy remains absolute and authoritative over what actions it is permitted to perform.**

