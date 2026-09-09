# DOGE Open Research Problems

## Problems That Don't Have Known Solutions

These are genuine research questions that DOGE must solve. Not implementation tasks — research problems that require experimentation, measurement, and iteration.

---

### 1. How to Generate Novel Security Hypotheses

**The problem**: Given a world model of an application, how does DOGE generate hypotheses about security properties that might not hold — including properties and violations that its designers never explicitly programmed?

**Why it's hard**: Current hypothesis generation is either pattern-matching (regex on observations) or LLM-prompted (which inherits the model's training biases). Neither naturally produces hypotheses about truly novel vulnerability mechanisms.

**Research direction**:
- Anomaly-first research: "I cannot explain this behavior" → investigate
- Security property enumeration: systematically derive testable properties from the world model
- Differential analysis: unexpected differences between principals/endpoints/states → hypotheses
- Abductive reasoning: given the observation, what could explain it?

**Measurement**: Count of findings that don't match any pre-programmed vulnerability class.

---

### 2. Information-Gain-Optimal Experiment Selection

**The problem**: Given N possible experiments and limited budget, which experiment would reduce the most uncertainty about the target's security properties?

**Why it's hard**: Computing true information gain requires knowing the probability distribution over world model states, which is exactly what we're trying to learn. The problem is partially observable.

**Research direction**:
- Bayesian experiment design adapted to security research
- Multi-armed bandit approaches to exploration vs. exploitation
- Hypothesis discrimination: choose experiments that maximally separate competing hypotheses
- Coverage-driven: choose experiments that test untested surfaces

**Measurement**: Uncertainty reduction per experiment over a benchmark suite.

---

### 3. Attack Chain Discovery in Sparse Graphs

**The problem**: Given a large world model with many individually weak observations, how does DOGE discover that specific combinations form a security-critical chain?

**Why it's hard**: The combinatorial explosion of potential chains is enormous. Most combinations are meaningless. The attack graph is sparse and most edges are uncertain.

**Research direction**:
- Capability-based chain reasoning: "This grants capability X. What does capability X unlock?"
- Template-guided chain search: common chain patterns (SSRF→internal, auth bypass→escalation)
- LLM-assisted chain hypothesis: "Given these observations, could they form an attack chain?"
- Incremental chain construction: build chains forward from confirmed capabilities

**Measurement**: Chain finding rate on benchmark Level 8+ challenges.

---

### 4. Cross-Target Learning Without Overfitting

**The problem**: How does DOGE learn from past engagements without overfitting to specific targets?

**Why it's hard**: "Parameter X was injectable on Target A" does not mean "Parameter X is injectable on all targets." But "This technology stack commonly has injection on admin endpoints" might transfer. The right level of abstraction is unclear.

**Research direction**:
- Hierarchical learning: technology-level > endpoint-level > parameter-level
- Confidence decay: learned rules lose confidence over time without re-confirmation
- Negative transfer detection: identify when past learning hurts current research
- Provenance-backed learning: every learned rule carries evidence for review

**Measurement**: Performance on new targets after training on similar targets, vs. performance cold.

---

### 5. When to Stop Researching

**The problem**: In continuous research mode, how does DOGE decide when it has learned enough about a target? When should it reduce research intensity?

**Why it's hard**: The absence of findings could mean "the target is secure" or "DOGE hasn't looked in the right places yet." Distinguishing these requires meta-reasoning about research coverage.

**Research direction**:
- Coverage-based stopping: stop when all security properties are tested with high confidence
- Diminishing returns detection: stop when information gain per experiment drops below threshold
- Change-triggered reactivation: resume when target changes are detected
- Periodic re-evaluation: scheduled deep re-research to find things initially missed

**Measurement**: False negative rate on targets where DOGE declares "research complete."

---

### 6. Safe Autonomous Exploit Development

**The problem**: How does DOGE develop exploits that demonstrate real impact without causing unintended harm?

**Why it's hard**: A proof-of-concept must demonstrate the vulnerability is real, but "real" can mean "actually destructive." The line between "proof" and "damage" must be enforced deterministically, not by LLM judgment.

**Research direction**:
- Read-only exploitation first (data leakage proof without modification)
- Idempotent operations only (requests that don't change state)
- Canary-based validation (plant known data, demonstrate retrieval)
- Impact level controls (configurable: confirm only / demonstrate / controlled escalation)

**Measurement**: Impact demonstration completeness × safety violation rate.

---

### 7. Multi-Model Orchestration for Security Research

**The problem**: Different model providers have different strengths. How does DOGE route different research tasks to the optimal model while maintaining coherent research state?

**Why it's hard**: Model behavior varies across providers, versions, and configurations. A hypothesis generated by Model A must be interpretable by Model B for experiment design. The world model is the shared state, but reasoning coherence across models is not guaranteed.

**Research direction**:
- Structured interfaces: all model interactions through typed schemas, not freeform text
- World-model-grounded reasoning: models always reason from structured state, not conversation history
- Model capability profiles: benchmark each model on research subtasks and route accordingly
- Fallback chains: if preferred model fails, degrade gracefully to next available

**Measurement**: Research quality metrics across model configurations.

---

### 8. Adversarial Robustness of the Research Loop

**The problem**: Can an attacker manipulate DOGE's research by crafting target responses that cause false conclusions?

**Why it's hard**: DOGE ingests server responses as evidence. A malicious server could return misleading responses that cause DOGE to generate false-positive findings, miss real vulnerabilities, or waste budget.

**Research direction**:
- Response consistency verification: same request → same response
- Cross-source triangulation: verify server claims from multiple vantage points
- Anomalous response detection: flag responses that seem designed to mislead
- Evidence skepticism: higher proof standard for unusual observations

**Measurement**: False positive/negative rate against adversarial synthetic targets.

---

### 9. Explaining Research Decisions

**The problem**: A human asks "why did you test that?" DOGE must explain its research reasoning in terms a security professional can evaluate.

**Why it's hard**: The decision chain crosses world model state, hypothesis engine, information gain scoring, and researcher-specific logic. Reconstructing a human-readable explanation from this pipeline is non-trivial.

**Research direction**:
- Decision trace: record the complete reasoning chain at each mission dispatch
- Counter-factual explanations: "I tested this because testing X instead would have given less information"
- Hypothesis-grounded explanations: "I tested this to distinguish between hypotheses A and B"
- Natural language summarization of structured decision traces

**Measurement**: Human evaluator agreement on "was this a reasonable research decision?"

---

### 10. Benchmark Contamination Prevention

**The problem**: If DOGE learns from benchmarks, it might memorize benchmark signatures rather than develop general research capability.

**Why it's hard**: Any fixed benchmark eventually becomes a memorization target. But varying benchmarks makes regression testing impossible.

**Research direction**:
- Randomized benchmark generation: same vulnerability logic, different surface details
- Hold-out benchmarks: test against challenges DOGE has never seen
- Capability probes: test specific research capabilities in isolation
- Transfer benchmarks: train on one technology, test on another

**Measurement**: Performance gap between seen vs. unseen benchmarks.
