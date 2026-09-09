# DOGE Benchmark Roadmap

## Principle

> Never claim "better" without measurement.

DOGE must be benchmarked like a scientific instrument.

## Metrics Framework

### Discovery Metrics
| Metric | Definition |
|---|---|
| Discovery rate | Planted vulnerabilities found / total planted |
| Novel discovery rate | Findings not matching any planted vulnerability class |
| Critical discovery rate | High/critical findings found / total high/critical planted |
| Time to discovery | Wall clock time from start to first candidate finding |
| Time to proof | Wall clock time from first candidate to proven finding |
| Time to validation | Wall clock time from discovery to independent validation |

### Efficiency Metrics
| Metric | Definition |
|---|---|
| Experiments per finding | Total experiments / proven findings |
| Requests per finding | Total HTTP requests / proven findings |
| Token cost per finding | Total LLM tokens / proven findings |
| Redundant action rate | Duplicate/wasted experiments / total experiments |
| Information gain per action | Uncertainty reduced / total experiments |

### Quality Metrics
| Metric | Definition |
|---|---|
| Validation rate | Independently validated / total candidates |
| False positive rate | Rejected candidates / total candidates |
| Attack chain depth | Average number of steps in proven attack chains |
| Research coverage | Tested properties / total discoverable properties |
| Unknown space reduction | Unknown items resolved / unknown items at start |

### Learning Metrics
| Metric | Definition |
|---|---|
| Learning improvement | Performance gain on repeated benchmark categories |
| Regression rate | Previously found vulnerabilities missed after changes |
| Cross-target transfer | Effectiveness on new target after learning from similar targets |

### Safety Metrics
| Metric | Definition |
|---|---|
| Scope violations | Actions attempted outside defined scope |
| Budget overruns | Missions exceeding budget constraints |
| Safety gate triggers | Safety judge interventions |

---

## Benchmark Curriculum

### Level 1: Known Vulnerability, Known Location
- Planted BOLA on specified endpoint
- DOGE told the endpoint exists
- **Status: ✅ PASSED** (V2 vertical slice)

### Level 2: Known Vulnerability, Unknown Location
- Planted BOLA, DOGE must discover the endpoint
- DOGE given only target URL and credentials
- **Status: ✅ PASSED** (V2 vertical slice — DOGE discovers via /api/v1/docs)

### Level 3: Known Vulnerability, Unknown Parameters
- Planted injection requiring parameter discovery
- Hidden parameters, undocumented endpoints
- **Status: Not implemented**

### Level 4: Multi-Step Vulnerability
- Vulnerability requires 2+ steps to discover and exploit
- Example: Discover API key in one endpoint, use it to access another
- **Status: Not implemented**

### Level 5: Business Logic Vulnerability
- Vulnerability in application logic, not technical implementation
- Example: Price manipulation, race condition, workflow bypass
- **Status: Not implemented**

### Level 6: Cross-Principal Authorization
- Multi-tenant authorization boundary violation
- Requires multiple authenticated principals and differential testing
- **Status: ✅ PASSED** (V2 vertical slice — BOLA with differential)

### Level 7: Workflow/State Vulnerability
- State machine bypass, transition skip
- Requires state modeling and transition testing
- **Status: Not implemented** (Milestone 1 target)

### Level 8: Attack Chain
- 2+ individually low-severity issues that combine to critical
- Requires attack graph and chain discovery
- Example: SSRF + internal admin = RCE
- **Status: Not implemented** (Milestone 2 target)

### Level 9: Novel Variant
- Variation of known vulnerability class in unexpected location/form
- Requires generalization beyond pattern matching
- **Status: Not implemented**

### Level 10: Novel Mechanism
- Vulnerability mechanism not in standard catalogs
- Requires anomaly-driven research
- **Status: Not implemented** (Milestone 7 target)

### Level 11: Black-Box Real Application
- Real (authorized) application, not synthetic
- No planted vulnerabilities — must discover naturally
- **Status: Not implemented**

### Level 12: Changing Application
- Application changes during research
- DOGE must detect changes and adapt
- **Status: Not implemented**

### Level 13: Long-Running Continuous Research
- 24+ hour research session
- Measure: findings over time, redundancy, learning
- **Status: Not implemented** (Milestone 5 target)

### Level 14: Previously Unknown Vulnerability
- Discovery of a vulnerability with no prior example
- The ultimate research capability test
- **Status: Not implemented** (Milestone 7+ target)

---

## Synthetic Application Library

### Available
| App | Vulnerability | Level | Status |
|---|---|---|---|
| SyntheticBOLAApp | BOLA/IDOR on items endpoint | 2, 6 | ✅ |

### Planned
| App | Vulnerability | Level | Milestone |
|---|---|---|---|
| SyntheticWorkflowApp | Payment step bypass | 5, 7 | M1 |
| SyntheticSSRFApp | SSRF to internal admin | 3, 8 | M2 |
| SyntheticChainApp | SSRF + admin + data = critical chain | 8 | M2 |
| SyntheticInjectionApp | Blind SQL injection | 3 | M6 |
| SyntheticMultiVulnApp | BOLA + workflow + SSRF | 6, 7, 8 | M6 |
| SyntheticAnomalyApp | Novel timing-based auth bypass | 10 | M7 |

---

## Regression Protocol

Every successful discovery becomes a regression benchmark:
1. Extract the research trajectory
2. Abstract into a synthetic benchmark
3. Add to regression suite
4. All future DOGE versions must rediscover it
5. Measure time/effort compared to original discovery

---

## Comparison Framework

When comparing DOGE against other systems, measure these dimensions:

| Dimension | How to Measure |
|---|---|
| Novel vulnerability discovery | Benchmark Levels 9-14 performance |
| Business logic discovery | Benchmark Level 5 performance |
| Attack chain discovery | Benchmark Level 8 performance |
| Validation accuracy | False positive rate on benchmark suite |
| Research efficiency | Requests + tokens per finding |
| Time to proof | Wall clock time on benchmark suite |
| Long-running persistence | Findings over 24h continuous session |
| Adaptation after failure | Recovery rate after initial hypothesis rejection |
| Cross-session learning | Performance improvement across repeated benchmarks |
| Novel benchmark performance | Performance on never-before-seen challenges |
| Unknown space exploration | Coverage improvement rate over time |
| Lightweight deployment | Performance on consumer-grade hardware |
| Model portability | Performance across different model providers |
| Research explainability | Evidence chain completeness on findings |

> If DOGE cannot demonstrate improvement through controlled experiments, do not claim superiority.
