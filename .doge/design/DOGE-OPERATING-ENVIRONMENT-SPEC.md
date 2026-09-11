# DOGE: Autonomous Security Research Operating Environment
## Architectural Specification & Master Product Blueprint

**Status**: Approved Architecture & Engineering Blueprint  
**Version**: 3.0 (Security Research Operating Environment)  
**Date**: 2026-09-12  
**Target Platform**: Windows 11 Desktop (Cockpit) + WSL2 Linux (Laboratory) + DOGE Go Core (Kernel)

---

## Executive Summary

DOGE is an **autonomous, evidence-driven security research operating environment**. It is not merely a command-line wrapper, a vulnerability scanner, or an IDE plugin; it is a unified workstation designed to conduct algorithmic security science.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                         DOGE OPERATING ENVIRONMENT                       │
├───────────────────────────────┬──────────────────────────────────────────┤
│ THE COCKPIT                   │ Windows Native Application (Wails Shell) │
│ THE KERNEL                    │ DOGE Go Core Engine (Offline & Provable) │
│ THE LABORATORY                │ WSL2 Linux (Managed, Versioned, Sandboxed)│
│ THE SUBJECT                   │ Authorized Target Surface & Source Code  │
└───────────────────────────────┴──────────────────────────────────────────┘
```

The system operates around a central epistemic principle:
> **Target $\to$ World Model $\to$ Uncertainty Frontier $\to$ Causal Experiment $\to$ Cryptographic Evidence $\to$ Verified Knowledge**

The LLM is bounded and replaceable as a hypothesis/labeling source. Deterministic Go code strictly owns authorization, scope enforcement, validation truth, execution safety, and cryptographic certification.

---

## 1. The 4-Tier Architectural Separation

```text
                         DOGE DESKTOP
                  Windows Native Application (Cockpit)
                             │
             ┌───────────────┴────────────────┐
             │                                │
        GUI / IDE Layer                 System Integration
      (Wails / TypeScript)              (internal/runtime)
             │                                │
       ┌─────┴─────┐                  ┌──────┴──────┐
       │ Workspace │                  │ WSL Manager │
       │ Explorer  │                  │ Terminal    │
       │ Canvas    │                  │ Processes   │
       │ Findings  │                  │ Resources   │
       │ Graphs    │                  │ Events SSE  │
       │ Timeline  │                  └──────┬──────┘
       └─────┬─────┘                         │
             │                               ▼
             │                         WSL2 Security VM
             │                           (Laboratory)
             │                               │
             │                         ┌─────┴─────┐
             │                         │ DOGE Core │
             │                         │ Go Engine │
             │                         └─────┬─────┘
             │                               │
             │                 ┌─────────────┼─────────────┐
             │                 ▼             ▼             ▼
             │              tools          models        target
             │            nmap/etc.      local/API     authorized
             │
             └────────────── IPC/API (localhost:42424) ────────►
```

### 1.1. The Cockpit (Windows Desktop)
The user-facing workstation interface. It hosts the workspace explorer, interactive world model visualizer, real-time research canvas, research-aware terminal, evidence inspector, and command palette. It communicates with the kernel exclusively over local loopback IPC (`127.0.0.1:42424`) using REST and Server-Sent Events (SSE).

### 1.2. The Kernel (DOGE Go Core)
The deterministic scientific discovery engine. Implemented in Go, it maintains the Unified World Model Graph ($W_t$), runs Minimum Description Length (MDL) anomaly detection, synthesizes Pareto-optimal research strategies, executes Structural Causal Model (SCM) interventions, proves hypotheses via CEGAR separating predicates, and seals tamper-evident cryptographic proof bundles.

### 1.3. The Laboratory (WSL2 Linux)
The managed execution substrate. Hosts the offensive security toolchain (`nmap`, `httpx`, `ffuf`, `nuclei`, `sqlmap`, `amass`, etc.) and provides an isolated Linux environment (e.g. `kali-linux` or a managed, reproducible `doge-lab` distro). The cockpit never interacts directly with WSL bash; all execution flows through `internal/runtime`.

### 1.4. The Subject (Authorized Target)
The system under research. This encompasses external web APIs, networked services, microservices, cloud infrastructure, and whitebox AST source repositories within authorized boundaries.

---

## 2. Core Separation of Concerns: `internal/runtime` & `internal/platform`

To ensure DOGE remains portable and decoupled from operating system quirks, execution is bifurcated into two foundational layers:

```
internal/runtime/
├── runtime.go       # Master facade: Start, Execute, Stream, Pause, Resume, Stop
├── wsl.go           # WSL2 lifecycle, path conversions (C:\ <-> /mnt/c), batch tool probing
├── environment.go   # Toolchain status, OS detection, Go engine verification
├── workspace.go     # .doge/ directory layout, workspace.toml, policy.toml persistence
├── process.go       # Synchronous & real-time streaming process execution
├── resources.go     # Request budgeting, rate limiting, concurrent process caps
├── lifecycle.go     # State machine: UNINITIALIZED -> READY -> RESEARCHING <-> PAUSED -> STOPPED
├── events.go        # EventBroadcaster pub/sub bus for desktop UI telemetry
└── ipc.go           # Local HTTP REST & Server-Sent Events (SSE) server
```

### Clean Facade Seam
The desktop cockpit interacts with DOGE solely via clean, abstract runtime interfaces:
```go
rt := runtime.NewRuntime(cfg)
rt.Start(ctx)
rt.Execute(ctx, req)
rt.Stream(ctx, req, stdoutCallback, stderrCallback)
rt.StartResearch()
rt.Pause()
rt.Resume()
rt.Stop()
```

---

## 3. The 10 Major Workstation Surfaces

The DOGE desktop navigation organizes the research lifecycle into 10 dedicated surfaces:

| Icon | Surface | Primary Responsibility |
|---|---|---|
| 🧭 | **Mission** | Active research contract, objectives, autonomy slider, live execution controls |
| 🌐 | **Surface** | Discovered hosts, services, open ports, endpoints, parameters, technologies, AST routes |
| 🧠 | **Research** | Active research frontier ($F_t$), hypothesis version space, unknowns, strategies |
| 🕸 | **World Model** | Interactive 2D/3D directed graph of states, capabilities, invariants, and causal relations |
| 🧪 | **Experiments** | Executable DSL programs, Pareto multi-objective metrics, intervention results |
| 🔬 | **Findings** | Validated security vulnerabilities, CWE/CVSS scores, causal explanations, remediation |
| 📜 | **Evidence** | Cryptographic proof chains, SHA-256 Merkle roots, HMAC attestation, replay engine |
| 📊 | **Benchmarks** | Adversarial verification suite (10 synthetic targets: BOLA, Race, Smuggling, Blind...) |
| 💻 | **Terminal** | Bidirectional research-aware terminal (WSL integration + auto-observation parsing) |
| ⚙ | **Environment** | Managed WSL health, installed toolchain, resource monitoring, AI provider settings |

---

## 4. The Two Workstation Personalities

DOGE supports two distinct cognitive modes, switchable via a header toggle `[ OPERATOR ] [ SCIENTIST ]`:

### 4.1. Operator Mode
Designed for high-tempo tactical control and direct intervention:
- Focuses on raw terminal feeds, active tool processes, targets, port tables, network logs, and captured HTTP transactions.
- Provides immediate command execution, manual probe crafting, and direct target interaction.

### 4.2. Scientist Mode
Designed for epistemic discovery and architectural analysis:
- Focuses on the Unified World Model Graph, information gain landscapes, causal DAGs, anomaly compression deficiencies, and MAP-Elites quality-diversity archives.
- Visualizes *why* the engine selected an experiment and how the research frontier is contracting.

---

## 5. Workstation Workspace Architecture (`.doge/`)

Every project directory represents a self-contained, version-controllable security laboratory:

```text
.doge/
├── workspace.toml          # Project metadata, targets, active mission, environment mode
├── policy.toml             # Mission contract: risk ceiling, request budget, approval rules
├── targets/                # Target schemas, OpenAPI specs, whitebox source mirrors
├── world/
│   ├── graph.db            # SQLite persistence for Unified World Model W_t
│   ├── observations/       # Structured raw observations from tools and probes
│   └── concepts/           # Promoted ontological concepts (rho operator outputs)
├── research/
│   ├── hypotheses/         # Epistemic hypotheses with confidence intervals [c_min, c_max]
│   ├── experiments/        # Generated Strategy DSL programs and execution records
│   └── strategies/         # Pareto-optimal synthesized research procedures
├── evidence/               # Captured HTTP request/response payloads and artifacts
├── sessions/               # Replayable research session checkpoints
├── reports/                # Generated Markdown, JSON, and OASIS SARIF v2.1.0 advisories
├── benchmarks/             # Ground-truth scenario configs and evaluation scorecards
├── tools/                  # Custom scripts, wordlists, and laboratory extensions
└── logs/                   # Temporal execution traces and stderr/stdout logs
```

---

## 6. Continuous Autonomous Research Loop

The primary operational action is **START RESEARCH**. The engine executes the autonomous discovery loop:

```text
                ┌───────────────────────────────────────┐
                │          OBSERVE AUTHORIZED           │
                │    Tactical Sandbox / Probe / Tool    │
                └───────────────────┬───────────────────┘
                                    │
                                    ▼
                ┌───────────────────────────────────────┐
                │         UPDATE WORLD MODEL            │
                │        W_t = (V_t, E_t, tau)          │
                └───────────────────┬───────────────────┘
                                    │
                                    ▼
                ┌───────────────────────────────────────┐
                │        MDL ANOMALY SCANNING           │
                │       L(o | ∅) vs L(o | K_t)          │
                └───────────────────┬───────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
            [Anomaly Exceeds]               [Explained]
                    │                               │
                    ▼                               │
        ┌──────────────────────┐                    │
        │  rho-CONCEPT GROWTH  │                    │
        │ Provisional Concepts │                    │
        └───────────┬──────────┘                    │
                    │                               │
                    ▼                               ▼
        ┌───────────────────────────────────────────────┐
        │          EVALUATE RESEARCH FRONTIER           │
        │  F_t = { v : conf(v) < c_min v anom(v) > a }  │
        └───────────────────┬───────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────────┐
        │         PARETO STRATEGY SYNTHESIS             │
        │  Max Info Gain, Novelty | Min Cost, Risk      │
        └───────────────────┬───────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────────┐
        │           MISSION CONTRACT / SCOPE            │
        │    Structural TypeCheck & Safety Gateway      │
        └───────────────────┬───────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────────┐
        │             EXECUTE IN WSL LAB                │
        │   Process Stream -> Ingestion -> Evidence     │
        └───────────────────┬───────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────────┐
        │         CEGAR FALSIFICATION & PROOF           │
        │   Falsify -> Narrow | Support -> Prove        │
        └───────────────────┬───────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────────────┐
        │          MAP-ELITES CREDIT ASSIGNMENT         │
        │ Reinforce Primitives -> Decay Stale Confidence│
        └───────────────────────────────────────────────┘
```

---

## 7. Bidirectional Research-Aware Terminal

The terminal is not a detached console. It is tightly coupled to the World Model:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ TERMINAL / EVENT STREAM                                    WSL2 [Kali] │
├────────────────────────────────────────────────────────────────────────┤
│ $ nmap -sV -p 80,443,8080 target.corp                                  │
│                                                                        │
│ Starting Nmap 7.94 ( https://nmap.org )                                │
│ Nmap scan report for target.corp (10.0.4.12)                           │
│ PORT     STATE SERVICE  VERSION                                        │
│ 80/tcp   open  http     nginx 1.24.0                                   │
│ 443/tcp  open  ssl/http nginx 1.24.0                                   │
│ 8080/tcp open  http-proxy                                              │
│                                                                        │
│ ◈ [DOGE RUNTIME] Output intercepted (Nmap Parser v1.2)                 │
│   • Ingested 3 Service Observations                                    │
│   • Registered 1 Host Entity, 3 Port Entities                          │
│   • Discovered Technology: nginx 1.24.0                                │
│   • Expanded Research Frontier: 8080/tcp unexpected proxy boundary     │
│   • Spawning Hypothesis H-104 (Reverse Proxy Request Desync)           │
└────────────────────────────────────────────────────────────────────────┘
```

1. **User manual execution**: Commands typed in the terminal execute in WSL; output is parsed in real time by `internal/parser/` (20+ tools) into structured observations and entities without manual import.
2. **Autonomous execution**: When DOGE executes an authorized experiment, the commands, telemetry, and evidence stream into the same shared log with provenance tags.

---

## 8. Cryptographic Proof & Replay Architecture

Every security finding in DOGE is backed by a **mathematical proof bundle**, guaranteeing zero false positives:

```text
FINDING DOGE-2026-0017: BOLA Horizontal Privilege Escalation
Endpoint: /api/v1/orders/8821
Severity: HIGH | CVSS: 8.6 | Confidence: 0.98

REPLAY PROOF CHAIN
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ Step 0: Auth    │──────▶│ Step 1: Probe   │──────▶│ Step 2: Impact  │
│ GET /api/v1/auth│       │ GET /orders/8820│       │ GET /orders/8821│
│ Status: 200 OK  │       │ Status: 200 OK  │       │ Status: 200 OK  │
│ Hash: 8f4a...   │       │ Hash: 1b2c...   │       │ Hash: d9e0...   │
└─────────────────┘       └─────────────────┘       └─────────────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   ▼
                   SHA-256 Chained Hash Ledger
                   H_i = SHA256(H_{i-1} || StepHash_i)
                                   ▼
                        Binary Merkle Tree Root
                   Root: 7a9e4f2c0182b881ef...
                                   ▼
                   HMAC-SHA256 Cryptographic Seal
                   Attestation: Engine v7.0.0-enterprise
```

### Deterministic Replay Capabilities
From the Evidence surface, any finding or experiment can be:
- **Replayed**: The engine re-executes the exact HTTP transactions to verify whether the vulnerability remains unpatched.
- **Forked**: Clones the session state to test alternative exploit hypotheses.
- **Compared**: Generates differential diffs between target versions.
- **Exported**: Emits OASIS SARIF v2.1.0 or signed executive Markdown advisories.

---

## 9. Mission Contract & Autonomy Governance

Autonomy is strictly bounded by the user-defined **Mission Contract**:

```text
AUTONOMY LEVEL SLIDER: [ 1 ── 2 ── 3 ──●── 5 ] (Level 4 Selected)

Level 1: Passive Observation Only (Parses manual terminal commands)
Level 2: Epistemic Assistant (Proposes hypotheses & experiments; no execution)
Level 3: Low-Risk Probing (Executes non-state-changing read-only probes)
Level 4: Continuous Authorized Research (Executes within strict policy budget)
Level 5: Full Mission Autonomy (Autonomous exploitation & validation chains)

MISSION CONTRACT CONTROLS:
• Target Whitelist:      https://authorized.example, api.authorized.example
• Request Budget:        12,483 / 20,000 requests remaining
• Rate Ceiling:          25 requests / second
• Risk Score Ceiling:    0.60 (Conservative)
• State-Changing Ops:    REQUIRES HUMAN APPROVAL
• Prohibited CWEs:       CWE-78 (Command Injection on Production)
```

---

## 10. AI Model Agnosticism & Authority Boundary

DOGE operates on a strict **zero-authority AI philosophy**:

```text
AI Provider Proposal ──▶ [ Structural DSL TypeChecker ] ──▶ Authorized?
                                                               │
                                         ┌─────────────────────┴─────────────┐
                                         ▼                                   ▼
                                      [YES]                                [NO]
                                        │                                    │
                                 Execute in WSL Lab                  Structurally Rejected
                                        │
                                        ▼
                             [ Independent Verifier ]
                             Deterministic Evidence Check
```

### Supported Providers (`pkg/ai`)
1. **Algorithmic Core (Default)**: Pure deterministic heuristics, statistical priors, Shannon entropy, and graph algorithms. Zero external API dependencies; runs 100% offline.
2. **Local Ollama / vLLM**: Communicates with local host models (`llama3`, `mistral`, `deepseek`) via local HTTP APIs.
3. **OpenRouter / OpenAI-Compatible**: Configurable cloud endpoints for advanced reasoning tasks.

### Permitted vs. Prohibited Delegations
- **Permitted**: Natural language explanations, hypothesis formulation seeds, concept labeling/naming, documentation digestion.
- **Prohibited**: Scope verification, network authorization, validation truth, finding certification.

---

## 11. Implementation Phasing & Engineering Roadmap

```text
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   PHASE A    │────▶│   PHASE B    │────▶│   PHASE C    │
│ internal/    │     │ Desktop      │     │ Research     │
│ runtime/     │     │ Wails Shell  │     │ State API    │
└──────────────┘     └──────────────┘     └──────────────┘
       │                                         │
       ▼                                         ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   PHASE D    │────▶│   PHASE E    │────▶│   PHASE F    │
│ Research     │     │ Research     │     │ Autonomous   │
│ Visual Canvas│     │ Terminal     │     │ Mode UI      │
└──────────────┘     └──────────────┘     └──────────────┘
       │                                         │
       ▼                                         ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   PHASE G    │────▶│   PHASE H    │────▶│   PHASE I    │
│ Model Router │     │ Disposable   │     │ Desktop      │
│ Cockpit      │     │ WSL Lab      │     │ Polish       │
└──────────────┘     └──────────────┘     └──────────────┘
```

* **Phase A (Completed — commit `7a7e99a`)**: Built `internal/runtime/` (WSL manager, process streaming, workspace layout, resource governor, lifecycle machine, event broadcaster, local IPC server).
* **Phase B (Next)**: Initialize Wails desktop application (`cmd/desktop/`), window management, workspace switcher, and basic cockpit layout.
* **Phase C**: Connect local IPC API to frontend state store via Server-Sent Events (SSE).
* **Phase D**: Build Research Canvas, World Model Graph visualizer, and Evidence Inspector.
* **Phase E**: Connect embedded xterm.js terminal to `internal/runtime/process.go` streaming and `internal/parser/` observation ingestion.
* **Phase F**: Build Mission Builder, Autonomy Slider, and Autonomy Console.
* **Phase G**: Build AI Provider settings cockpit.
* **Phase H**: Implement disposable/reproducible WSL lab distribution management.
* **Phase I**: Ergonomics, command palette (`Ctrl+Shift+P`), keyboard shortcuts, dark/light themes, and export utilities.
