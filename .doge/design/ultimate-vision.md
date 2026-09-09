# DOGE Ultimate Vision

## Identity

**DOGE: A lightweight, autonomous, continuously operating cybersecurity research system.**

DOGE is not a scanner. DOGE is not a tool orchestrator. DOGE is not "an LLM with security tools."

DOGE is a **research system** that can learn how to research security.

## The Fundamental Difference

| Category | Behavior |
|---|---|
| **Tool** | Knows techniques |
| **Agent** | Executes techniques |
| **Researcher** | Chooses techniques |
| **Research System** | Learns which questions to ask next |

DOGE's objective is to become the fourth category.

## Core Capability

> Enter an authorized environment with incomplete knowledge, continuously reduce uncertainty, discover unexpected behavior, form novel security hypotheses, construct attack paths, prove real impact, learn from failure, and continue investigation without needing a human to prescribe the next move.

## Operating Principle

> **DOGE must never optimize for finding vulnerabilities that its designers already know exist. It must optimize for reducing uncertainty about the target.**

## Optimization Target

> **Maximum security knowledge discovered per unit of cost and risk.**

The ideal DOGE is not the system that attacks the most. It is the system that **learns the most from the fewest intelligent experiments.**

## Operating Modes

| Mode | Duration | Description |
|---|---|---|
| `doge hunt` | 1 hour - continuous | Autonomous research against authorized target |
| `doge research` | Session | Human-directed collaborative research |
| `doge monitor` | Continuous | Detect changes, generate new research |
| `doge benchmark` | Test cycle | Evaluate DOGE against synthetic challenges |

## Input Model

The human provides:
```
authorization
scope
objective
constraints
credentials/context
optional priorities
```

DOGE performs the research.

## Architecture Layers

```
┌─────────────────────────┐
│      RESEARCH           │  Strategy, planning, long-term memory
│      DIRECTOR           │
├─────────────────────────┤
│   WORLD MODEL           │  Everything DOGE knows/believes/suspects
│   + UNKNOWN SPACE       │  about the target
├─────────────────────────┤
│   HYPOTHESIS ENGINE     │  Competing explanations of observations
│   + SECURITY PROPERTIES │  Property-based reasoning
├─────────────────────────┤
│   RESEARCH ORCHESTRATOR │  Mission creation, researcher dispatch,
│   + MISSION SYSTEM      │  debriefing, state updates
├─────────────────────────┤
│   SPECIALIZED           │  Short-lived focused researchers
│   RESEARCHERS           │  (Recon, Auth, Logic, Browser, Exploit...)
├─────────────────────────┤
│   EXPERIMENT ENGINE     │  Design, execute, capture evidence
│   + EVIDENCE SYSTEM     │
├─────────────────────────┤
│   ATTACK GRAPH          │  Chain discovery, impact propagation,
│   + EXPLOIT ENGINE      │  PoC development
├─────────────────────────┤
│   VALIDATION ENGINE     │  Independent reproduction
│   + IMPACT RESEARCH     │  Safe impact demonstration
├─────────────────────────┤
│   LEARNING SYSTEM       │  Target-specific, cross-session learning
│   + SELF-IMPROVEMENT    │  Research policy optimization
├─────────────────────────┤
│   SAFETY ARCHITECTURE   │  Scope, policy, budget, gates,
│                         │  rate limits, emergency stop
├─────────────────────────┤
│   MODEL ROUTER          │  Multi-provider, role-based routing
│                         │  (Claude, GPT, Ollama, deterministic)
├─────────────────────────┤
│   BENCHMARK LAB         │  Synthetic generation, trajectory
│                         │  analysis, regression, curriculum
└─────────────────────────┘
```

## Model Relationship

```
┌────────────────────┐
│ DOGE               │
│ Research Platform   │  ← The intelligence infrastructure
└─────────┬──────────┘     DOGE owns this. Not replaceable.
          │
    Model Router
          │
  ┌───────┼───────┐
  ↓       ↓       ↓
Claude  GPT/etc  Local    ← Replaceable reasoning providers
  │       │       │
  └───────┼───────┘
          ↓
  Research result
```

The model is replaceable. DOGE's world model, evidence, attack graph, learning, policy, missions, and validation infrastructure are **not**.

## What DOGE Is NOT

- NOT a wrapper around an LLM
- NOT a vulnerability scanner with AI
- NOT a hardcoded tool pipeline (subfinder → httpx → ...)
- NOT a system that only finds vulnerabilities it was programmed to look for
- NOT a system that requires humans to prescribe every step
- NOT a system that optimizes for number of requests/scans/agents

## What DOGE IS

- A **research system** that learns which questions to ask
- A **world modeler** that tracks what it knows, doesn't know, believes, and cannot explain
- A **hypothesis engine** that generates competing explanations
- A **experiment designer** that maximizes information gain
- A **evidence collector** that proves claims with objective evidence
- A **chain discoverer** that connects individually weak signals
- A **learning system** that improves from every engagement
- A **benchmark laboratory** that measures research capability scientifically
