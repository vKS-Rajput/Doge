# 🐕 DOGE — AI Security Research Workspace

A persistent research copilot that automatically captures, organizes, and analyzes everything you do during a security engagement. You run the tools. DOGE remembers everything, builds the knowledge graph, tracks coverage, identifies gaps, learns research patterns, and tells you where to look next.

## How It Works

```
YOU                                    DOGE
 │                                      │
 │  run nmap, httpx, curl, ffuf...      │
 │──────────────────────────────────────►│
 │                                      │  auto-capture command + output
 │  see normal output                   │  auto-detect new files
 │◄─────────────────────────────────────│  auto-parse supported formats
 │                                      │  update knowledge graph
 │  keep working                        │  update coverage + gaps
 │──────────────────────────────────────►│  learn research patterns
 │                                      │  recommend next investigation
 │  glance at monitor                   │
 │◄─────────────────────────────────────│
 │                                      │
 │  "where should I look next?"         │
 │◄─────────────────────────────────────│  /api/export?id= — authorization
 │                                      │  incomplete (HIGH)
```

## Quick Start

```bash
# Build
go build -o doge ./cmd/workspace

# Create investigation workspace
mkdir -p ~/investigations/target-name
cd ~/investigations/target-name

# Start research shell (Terminal 1)
doge work --target example.com --env authorized

# Open live dashboard (Terminal 2)
doge monitor
```

Then work normally inside the DOGE shell:

```
DOGE:example.com $ nmap -sCV example.com -oX scan.xml
  ✓ nmap recorded → 17 observations | 1 new files

DOGE:example.com $ httpx -l hosts.txt -json -o http.json
  ✓ httpx recorded → 87 observations | 1 new files

DOGE:example.com $ curl https://example.com/api/profile
  ✓ curl recorded

DOGE:example.com $ note "admin account has access to /export"
  📝 Note recorded
```

DOGE handles everything else automatically.

## Three Primary Commands

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `doge work` | Research shell — work normally, DOGE captures everything | Terminal 1: your workbench |
| `doge monitor` | Live dashboard: activity, coverage, gaps, patterns, approvals | Terminal 2: your control tower |
| `doge notebook` | Complete investigation state: history, evidence, coverage | On-demand: your research record |

## What DOGE Does Automatically

After every command you run:

- ✓ **Captures** command, stdout, stderr, exit code, duration
- ✓ **Detects** new and modified files in the workspace
- ✓ **Stores** artifacts in a content-addressable store
- ✓ **Parses** supported formats (nmap XML, httpx JSON, nuclei JSONL, etc.)
- ✓ **Creates** observations from structured output
- ✓ **Updates** the knowledge graph (entities, relationships)
- ✓ **Recalculates** coverage across 8 investigation categories
- ✓ **Identifies** investigation gaps (untested, partial, stale, contradictory)
- ✓ **Learns** research patterns from accumulated evidence
- ✓ **Recommends** what to investigate next

## What DOGE Never Does

- ❌ Executes security tools autonomously
- ❌ Sends requests to targets
- ❌ Fabricates findings or evidence
- ❌ Converts hypotheses into facts
- ❌ Bypasses human approval for epistemic decisions
- ❌ Modifies your commands or tool arguments

## Operating Modes

| Mode | Flag | Behavior |
|------|------|----------|
| **Research** | `--mode research` (default for `authorized`) | You run tools. DOGE observes, analyzes, recommends. |
| **Hunt** | `--mode hunt` (default for `htb`/`lab`) | Autonomous scheduler executes tools. Still requires human approval for findings. |

## Supported Parsers

| Tool | Output Format | Parser |
|------|--------------|--------|
| nmap | XML (`-oX`) | ✓ |
| httpx | JSON/JSONL (`-json`) | ✓ |
| nuclei | JSONL (`-o`) | ✓ |
| ffuf | JSON (`-o`) | ✓ |
| katana | JSONL (`-o`) | ✓ |
| subfinder | JSON/JSONL | ✓ |
| dnsx | JSON/JSONL | ✓ |
| Unknown | Raw capture | ✓ (preserved, not parsed) |

## Architecture

```
cmd/workspace/           CLI commands (work, monitor, notebook, etc.)
internal/
├── runner/              Command execution + auto-capture
├── learning/            Adaptive Evidence-Based Research Memory
├── journal/             Command execution history
├── coverage/            Evidence-derived investigation coverage
├── app/                 Application service layer
├── db/                  SQLite + migrations
├── parser/              Tool-specific output parsers
│   ├── nmap/
│   ├── httpx/
│   ├── nuclei/
│   ├── ffuf/
│   ├── katana/
│   ├── subfinder/
│   └── dnsx/
├── observation/         Observation validation + persistence
├── entity/              Knowledge graph entities
├── correlation/         Entity relationship detection
├── surface/             Attack surface tracking
├── novelty/             Change detection
├── opportunity/         Research opportunity ranking
├── brain/               AI reasoning (optional)
├── finding/             Validated security findings
├── session/             Session state management
├── watcher/             Filesystem change detection
├── watch/               Watch orchestrator
├── tui/                 Terminal UI (Bubble Tea)
├── timeline/            Temporal event tracking
├── search/              Evidence search
├── insight/             Pattern detection
├── validation/          Evidence validation
├── verification/        Finding verification
├── reasoning/           AI reasoning framework
├── config/              Configuration management
├── bus/                 Event bus
├── cache/               Query cache
└── logging/             Structured logging + credential redaction
pkg/
├── domain/              Core types (Observation, Entity, Evidence, etc.)
├── events/              Event type definitions
└── errors/              Shared error types
```

## Core Principles

1. **Observations are immutable** — parsed data is never modified or deleted
2. **Evidence is traceable** — every claim links to specific artifacts
3. **Learning is advisory** — patterns improve recommendations, never become facts
4. **Human authority** — you execute, DOGE observes
5. **Persistence** — everything survives restart

## Building

```bash
# Prerequisites: Go 1.26.6+
go build -o doge ./cmd/workspace

# Run tests
go test ./...

# Run with race detector
go test -race ./...

# Install (Linux/WSL)
go build -o /tmp/doge ./cmd/workspace && sudo cp /tmp/doge /usr/local/bin/doge
```

## All Commands

### Primary
| Command | Description |
|---------|-------------|
| `doge work` | Research shell with auto-capture |
| `doge monitor` | Unified live dashboard |
| `doge notebook` | Investigation browser |

### Secondary
| Command | Description |
|---------|-------------|
| `doge ingest <file>` | Manually import a file |
| `doge note "<text>"` | Add a researcher note |
| `doge journal` | View command history |
| `doge coverage` | View coverage bars |
| `doge gaps` | View investigation gaps |
| `doge search <query>` | Search evidence |
| `doge timeline` | View event timeline |
| `doge approvals` | Manage pending approvals |

### Workspace
| Command | Description |
|---------|-------------|
| `doge init` | Initialize a workspace |
| `doge start` | Start the investigation engine |
| `doge status` | Show workspace status |
| `doge runtime` | Show session state |
| `doge version` | Print version |

## CI/CD

[![DOGE CI](https://github.com/vKS-Rajput/Doge/actions/workflows/ci.yml/badge.svg)](https://github.com/vKS-Rajput/Doge/actions/workflows/ci.yml)

Every push and PR triggers a 6-stage pipeline:

| Stage | What It Does |
|-------|-------------|
| **Vet + Build** | Compile check, `go vet`, dependency tidiness |
| **Tests** | Full test suite on Linux + Windows |
| **Race Detection** | Tests with `-race` flag + coverage report |
| **Security** | `govulncheck` for known Go vulnerabilities |
| **Integration** | Workspace lifecycle, runner pipeline, learning replay |
| **Release Builds** | Cross-platform binaries (linux/windows/darwin × amd64/arm64) |

Dependabot keeps Go modules and Actions up to date weekly.

## Safety Model

```
Observation → Evidence → Analysis → Recommendation
                                         │
                                    HUMAN DECISION
                                         │
                              Hypothesis → Approval → Validation
                                                          │
                                                     HUMAN CONFIRM
                                                          │
                                                       Finding
```

Every epistemic transition requires explicit human approval:
- AI hypothesis → human approves → validation runs
- Candidate finding → human confirms → confirmed finding

The learning system can change **ranking and context**, never **scope, authorization, or safety constraints**.

## License

TBD
