# DOGE Startup Guide

Step-by-step guide to setting up and running your first DOGE investigation.

---

## Prerequisites

- **Go 1.22+** installed
- **Linux/WSL** recommended (DOGE shells commands through `bash`)
- A target you are **explicitly authorized** to test

---

## 1. Build DOGE

```bash
cd /path/to/doge

# Build
go build -o doge ./cmd/workspace

# Install globally (optional)
sudo cp doge /usr/local/bin/doge

# Verify
doge version
```

---

## 2. Create an Investigation Workspace

Each investigation gets its own directory. DOGE stores all artifacts, observations, coverage, and learned patterns inside a `.doge/` subdirectory.

```bash
mkdir -p ~/investigations/my-target
cd ~/investigations/my-target
```

---

## 3. Start the Research Shell

```bash
doge work --target my-target.com --env authorized
```

You'll see:

```
🐕 DOGE Research Workspace
────────────────────────────────────
  Target: my-target.com
  Scope:  authorized
  Mode:   RESEARCH
  Path:   /home/user/investigations/my-target
────────────────────────────────────

DOGE:my-target.com $
```

This is your research workbench. Everything you type here is automatically captured.

### Environment Options

| Flag | When to Use |
|------|------------|
| `--env authorized` | Real bug-bounty / authorized assessment |
| `--env htb` | HackTheBox machines |
| `--env lab` | Personal lab environments |

---

## 4. Run Tools Normally

Just type commands as you normally would:

```bash
DOGE:my-target.com $ nmap -sCV my-target.com -oX scan.xml
```

After the command finishes, DOGE reports:

```
  ✓ nmap recorded → 17 observations | 1 new files
```

Continue with more tools:

```bash
DOGE:my-target.com $ httpx -l hosts.txt -json -o http.json
  ✓ httpx recorded → 87 observations | 1 new files

DOGE:my-target.com $ curl https://my-target.com/api/profile
  ✓ curl recorded

DOGE:my-target.com $ ffuf -u https://my-target.com/FUZZ -w wordlist.txt -o fuzz.json
  ✓ ffuf recorded → 42 observations | 1 new files
```

**You never need to type `doge ingest` or `doge coverage` between commands.**

### Built-in Shell Commands

| Command | What It Does |
|---------|-------------|
| `note <text>` | Record a researcher observation |
| `status` | Show investigation summary |
| `coverage` | Show coverage progress bars |
| `gaps` | Show investigation gaps |
| `journal` | Show recent command history |
| `patterns` | Show learned research patterns |
| `help` | List all built-in commands |
| `exit` | Leave the shell |

---

## 5. Open the Monitor (Second Terminal)

Open another terminal:

```bash
cd ~/investigations/my-target
doge monitor
```

The monitor auto-refreshes every 3 seconds and shows:

```
🐕 DOGE MONITOR
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGET
  my-target.com
  Scope: AUTHORIZED
  Mode:  RESEARCH
  Session: ACTIVE

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LIVE ACTIVITY
  10:31:42  ✓ nmap -sCV my-target.com → 17 obs
  10:33:10  ✓ httpx -l hosts.txt → 87 obs
  10:35:02  ✓ curl /api/profile

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COVERAGE
  Discovery        ██████████████░ 100%
  Web Mapping      ████████████░░░  82%
  Authentication   █████████░░░░░░  61%
  Authorization    █████░░░░░░░░░░  34%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔥 INVESTIGATE NEXT
  #1  Authorization (34%) 🟡 HIGH

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧠 RESEARCH MEMORY
  Patterns: 3 | Outcomes: 0 | Events: 5
```

**Leave this open while you work. No other terminals needed.**

---

## 6. View the Complete Investigation

Whenever you want the full picture:

```bash
doge notebook
```

This prints the complete investigation state: session summary, command history, discovered entities, coverage, gaps, researcher notes, learned patterns, and unexplored areas.

---

## 7. Resume After Restart

Everything is persisted automatically. If your terminal closes or DOGE crashes:

```bash
cd ~/investigations/my-target
doge work
```

DOGE detects the existing investigation and resumes it. Your command history, artifacts, observations, coverage, gaps, and learned patterns all survive.

---

## How Auto-Capture Works

```
You type a command
       │
       ▼
DOGE executes it through bash
       │
       ├── stdout → tee'd to you + captured
       ├── stderr → tee'd to you + captured
       ├── exit code → recorded
       ├── duration → recorded
       │
       ▼
DOGE snapshots workspace files (before → after)
       │
       ├── new files → auto-imported as artifacts
       ├── modified files → auto-imported
       │
       ▼
DOGE identifies the tool (nmap? httpx? curl?)
       │
       ▼
Supported format? → parser → observations → knowledge graph
Unknown format?   → preserved as raw artifact
       │
       ▼
Coverage recalculated
Gaps updated
Learning engine fed
Monitor reflects changes
```

### What Gets Captured

| Source | What DOGE Captures |
|--------|-------------------|
| Command | Full command line, arguments, working directory |
| Timing | Start time, end time, duration |
| Output | stdout, stderr, exit code |
| Files | New files, modified files (within workspace) |
| Parsed | Observations from supported tool formats |

### Safety Limits

| Limit | Value |
|-------|-------|
| Max file size | 50 MB |
| Directory depth | 3 levels |
| Excluded dirs | `.doge/`, `.git/`, `node_modules/`, hidden dirs |

---

## Researcher Notes

Record observations that DOGE can't derive from tool output:

```bash
# Inside doge work:
note "admin account has access to export endpoint"
note "OAuth uses email+OTP, no password"
note "test account A belongs to tenant 123"
```

Or from any terminal:

```bash
doge note "upload accepts multipart/form-data only"
```

Notes become first-class observations in the knowledge graph.

---

## Understanding Coverage

Coverage is **evidence-derived**, not guessed. DOGE calculates scores from actual observations:

| Category | What Counts |
|----------|-------------|
| Discovery | Hosts, subdomains, IPs found |
| Services | Port/service enumeration |
| Web Mapping | HTTP endpoints, URLs |
| Endpoints | Endpoint discovery depth |
| Parameters | Parameter identification |
| Authentication | Auth flow observations |
| Authorization | Access control testing |
| Input Handling | File upload, form testing |

A category is only "tested" when observations exist for it.

---

## Understanding the Learning System

DOGE learns recurring patterns from your evidence:

```
Pattern: endpoint_with_object_id
Description: Resource endpoint with numeric ID parameter
Confidence: 72%
Occurrences: 7
Effect: +12% priority boost for similar endpoints
```

### What Learning CAN Change
- Research priority ranking
- Investigation recommendations
- Context supplied to gap analysis

### What Learning CANNOT Change
- Immutable observations
- Target scope
- Authorization policy
- Safety constraints
- Human approval requirements

---

## Troubleshooting

### "No active session"

You need to start DOGE first:

```bash
doge work --target example.com --env authorized
```

### "Failed to open workspace"

Make sure you're in the investigation directory:

```bash
cd ~/investigations/my-target
doge work
```

### Monitor shows no activity

Make sure you're running commands inside `doge work`, not in a separate terminal. Commands in separate terminals aren't auto-captured (use `doge ingest` to manually import their output).

### Tool output not parsed

DOGE only parses supported formats. If your tool produces custom output:
1. Save it to a file in the workspace — it will be captured as a raw artifact
2. Use `doge ingest <file> --tool <name>` for manual import

---

## File Layout

After running a few commands, your workspace looks like:

```
~/investigations/my-target/
├── .doge/
│   ├── workspace.db        # SQLite database (observations, entities, etc.)
│   ├── state.json          # Session state (target, mode, phase)
│   ├── artifacts/          # Content-addressable artifact store
│   └── captured/           # Auto-captured stdout
├── scan.xml                # Your nmap output
├── http.json               # Your httpx output
├── fuzz.json               # Your ffuf output
└── ...                     # Your other files
```

---

## What's Next

Once your investigation is running:

1. **Keep working** — DOGE captures everything automatically
2. **Glance at monitor** — see coverage and gaps change in real-time
3. **Follow DOGE's suggestions** — investigate areas with low coverage
4. **Record manual observations** — use `note` for things DOGE can't see
5. **Review with notebook** — get the complete investigation state anytime
