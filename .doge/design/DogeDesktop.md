Absolutely. The screenshot gives the **visual direction**, but I would not tell the coding AI to merely reproduce that dashboard. That would produce a polished scanner UI, not DOGE.

The prompt below tells the AI to treat the screenshot as the **visual seed**, while treating DOGE's existing Go architecture, runtime, research engine, WSL laboratory, world model, evidence system, and autonomous research concepts as the actual product foundation.

I would give this to a strong coding agent as the **master implementation prompt**.

---

# MASTER PROMPT: DOGE DESKTOP

```text
# DOGE DESKTOP
## Autonomous Security Research Operating Environment
### Master Product + Architecture + Implementation Mission

You are the principal architect, senior desktop engineer, systems engineer,
security-research engineer, UX engineer, and product designer responsible for
transforming the existing DOGE codebase into a complete native Windows
desktop application.

This is NOT a request to build a dashboard.

This is NOT a request to wrap the existing CLI in buttons.

This is NOT a request to create a browser application.

This is NOT a request to make another generic AI pentesting interface.

You are building DOGE as a complete desktop operating environment for
authorized security research.

The final product should feel like an application category that does not
currently exist:

    "Security Research Operating Environment"

Think about the interaction quality of:

    VS Code
    Antigravity
    modern IDEs
    professional security tooling
    terminal environments
    research notebooks
    graph-analysis systems

but DO NOT copy their architecture.

DOGE must have its own identity.

The core idea is:

    Target
      ↓
    Observation
      ↓
    World Model
      ↓
    Uncertainty
      ↓
    Research Frontier
      ↓
    Hypothesis
      ↓
    Experiment
      ↓
    Authorized Execution
      ↓
    Evidence
      ↓
    Independent Validation
      ↓
    Finding / Knowledge
      ↓
    Learning
      ↓
    New Research Frontier
      ↓
    repeat

The desktop application is the cockpit for this system.

============================================================
# 0. ABSOLUTE ENGINEERING RULES
============================================================

1. FIRST inspect the existing repository completely.

Do not assume the architecture.

Read the existing implementation.

Understand:

    internal/
    cmd/
    pkg/
    world model
    research engine
    strategy system
    validation
    verification
    persistence
    session system
    evidence
    runtime
    WSL integration
    AI/model routing
    CLI
    tests

The existing implementation is authoritative.

Do not replace working systems merely because you would personally design
them differently.

Reuse existing functionality wherever possible.

2. NEVER create fake functionality.

Do not create UI buttons that pretend to work.

Every important visible operation must connect to real DOGE functionality.

If something is not implemented yet:

    either implement it properly
    or expose it honestly as unavailable/planned.

Never use fake findings, fake scan results, fake CPU values, fake WSL status,
fake graphs, fake AI responses, or fake autonomous activity in production.

Mock data is acceptable ONLY inside explicit demo/test fixtures.

3. Preserve DOGE Core.

The existing Go research engine is the brain/kernel.

The desktop UI is the cockpit.

Do not move the research engine into JavaScript.

Do not make JavaScript responsible for:

    authorization
    scope
    safety
    validation
    finding truth
    execution policy
    resource enforcement

The UI must never become the security authority.

4. Security boundaries are deterministic.

LLMs may propose.

LLMs may interpret.

LLMs may explain.

LLMs may generate hypotheses.

LLMs MUST NOT become the authority for:

    scope
    authorization
    execution approval
    safety
    evidence validity
    validation truth
    finding certification

5. DOGE operates ONLY against explicitly authorized targets.

The application must preserve deterministic scope and policy enforcement.

State-changing or high-risk actions require the appropriate explicit approval
mechanism.

Do not implement mechanisms intended to bypass authorization, scope,
security controls, or approval requirements.

The product is for legitimate security research, authorized testing,
security engineering, defensive research, and controlled laboratory work.

6. Offline-first is mandatory.

DOGE Desktop must function without cloud services.

The application UI must not depend on:

    CDN
    remote JavaScript
    remote CSS
    external fonts
    analytics
    cloud backend
    internet connectivity

AI is optional.

DOGE must remain functional when:

    no AI provider exists
    no internet exists
    OpenRouter is unavailable
    local models are unavailable

7. Do not turn DOGE into an Electron-style browser website.

The production application must be a real Windows desktop executable.

Use a native desktop application shell.

Preferred architecture:

    Go
      +
    Wails
      +
    embedded frontend
      +
    WebView2 rendering
      +
    DOGE Go backend
      +
    WSL2 laboratory

The frontend may use HTML/CSS/JavaScript or TypeScript internally,
but it must be packaged into the desktop executable.

Do NOT launch:

    msedge.exe --app=http://127.0.0.1:...

as the production desktop application.

The user must launch:

    DOGE.exe

and receive the DOGE desktop environment.

8. Keep a local API if useful.

The existing runtime IPC/HTTP layer may remain available for:

    CLI
    integration testing
    automation
    plugins
    diagnostics
    future integrations

But the desktop application's primary communication path should use
native Go ↔ frontend bindings/events where appropriate.

============================================================
# 1. PRODUCT VISION
============================================================

DOGE should feel like:

    "I have opened my own security research workstation."

Not:

    "I opened a pentesting dashboard."

The user should be able to open DOGE and immediately understand:

    What am I researching?
    What is DOGE doing?
    What does DOGE know?
    What does DOGE NOT know?
    What is it investigating?
    Why did it choose that experiment?
    What evidence exists?
    What findings are validated?
    What is running in WSL?
    What tools are available?
    What requires my approval?
    What has DOGE learned?

The application should make the research process visible.

DOGE should not hide intelligence behind an opaque "AI is thinking..."
indicator.

Expose research reasoning as structured state.

For example:

    Current hypothesis:
        H-184

    Evidence:
        7 observations

    Current uncertainty:
        Authorization behavior across actor states

    Candidate experiments:
        6

    Selected experiment:
        E-721

    Expected information gain:
        0.84

    Novelty:
        0.72

    Risk:
        0.14

    Reason:
        Highest-value authorized experiment on current frontier.

This is a research workstation.

============================================================
# 2. CORE ARCHITECTURE
============================================================

Build this architecture:

                         DOGE.exe
                            │
              ┌─────────────┴─────────────┐
              │                           │
        Native Desktop                DOGE Core
            Shell                         │
              │                           │
       Embedded UI                    Go Runtime
              │                           │
       ┌──────┴──────┐            ┌───────┴────────┐
       │             │            │                │
    UI State      Events      Research Engine   World Model
                                 │                │
                           ┌─────┼─────┐          │
                           │     │     │          │
                        Causal Strategy Learning  │
                           │     │     │          │
                           └─────┼─────┘          │
                                 │                │
                         Policy / Scope / Safety  │
                                 │                │
                         Validation / Evidence    │
                                 │                │
                          internal/runtime        │
                                 │
                           WSL2 Laboratory
                                 │
                  ┌──────────────┼───────────────┐
                  │              │               │
                tools          source       authorized targets

Desktop:

    internal/desktop/

Runtime:

    internal/runtime/

Core:

    existing DOGE architecture

Do not merge these layers together.

============================================================
# 3. TECHNOLOGY DIRECTION
============================================================

Preferred desktop stack:

    Wails
    Go
    embedded frontend
    WebView2

Frontend:

    TypeScript preferred if it improves maintainability,
    otherwise clean vanilla JavaScript is acceptable.

No framework should be introduced merely for fashion.

If React/Svelte/etc. materially improves the architecture, evaluate it
against the project's offline-first and packaging requirements before using it.

The final executable should be buildable as a Windows application.

Development mode may use development servers.

Production mode must package the frontend into the executable.

============================================================
# 4. VISUAL IDENTITY
============================================================

Use the supplied DOGE screenshot as VISUAL INSPIRATION.

The screenshot establishes the visual language:

    dark security workstation
    deep black/blue environment
    cyan primary interaction
    controlled violet accents
    emerald success
    amber warning
    crimson danger
    dense information architecture
    glowing but restrained borders
    graph visualization
    integrated terminal
    professional security tooling
    futuristic but usable

Do NOT blindly reproduce the screenshot.

Improve it.

The screenshot is the beginning of the visual language, not the final product.

DOGE should feel:

    premium
    technical
    serious
    fast
    dense
    intelligent
    focused
    calm under heavy information load

Avoid:

    cheesy hacker graphics
    excessive Matrix rain
    skull imagery everywhere
    meaningless neon
    giant glowing buttons
    excessive animations
    fake "AI magic"
    clutter
    generic SaaS dashboard aesthetics

The interface should look like software used by serious security researchers.

============================================================
# 5. COLOR SYSTEM
============================================================

Use semantic design tokens.

Base:

    background:
        deep obsidian / near-black blue

    surface:
        slightly lighter blue-black

    elevated surface:
        controlled glass/dark cards

Primary:

    cyan

Secondary:

    violet

Success:

    emerald

Warning:

    amber

Critical:

    crimson

Informational:

    blue/cyan

Do NOT hardcode colors throughout components.

Create:

    --color-bg
    --color-surface
    --color-surface-elevated
    --color-primary
    --color-secondary
    --color-success
    --color-warning
    --color-danger
    --color-info
    --color-border
    --color-text
    --color-text-muted

The visual system must be consistent across the entire application.

============================================================
# 6. APPLICATION WINDOW
============================================================

The main DOGE window should be approximately:

    1440–1800px wide
    900–1100px tall

but responsive.

Support:

    maximize
    minimize
    resize
    fullscreen
    compact mode

Use a real application title:

    DOGE — Security Research Workstation

Provide:

    application icon
    native menus where appropriate
    keyboard shortcuts
    system tray integration
    desktop notifications
    clean shutdown
    crash/recovery behavior

============================================================
# 7. FIRST-RUN EXPERIENCE
============================================================

When the user launches DOGE for the first time:

DO NOT dump them into a terminal.

Show:

                    DOGE

          SECURITY RESEARCH WORKSTATION

    ┌────────────────────────────────────┐
    │ Environment                         │
    │                                    │
    │ Windows       ✓                    │
    │ WSL2          ✓ / Configure        │
    │ DOGE Engine   ✓                    │
    │ Toolchain     Checking...          │
    │ Workspace     Ready                │
    └────────────────────────────────────┘

              [ Create Workspace ]

              [ Open Existing ]

              [ Environment Settings ]

Automatically detect:

    Windows
    architecture
    WSL
    available distributions
    DOGE runtime
    toolchain
    available storage
    optional local AI providers

Do not install or modify system software silently.

Any environment modification must be explicit and understandable.

============================================================
# 8. WORKSPACE MODEL
============================================================

DOGE is workspace-centric.

A workspace represents a complete research environment.

Opening a workspace restores:

    mission
    targets
    authorization policy
    world model
    hypotheses
    experiments
    strategies
    evidence
    findings
    sessions
    timeline
    notes
    terminal state where appropriate
    environment metadata
    AI provider configuration
    benchmark state

Use the existing .doge structure.

Make it visible through the application.

Workspace examples:

    Project
        Targets
        Research
        World
        Evidence
        Findings
        Sessions
        Benchmarks

Provide:

    New Workspace
    Open Workspace
    Recent Workspaces
    Close Workspace
    Recover Workspace

============================================================
# 9. MAIN NAVIGATION
============================================================

Create the following primary surfaces:

    01 Mission
    02 Surface
    03 Research
    04 World Model
    05 Experiments
    06 Findings
    07 Evidence
    08 Benchmarks
    09 Terminal
    10 Environment

Do not make all surfaces visually identical.

Each should have a purpose.

============================================================
# 10. MISSION SURFACE
============================================================

Mission is the home screen.

It answers:

    What is DOGE doing right now?

Show:

    target
    mission objective
    authorization status
    scope
    autonomy level
    elapsed time
    budget
    risk
    research progress
    current hypothesis
    current experiment
    research frontier
    recent discoveries

Primary controls:

    Start
    Pause
    Resume
    Stop
    Take Control

The Start button must NEVER bypass scope/policy checks.

============================================================
# 11. MISSION BUILDER
============================================================

Build a beautiful mission creation interface.

Fields:

    Workspace
    Target
    Authorization source
    Scope
    Objective
    Research mode
    Time budget
    Request budget
    Resource limits
    Risk ceiling
    Autonomy level
    AI provider
    Optional research priorities

Modes:

    Observe
    Recon
    Research
    Benchmark
    Monitor

Clearly distinguish:

    what DOGE can do autonomously
    what requires approval
    what is blocked

Before execution:

    show a Mission Contract.

Example:

    TARGET
        authorized.example

    SCOPE
        *.authorized.example

    METHODS
        approved methods only

    RISK
        Conservative

    BUDGET
        20,000 requests

    STATE-CHANGING ACTIONS
        Approval required

Then:

    [ START MISSION ]

============================================================
# 12. OPERATOR / SCIENTIST MODE
============================================================

Implement:

    OPERATOR
    SCIENTIST

as two interface perspectives.

OPERATOR:

    targets
    terminal
    tools
    requests
    sessions
    environment
    direct control

SCIENTIST:

    research frontier
    hypotheses
    experiments
    causal graph
    world model
    concepts
    strategy evolution
    evidence
    uncertainty
    learning

The underlying state is identical.

Only the presentation changes.

============================================================
# 13. RESEARCH SURFACE
============================================================

This is one of the most important screens.

Show:

    Research Frontier

with ranked unresolved questions.

Example:

    HIGH

    Authorization state transition
    Information leakage boundary
    Cache behavior
    Workflow transition
    Cross-context data flow

Each item should show:

    uncertainty
    expected information gain
    novelty
    security relevance
    estimated cost
    risk
    dependencies
    evidence

Clicking an item opens:

    Why is this interesting?
    What does DOGE know?
    What does DOGE not know?
    What hypotheses exist?
    What experiments are available?
    Why is this ranked here?

============================================================
# 14. HYPOTHESIS VIEW
============================================================

Every hypothesis should have a real object identity.

Example:

    H-184

    Hypothesis
        Authorization decision depends on stale state.

    Status
        Supported

    Confidence
        0.81

    Evidence
        7 observations

    Experiments
        E-420
        E-421
        E-422

    Origin
        anomaly / causal divergence

    Related concepts
        state transition
        authorization

    Provenance
        complete

Allow:

    inspect
    compare
    replay
    fork
    falsify
    promote

============================================================
# 15. EXPERIMENT VIEW
============================================================

Every experiment should be a first-class object.

Display:

    Experiment ID
    Hypothesis
    Objective
    Preconditions
    Expected information gain
    Novelty
    Cost
    Risk
    Authorization status
    Execution status
    Result
    Evidence
    World-model changes

Provide:

    [ Inspect ]
    [ Replay ]
    [ Fork ]
    [ Compare ]

The user should be able to understand why DOGE chose an experiment.

============================================================
# 16. DECISION INSPECTOR
============================================================

Create a right-side inspector.

Whenever DOGE chooses something, expose:

    DECISION

    Selected:
        E-421

    Why?

    Information gain:
        0.84

    Novelty:
        0.72

    Security relevance:
        0.88

    Cost:
        0.13

    Risk:
        0.14

    Dependencies:
        H-184

    Alternatives considered:
        E-419
        E-420
        E-421

    Rejected alternatives:
        duplicate evidence
        lower information gain

    Policy:
        authorized

This is a core DOGE feature.

============================================================
# 17. WORLD MODEL
============================================================

The World Model should be a flagship visual surface.

Render:

    states
    actors
    services
    endpoints
    capabilities
    hypotheses
    experiments
    evidence
    concepts
    strategies
    causal relations

Use SVG or Canvas/WebGL as appropriate.

Features:

    pan
    zoom
    drag
    search
    filter
    collapse
    expand
    focus
    path highlighting
    node inspection
    provenance inspection

Allow graph modes:

    World
    Attack Surface
    Causal
    Research
    Evidence
    Capability
    Strategy

These are projections of the same underlying world model.

Do NOT maintain separate inconsistent graph databases in the UI.

============================================================
# 18. GRAPH UX
============================================================

The graph must not become an unreadable hairball.

Implement:

    clustering
    semantic grouping
    edge filtering
    relevance filtering
    focus mode
    neighborhood expansion
    search-to-node
    path exploration
    minimap

When a node is selected:

    show inspector

Example:

    CAPABILITY C-72

    Preconditions
    Postconditions
    Evidence
    Related hypotheses
    Related experiments
    Confidence
    First observed
    Last validated
    Provenance

============================================================
# 19. SURFACE / ATTACK-SURFACE VIEW
============================================================

Create a dedicated surface visualization.

Show:

    domains
    subdomains
    hosts
    services
    ports
    applications
    APIs
    endpoints
    technologies
    source components

Provide multiple views:

    Tree
    Graph
    Table
    Timeline

Clicking an entity should open its complete context.

============================================================
# 20. INTEGRATED TERMINAL
============================================================

Build a real WSL-backed terminal experience.

The user should feel like they are inside a serious Linux security workstation.

Provide:

    tabs
    multiple sessions
    resize
    scrollback
    search
    copy/paste
    keyboard shortcuts
    working directory
    environment display

Example:

    [ kali ] [ research ] [ shell ]

Commands execute through the existing DOGE runtime.

Do not directly expose raw system execution paths outside the existing
runtime/policy architecture.

Every execution should flow through:

    runtime
      ↓
    policy
      ↓
    process manager
      ↓
    WSL

When output is produced:

    stdout/stderr
      ↓
    event system
      ↓
    parsers where applicable
      ↓
    observations
      ↓
    world model

Manual researcher activity should be automatically captured where the
existing architecture supports it.

The user should NOT have to manually tell DOGE:

    "I just ran nmap."

DOGE should observe the event.

============================================================
# 21. TERMINAL + RESEARCH INTEGRATION
============================================================

This is critical.

The terminal and autonomous engine are not separate worlds.

Show contextual annotations:

    [DOGE]
    Parsed 14 endpoints.

    [DOGE]
    Added service S-91.

    [DOGE]
    New uncertainty detected.

    [DOGE]
    Research frontier updated.

These should be subtle.

Do not spam the terminal.

Allow the user to hide annotations.

============================================================
# 22. FINDINGS
============================================================

Build a professional findings workspace.

Views:

    Grid
    List
    Severity
    Confidence
    Validation
    Timeline

Each finding should display:

    ID
    title
    severity
    confidence
    novelty
    target
    status
    validation state
    evidence state

Finding states:

    Candidate
    Investigating
    Validating
    Validated
    Rejected
    Proven

Never present an unvalidated candidate as a confirmed vulnerability.

============================================================
# 23. FINDING DETAIL
============================================================

Finding detail should contain:

    Summary
    Security property
    Root cause
    Preconditions
    Impact
    Evidence
    Reproduction
    Validation
    Timeline
    Related hypotheses
    Related experiments
    Attack/capability chain
    Confidence
    Provenance
    Mitigation
    Export

Include:

    Replay Evidence

where supported.

============================================================
# 24. EVIDENCE STUDIO
============================================================

Create an evidence-focused surface.

Show:

    event timeline
    requests
    responses
    screenshots/artifacts
    command execution
    observations
    validation
    hashes
    proof chain
    provenance

Every piece of evidence should have an identity.

Example:

    E-8821

    Created:
        19:42:31

    Source:
        Experiment E-421

    Type:
        HTTP observation

    Hash:
        ...

    Related:
        H-184
        F-009

Provide:

    Replay
    Inspect
    Compare
    Export

============================================================
# 25. EVIDENCE REPLAY
============================================================

Build a visual replay system.

Timeline:

    E1
    E2
    E3
    E4
    E5

Controls:

    ▶
    pause
    next
    previous
    speed
    jump

Show:

    command
    request
    response
    observation
    state change
    validation

The user should be able to reconstruct how a finding was established.

============================================================
# 26. TIMELINE
============================================================

Create a universal DOGE timeline.

Events include:

    mission started
    observation created
    entity discovered
    hypothesis created
    hypothesis updated
    experiment selected
    experiment executed
    anomaly detected
    validation started
    validation completed
    finding created
    strategy updated
    frontier changed
    concept created
    AI proposal
    AI rejection
    policy block
    user approval

Timeline should be searchable.

============================================================
# 27. AUTONOMY CENTER
============================================================

Create a dedicated autonomy interface.

Display:

    Current autonomy level
    Current mission
    Current strategy
    Current hypothesis
    Current experiment
    Research frontier
    Budget
    Risk
    Runtime
    Process count
    Pending approvals

Controls:

    Pause
    Resume
    Stop
    Take Control

Autonomy levels:

    1 Observe
    2 Suggest
    3 Low-risk authorized execution
    4 Continuous bounded research
    5 Full bounded mission autonomy

The exact permissions must still be determined by deterministic policy.

============================================================
# 28. BACKGROUND OPERATION
============================================================

DOGE should be capable of running research while the main window is hidden,
subject to mission configuration and policy.

Add:

    Windows system tray

Tray states:

    Ready
    Researching
    Paused
    Finding discovered
    Attention required
    Error

Tray actions:

    Show DOGE
    Pause
    Resume
    Open Mission
    Open Latest Finding
    Stop
    Exit

============================================================
# 29. NOTIFICATIONS
============================================================

Use native Windows notifications where appropriate.

Notify for meaningful events:

    high-confidence finding
    validation complete
    approval required
    mission completed
    mission blocked
    runtime failure
    WSL failure
    important research milestone

Do not notify for every tool execution.

============================================================
# 30. ENVIRONMENT CENTER
============================================================

Create a system/environment dashboard.

Show:

    Windows
    WSL
    distribution
    DOGE runtime
    CPU
    memory
    storage
    active processes
    toolchain
    AI providers

Tool status:

    nmap
    httpx
    ffuf
    nuclei
    sqlmap
    amass
    subfinder
    feroxbuster
    katana
    dalfox
    whatweb
    etc.

Status:

    Ready
    Missing
    Broken
    Version
    Path

Provide:

    Open WSL Terminal
    Diagnose
    Refresh

Do not silently install offensive tooling.

============================================================
# 31. WSL LABORATORY
============================================================

WSL is the laboratory, not the application.

DOGE Desktop must abstract WSL details away from the normal user.

Show:

    Laboratory
        WSL2
        Distribution
        Toolchain
        Workspace
        Resource limits

Allow advanced users to inspect the environment.

Normal users should not need to know:

    wsl.exe
    Linux mount paths
    process IDs
    distro internals

unless they open advanced diagnostics.

============================================================
# 32. LAB SNAPSHOTS
============================================================

Design for reproducible research.

A research environment should eventually support:

    environment version
    toolchain version
    workspace version
    benchmark version

Example:

    DOGE Laboratory
    Version: 1.0
    WSL: Kali
    Toolchain: DOGE-Lab-2026.09

This is important for reproducibility.

Implement only what the current architecture can support safely.

============================================================
# 33. AI SYSTEM
============================================================

AI is optional.

DOGE must support:

    Algorithmic Core
    Local Model
    Remote Model
    No Model

Provider architecture should support:

    local Ollama
    local vLLM
    OpenAI-compatible endpoints
    OpenRouter
    future providers

Do not hardcode one provider.

The AI layer should have roles:

    hypothesis proposal
    semantic interpretation
    source-code explanation
    research summarization
    concept naming
    strategy proposal
    report assistance

AI output must be represented as:

    proposal

not:

    truth

============================================================
# 34. AI INSPECTOR
============================================================

Create an AI inspector.

Show:

    provider
    model
    role
    request
    response
    latency
    token usage where available
    acceptance/rejection
    downstream effect

Example:

    AI PROPOSAL P-17

    Role:
        Hypothesis Generator

    Proposal:
        ...

    Accepted:
        Yes

    Reason:
        Passed deterministic validation

This creates accountability.

============================================================
# 35. LLM-FREE MODE
============================================================

This is a major DOGE differentiator.

Provide:

    Algorithmic Only

mode.

The UI should clearly show:

    AI: OFF
    Algorithmic Core: ACTIVE

DOGE should continue to operate using:

    deterministic reasoning
    world model
    causal reasoning
    anomaly detection
    research frontier
    experiment selection
    validation
    strategy mechanisms
    existing algorithms

where supported.

Do not fake LLM-free intelligence.

If a capability genuinely requires an AI provider, say so.

============================================================
# 36. COMMAND PALETTE
============================================================

Ctrl+Shift+P

Build a professional command palette.

Commands:

    New Mission
    Open Workspace
    Start Research
    Pause Research
    Resume Research
    Stop Research
    Inspect Frontier
    Open World Model
    Open Surface
    Open Terminal
    Open Latest Finding
    Replay Evidence
    Fork Session
    Compare Strategies
    Run Benchmark
    Open Environment
    Change AI Provider
    Toggle Scientist Mode
    Toggle Operator Mode
    Toggle Offline Mode
    Settings

Fuzzy search.

Keyboard navigation.

Recent commands.

============================================================
# 37. KEYBOARD-FIRST DESIGN
============================================================

Security researchers spend enormous amounts of time at the keyboard.

Implement:

    Ctrl+Shift+P
    Ctrl+P
    Ctrl+`
    Ctrl+Shift+F
    Ctrl+Shift+E
    Ctrl+Shift+G

where useful.

Do not invent shortcuts that conflict with OS/browser behavior unnecessarily.

Every important operation should be accessible without hunting through menus.

============================================================
# 38. QUICK ACTIONS
============================================================

Provide contextual quick actions.

Examples:

Target:

    Open
    Inspect
    Research
    Terminal
    Add Note

Hypothesis:

    Inspect
    Test
    Replay
    Compare
    Fork

Finding:

    Validate
    Replay
    Report
    Export

World node:

    Focus
    Expand
    Trace
    Inspect
    Find related

Never expose dangerous actions without the appropriate authorization and
policy controls.

============================================================
# 39. NOTES / RESEARCH NOTEBOOK
============================================================

Create a persistent notebook.

Notes should be linked to:

    target
    entity
    hypothesis
    experiment
    finding
    evidence
    strategy

Allow:

    markdown
    tags
    backlinks
    timestamps

A note should become part of the research context.

============================================================
# 40. SESSION MANAGEMENT
============================================================

Support:

    save
    checkpoint
    restore
    replay
    fork

Example:

    Session 1842

        checkpoint 0
        checkpoint 1
        checkpoint 2

        hypothesis A
            ├── experiment A1
            └── experiment A2

        hypothesis B
            └── experiment B1

Allow the researcher to fork from any checkpoint.

============================================================
# 41. BENCHMARK CENTER
============================================================

Create a first-class benchmark environment.

Show:

    benchmark
    version
    baseline
    DOGE result
    discovery rate
    validation rate
    time
    experiments
    requests
    information gain
    novelty
    false positives
    coverage
    unknown-space reduction

Support:

    Run
    Compare
    Replay
    Export

DOGE should be measurable.

Do not display claims such as:

    "Better than XBOW"

unless there is actual benchmark evidence.

============================================================
# 42. RESEARCH COMPARISON
============================================================

Build a strategy comparison view.

Example:

    Strategy A
    Strategy B
    Strategy C

Compare:

    findings
    time
    experiments
    requests
    information gain
    novelty
    validation
    redundant actions
    unknown-space reduction

This is part of DOGE's scientific identity.

============================================================
# 43. RESEARCH FRONTIER VISUALIZATION
============================================================

Make the unknown space visible.

Show:

    known
    partially known
    uncertain
    unexplored
    blocked
    investigated
    falsified
    promising

The researcher should be able to answer:

    "Where has DOGE NOT looked yet?"

This should be one of the most distinctive screens in the application.

============================================================
# 44. INFORMATION DENSITY
============================================================

Do not waste screen space.

A professional researcher needs lots of information.

But use hierarchy.

Primary:

    current mission
    research state
    frontier
    hypothesis
    experiment

Secondary:

    telemetry
    resources
    event stream

Tertiary:

    raw logs
    implementation details

Everything should be collapsible.

============================================================
# 45. EVENT STREAM
============================================================

Build a live event drawer.

Events:

    observation
    hypothesis
    experiment
    process
    validation
    policy
    finding
    world model
    AI
    runtime

Filters:

    All
    Research
    Runtime
    Terminal
    Validation
    Findings
    AI
    Policy

Events should stream live.

Avoid polling where possible.

============================================================
# 46. ERROR HANDLING
============================================================

Errors must be understandable.

Bad:

    "runtime error"

Good:

    WSL LABORATORY UNAVAILABLE

    DOGE could not connect to the configured WSL environment.

    Cause:
        distribution is not running

    Suggested action:
        Start laboratory

    [ Diagnose ]
    [ Retry ]

Never silently swallow errors.

Never let UI failure corrupt research state.

============================================================
# 47. CRASH RECOVERY
============================================================

DOGE is a long-running research application.

Design for:

    process crashes
    WSL crashes
    UI crashes
    model provider failure
    network failure
    interrupted experiments
    power loss

Persist important state incrementally.

On restart:

    recover workspace
    recover runtime state
    recover session
    show incomplete operations
    allow safe recovery

Never pretend an interrupted experiment completed.

============================================================
# 48. PERFORMANCE
============================================================

DOGE may have:

    thousands of nodes
    thousands of events
    large terminal output
    long research sessions
    large evidence sets

The UI must remain responsive.

Do not render every event as an expensive DOM tree forever.

Use:

    virtualization
    incremental graph rendering
    event batching
    lazy loading
    pagination
    caching
    background computation

Never block the UI thread with heavy computation.

============================================================
# 49. SECURITY OF THE DESKTOP APP
============================================================

DOGE itself is security-sensitive software.

Implement:

    strict local binding behavior
    no unnecessary network listeners
    loopback-only APIs where appropriate
    authentication/authorization for any exposed local control surface
    safe serialization
    input validation
    path validation
    command validation
    workspace isolation
    secret protection
    safe logging

Do not expose arbitrary remote command execution through the desktop API.

Do not trust frontend-supplied authorization.

The backend must independently enforce policy.

============================================================
# 50. FILE SYSTEM SAFETY
============================================================

Workspace paths must be validated.

Prevent:

    path traversal
    accidental workspace escape
    destructive cleanup outside workspace
    unsafe symlink behavior where applicable

All filesystem operations should have clear ownership.

============================================================
# 51. SECRETS
============================================================

Never put secrets into:

    frontend source
    logs
    screenshots
    event streams
    Git
    configuration files unnecessarily

If credentials are required, integrate with appropriate secure OS storage
where practical.

The UI should show:

    configured

rather than displaying secrets.

============================================================
# 52. DESKTOP SETTINGS
============================================================

Settings categories:

    Appearance
    Workspace
    WSL
    Toolchain
    AI
    Research
    Safety
    Notifications
    Terminal
    Keyboard
    Privacy
    Advanced

Appearance:

    Dark
    System

DOGE should be dark-first.

============================================================
# 53. ACCESSIBILITY
============================================================

Even though this is a security workstation:

    keyboard navigation
    focus states
    readable contrast
    scalable text
    screen-reader semantics where practical
    reduced-motion option

must be considered.

============================================================
# 54. ANIMATION
============================================================

Use animation only to communicate state.

Good:

    node discovery pulse
    mission state transition
    finding arrival
    progress
    panel transition

Bad:

    constant glowing
    spinning logos
    distracting particles
    animations that delay interaction

The application should feel alive, not noisy.

============================================================
# 55. DESKTOP UX PRINCIPLE
============================================================

Every screen should answer:

    What is this?
    Why does it matter?
    What can I do?
    What happened?
    What happens next?

Never force the user to read raw logs to understand the system.

============================================================
# 56. DO NOT BUILD A FAKE SECURITY DASHBOARD
============================================================

This is a critical warning.

Do not make the application primarily:

    vulnerability counters
    severity donuts
    scan buttons
    port lists
    generic AI chat

Those are secondary.

The main experience is:

    research.

The central screen should answer:

    "What is DOGE learning about this environment?"

============================================================
# 57. AI CHAT IS NOT THE MAIN UI
============================================================

The screenshot includes an AI assistant.

Keep it.

But it should NOT dominate the application.

The assistant should be contextual.

Example:

User selects:

    Hypothesis H-184

AI panel becomes:

    Ask about H-184...

Suggested actions:

    Explain hypothesis
    Summarize evidence
    Find contradictions
    Suggest experiments
    Explain decision

The AI should understand the selected DOGE context.

Do not make a generic ChatGPT clone inside DOGE.

============================================================
# 58. CONTEXTUAL AI
============================================================

The assistant should know the currently selected:

    target
    entity
    hypothesis
    experiment
    finding
    evidence
    world-model region

through structured context supplied by DOGE.

Do not dump the entire database into every prompt.

Build a context selection layer.

============================================================
# 59. APPLICATION INFORMATION ARCHITECTURE
============================================================

Final navigation:

    DOGE

    ├── Mission
    │
    ├── Surface
    │
    ├── Research
    │   ├── Frontier
    │   ├── Hypotheses
    │   └── Strategies
    │
    ├── World
    │   ├── Graph
    │   ├── States
    │   ├── Capabilities
    │   └── Concepts
    │
    ├── Experiments
    │
    ├── Findings
    │
    ├── Evidence
    │
    ├── Benchmarks
    │
    ├── Terminal
    │
    ├── Notebook
    │
    └── Environment

============================================================
# 60. MAIN SCREEN COMPOSITION
============================================================

The default Mission screen should approximately follow:

┌───────────────────────────────────────────────────────────────────────┐
│ DOGE      Workspace        Target              ● RESEARCHING     ⋯   │
├───────┬──────────────────────────────────────────────────────┬───────┤
│       │                                                      │       │
│ M     │  CURRENT MISSION                                    │       │
│ I     │                                                      │       │
│ S     │  target.example                                     │       │
│ S     │  Autonomous Security Research                       │       │
│ I     │                                                      │       │
│ O     │  ┌────────────┐ ┌────────────┐ ┌──────────────┐     │       │
│ N     │  │ Frontier   │ │ Hypothesis │ │ Experiment   │     │       │
│       │  │ 8 unknowns │ │ H-184      │ │ E-421        │     │       │
│       │  └────────────┘ └────────────┘ └──────────────┘     │       │
│ S     │                                                      │       │
│ U     │             RESEARCH CANVAS                         │       │
│ R     │                                                      │       │
│ F     │         World / Attack / Causal Graph               │       │
│ A     │                                                      │       │
│ C     │                                                      │       │
│ E     │                                                      │       │
│       ├──────────────────────────────────────────────────────┤       │
│       │ TERMINAL / EVENTS                                    │       │
│       │                                                      │       │
│       └──────────────────────────────────────────────────────┴───────┘
└───────┴────────────────────────────────────────────────────────────────┘

The right inspector should be collapsible.

The bottom terminal/event drawer should be collapsible.

============================================================
# 61. DIFFERENTIATE DOGE FROM GENERIC PENTESTING PRODUCTS
============================================================

DOGE's identity must revolve around:

    world model
    uncertainty
    research frontier
    hypotheses
    experiments
    causal reasoning
    concept discovery
    strategy discovery
    evidence
    validation
    learning
    reproducibility

A scanner is a tool.

An LLM is a tool.

A terminal is a tool.

A vulnerability database is a tool.

DOGE is the research environment that coordinates these instruments.

============================================================
# 62. DIFFERENTIATE DOGE FROM GENERIC AI AGENTS
============================================================

Do not build:

    prompt
      ↓
    LLM
      ↓
    shell
      ↓
    output

Build:

    world model
      ↓
    uncertainty
      ↓
    research frontier
      ↓
    hypothesis
      ↓
    experiment
      ↓
    policy
      ↓
    execution
      ↓
    evidence
      ↓
    validation
      ↓
    learning

The LLM, if present, sits inside this architecture.

It does not own the architecture.

============================================================
# 63. DO NOT OVERENGINEER THE FRONTEND
============================================================

Before adding dependencies ask:

    Does this materially improve DOGE?

Avoid dependency bloat.

Avoid remote assets.

Avoid giant UI libraries unless justified.

Prefer:

    small
    auditable
    maintainable
    offline
    fast

============================================================
# 64. IMPLEMENTATION PROCESS
============================================================

Do NOT attempt to write the entire application blindly in one pass.

Work in stages.

STAGE 1

Inspect repository.

Produce:

    architecture map
    dependency map
    runtime map
    existing API map
    existing UI/TUI map
    reusable components
    integration points
    risks

Do not change code yet.

STAGE 2

Design desktop architecture.

Implement:

    Wails application
    embedded frontend
    native window
    Go bindings
    event bridge

STAGE 3

Implement:

    application shell
    navigation
    workspace loading
    status bar
    command palette

STAGE 4

Implement:

    Mission
    Mission Builder
    autonomy controls
    runtime integration

STAGE 5

Implement:

    Surface
    World Model
    graph visualization

STAGE 6

Implement:

    Research
    Frontier
    Hypotheses
    Experiments
    Decision Inspector

STAGE 7

Implement:

    Terminal
    WSL integration
    event stream

STAGE 8

Implement:

    Findings
    Evidence
    Replay
    Timeline

STAGE 9

Implement:

    Environment
    WSL diagnostics
    Toolchain

STAGE 10

Implement:

    AI integration
    contextual assistant
    provider management

STAGE 11

Implement:

    Benchmarks
    Sessions
    Forking
    recovery

STAGE 12

Polish the entire application.

============================================================
# 65. DEVELOPMENT LOOP
============================================================

After EACH meaningful implementation phase:

    compile
    run tests
    run relevant integration tests
    inspect UI
    fix errors
    inspect logs
    verify real functionality

Then continue.

Never accumulate dozens of unverified changes.

Use small coherent commits.

============================================================
# 66. TESTING
============================================================

Minimum:

    go test ./...

Add desktop tests.

Test:

    application startup
    Wails bindings
    workspace loading
    workspace creation
    event propagation
    mission controls
    lifecycle
    WSL integration
    terminal streaming
    graph data
    findings
    evidence
    recovery
    policy enforcement

Where possible, create deterministic fixtures.

============================================================
# 67. UI TESTING
============================================================

Verify:

    first launch
    create workspace
    open workspace
    create mission
    start mission
    pause
    resume
    stop
    navigate every surface
    open graph
    inspect node
    open finding
    replay evidence
    open terminal
    switch Operator/Scientist
    open command palette
    change AI provider
    close/reopen application
    recover session

============================================================
# 68. REAL SYSTEM TESTING
============================================================

Where safe and authorized:

    verify WSL detection
    verify process lifecycle
    verify terminal streaming
    verify workspace persistence
    verify runtime events
    verify resource governor
    verify policy enforcement

Do not test against unauthorized external systems.

Use controlled local targets and laboratory environments.

============================================================
# 69. PERFORMANCE TARGETS
============================================================

Target:

    fast startup
    smooth navigation
    responsive graph
    non-blocking terminal
    low idle CPU
    bounded memory
    efficient event processing

Measure instead of guessing.

============================================================
# 70. PACKAGING
============================================================

Production output:

    DOGE.exe

Installer:

    DOGE-Setup.exe

The user should be able to:

    install
    launch
    create workspace
    begin research

without opening PowerShell first.

Optional:

    file association for DOGE workspace files
    Start Menu shortcut
    Desktop shortcut
    PATH integration for CLI

The CLI remains available.

============================================================
# 71. CLI + DESKTOP COEXISTENCE
============================================================

Do NOT kill the CLI.

The architecture should support:

    doge
    doge desktop
    doge hunt
    doge research
    doge benchmark
    doge monitor

The desktop should be another interface to the same DOGE core.

Example:

    CLI
      ↓
    Runtime
      ↓
    Core

and:

    Desktop
      ↓
    Runtime
      ↓
    Core

No duplicated research logic.

============================================================
# 72. DESKTOP API
============================================================

Create clean application bindings such as:

    GetStatus()
    GetEnvironment()
    GetWorkspace()
    CreateWorkspace()
    OpenWorkspace()
    CreateMission()
    StartMission()
    PauseMission()
    ResumeMission()
    StopMission()
    GetResearchFrontier()
    GetHypotheses()
    GetExperiments()
    GetWorldModel()
    GetFindings()
    GetEvidence()
    GetTimeline()
    ExecuteTerminal()
    GetToolchain()
    GetAIProviders()
    SetAIProvider()

Exact APIs should follow the existing codebase.

Do not duplicate existing runtime functionality.

============================================================
# 73. EVENT API
============================================================

Create structured events.

Examples:

    MissionStarted
    MissionPaused
    MissionStopped
    ObservationCreated
    EntityDiscovered
    HypothesisCreated
    HypothesisUpdated
    ExperimentSelected
    ExperimentStarted
    ExperimentCompleted
    ValidationStarted
    ValidationCompleted
    FindingCreated
    FindingValidated
    FrontierUpdated
    StrategyUpdated
    ConceptDiscovered
    ProcessStarted
    ProcessOutput
    ProcessCompleted
    PolicyBlocked
    ApprovalRequired
    RuntimeError

Use typed event payloads.

============================================================
# 74. RESEARCH STATE
============================================================

The frontend should not invent state.

The backend is authoritative.

Frontend state is a projection/cache.

For example:

    backend:
        MissionState

    frontend:
        MissionViewModel

Do not let the browser UI mutate backend truth directly.

============================================================
# 75. OBSERVABILITY
============================================================

DOGE should expose enough telemetry to diagnose itself.

Show:

    runtime status
    active processes
    event rate
    queue depth
    research cycle
    memory
    CPU
    WSL health
    tool health

Advanced diagnostics should be available but hidden from the normal view.

============================================================
# 76. DESIGN THE EMPTY STATES
============================================================

This is important.

When there is no workspace:

    "Create your first research workspace."

When there is no mission:

    "No active mission."

When there are no findings:

    "No validated findings yet."

When there is no AI:

    "Algorithmic Core active. AI provider optional."

When WSL is unavailable:

    "Laboratory unavailable."

Never show empty black panels.

============================================================
# 77. DESIGN FOR LONG-RUNNING RESEARCH
============================================================

DOGE is not only a 10-minute scanner.

The UI should remain useful after:

    1 hour
    6 hours
    24 hours

Research should accumulate.

The workspace should become more valuable over time.

The application should show:

    what changed
    what was learned
    what remains unknown
    what strategies improved
    what hypotheses were falsified
    what concepts emerged

============================================================
# 78. LEARNING VIEW
============================================================

Create a learning/history surface.

Show:

    strategies learned
    failed strategies
    successful strategies
    concepts discovered
    target-independent knowledge
    benchmark improvements

Distinguish:

    target-specific knowledge

from:

    generalized knowledge

This is essential to DOGE's long-term research identity.

============================================================
# 79. CROSS-TARGET KNOWLEDGE
============================================================

Where supported by the existing research architecture, expose:

    transferred concepts
    transferred causal patterns
    transferred strategies
    confidence
    provenance

Do NOT silently transfer target-specific secrets or credentials.

The UI should make knowledge provenance visible.

============================================================
# 80. FUTURE-PROOF THE ARCHITECTURE
============================================================

Design extension points for:

    new researchers
    new model providers
    new tools
    new graph projections
    new benchmark types
    new experiment generators
    new evidence types
    new target adapters

But do NOT implement speculative plugin systems unnecessarily in v1.

Create clean interfaces first.

============================================================
# 81. PRODUCT QUALITY BAR
============================================================

The finished application should pass this test:

If someone sees DOGE for the first time, they should NOT think:

    "This is a web dashboard."

They should think:

    "This is a serious desktop security workstation."

If they start a mission, they should NOT think:

    "The AI is randomly running commands."

They should think:

    "The system has a research process."

If they inspect a finding, they should NOT think:

    "The AI says this is vulnerable."

They should think:

    "There is an evidence-backed chain establishing why this is a finding."

If they disable AI, they should NOT think:

    "DOGE stopped working."

They should think:

    "The algorithmic research core is still operating."

============================================================
# 82. DEFINITION OF DONE
============================================================

DOGE Desktop v1 is complete only when:

[ ] DOGE launches as a native Windows application.

[ ] No Edge --app production mechanism exists.

[ ] UI assets are embedded in the executable.

[ ] Application works offline.

[ ] DOGE Core remains in Go.

[ ] Runtime remains independent of UI.

[ ] WSL is treated as a managed laboratory.

[ ] Workspace system works.

[ ] Mission Builder works.

[ ] Mission lifecycle works.

[ ] Operator/Scientist modes work.

[ ] Research Frontier works.

[ ] Hypothesis system is visible.

[ ] Experiment system is visible.

[ ] Decision Inspector works.

[ ] World Model is interactive.

[ ] Surface discovery is visible.

[ ] Integrated WSL terminal works.

[ ] Terminal events integrate with DOGE.

[ ] Findings workspace works.

[ ] Evidence Studio works.

[ ] Evidence replay works.

[ ] Timeline works.

[ ] Autonomy controls work.

[ ] Policy remains deterministic.

[ ] High-risk/state-changing actions remain gated.

[ ] AI is optional.

[ ] Local AI provider support exists where implemented.

[ ] Remote AI provider support exists where implemented.

[ ] AI cannot override DOGE policy.

[ ] Environment Center works.

[ ] WSL health is visible.

[ ] Toolchain health is visible.

[ ] Sessions can be recovered.

[ ] Benchmarks are visible.

[ ] CLI still works.

[ ] Existing Go tests remain green.

[ ] Desktop tests pass.

[ ] Application does not contain fake production functionality.

[ ] Application remains responsive during long-running research.

============================================================
# 83. FINAL INSTRUCTION TO THE IMPLEMENTATION AGENT
============================================================

Do not rush.

Do not blindly generate hundreds of files.

Do not start by building decorative UI.

First understand DOGE.

Then design the integration boundary.

Then implement the native shell.

Then connect the real runtime.

Then progressively expose the real research system.

When you encounter a design decision, prefer:

    correctness
    separation of concerns
    deterministic safety
    offline capability
    reproducibility
    observability
    maintainability
    researcher ergonomics

over:

    flashy demos
    unnecessary dependencies
    fake autonomy
    generic AI chat
    superficial similarity to other products

The supplied DOGE screenshot is the visual seed.

The existing DOGE repository is the engineering foundation.

The DOGE research architecture is the intellectual foundation.

Your job is to combine them into one coherent product.

Do not merely build a prettier DOGE.

Build the desktop environment in which DOGE itself becomes usable.

============================================================
# 84. YOUR FIRST RESPONSE
============================================================

Before modifying anything, inspect the repository and report:

1. Existing architecture
2. Existing runtime capabilities
3. Existing desktop/UI capabilities
4. Existing CLI capabilities
5. Existing research engine capabilities
6. Existing persistence/session capabilities
7. Existing WSL capabilities
8. Existing AI/model capabilities
9. Existing tests
10. What can be reused directly
11. What must be added
12. What must NOT be rewritten
13. Proposed implementation sequence
14. Risks and architectural conflicts

Then begin implementation.

Do not ask me to manually explain files that you can inspect yourself.

Do not stop after generating a plan.

After inspection, implement the system incrementally and verify each stage.

The final objective is:

                        DOGE.exe

        A complete offline-first Windows desktop
        security research operating environment.

        Not a webpage.
        Not a dashboard.
        Not a CLI wrapper.
        Not an LLM shell.

        A real security research workstation.

                         BUILD IT.
```

## One change I'd make to the screenshot itself

The generated design is a **good visual starting point**, but I would deliberately move DOGE away from making **"Vulnerabilities / Exploitation / Post-Exploitation"** the dominant navigation.

That makes it look like a conventional pentesting suite.

The more distinctive DOGE navigation should be:

```text
MISSION
SURFACE
RESEARCH
WORLD
EXPERIMENTS
FINDINGS
EVIDENCE
BENCHMARKS
TERMINAL
ENVIRONMENT
```

And the center of gravity should be **Research Frontier + World Model**, not a vulnerability counter.

That's the part that makes DOGE feel like a genuinely different product rather than "Burp + Kali + an AI chat panel."

Also, your current runtime work is exactly the right foundation for this direction. The desktop should sit **above** it rather than replacing it:

```text
                 DOGE.exe
                    │
             Native Desktop
                    │
              Desktop API
                    │
              DOGE Runtime
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
     Research    World Model   Policy
        │           │           │
        └───────────┼───────────┘
                    │
                  WSL2
                    │
              Research Lab
```

That separation is the piece I would guard most aggressively while the coding agent works. The UI can evolve rapidly. **The research kernel and policy boundary should not become spaghetti underneath it.** 🧠🖥️
