Yes. That changes the architecture **substantially**.

If you genuinely do not want a web application, I would **remove Wails, WebView2, HTML, CSS, JavaScript, React, Electron, localhost UI, SSE-based UI, and browser-based rendering from the desktop architecture entirely.**

For a **Windows-first DOGE**, my recommendation is:

```text
Native UI:
    C# + .NET  + WinUI 3

DOGE Core:
    Go

Communication:
    Windows Named Pipes / local IPC
    NOT HTTP for the primary desktop interface

Laboratory:
    WSL2

Storage:
    SQLite / existing DOGE persistence

Graphs:
    Native WinUI drawing / DirectX-backed rendering where needed

Terminal:
    Native Windows terminal control / ConPTY integration
    connected to WSL2

AI:
    Go/C# provider abstraction
    Local models + OpenRouter optional

Output:
    DOGE.exe
```

This gives you a **real Windows application**, with a native Windows UI, while preserving the existing Go research engine instead of rewriting the brain unnecessarily.

Here is the stronger master prompt I would give the coding AI.

---

# MASTER IMPLEMENTATION PROMPT

## DOGE Native Desktop Security Research Operating Environment

```text id="doge-native-master"
You are the principal software architect, senior Windows desktop engineer,
systems engineer, Go engineer, C#/.NET engineer, security-research engineer,
UX architect, graphics engineer, and product designer responsible for
transforming the existing DOGE repository into a complete native Windows
desktop application.

This is a BUILD MISSION.

You are not being asked to create a mockup.

You are not being asked to create a prototype with fake data.

You are not being asked to create a website.

You are not being asked to create a browser application.

You are not being asked to create an Electron application.

You are not being asked to create a Wails application.

You are not being asked to wrap a localhost webpage inside a desktop shell.

You are building a REAL Windows desktop executable:

                        DOGE.exe

DOGE is a security research operating environment designed specifically
for ethical hackers, penetration testers, vulnerability researchers,
security engineers, red teamers operating under authorization, and
security researchers.

The application must make their daily research workflow dramatically
easier while exposing the underlying DOGE autonomous research system.

============================================================
# 1. NON-NEGOTIABLE TECHNOLOGY REQUIREMENT
============================================================

DO NOT USE:

    HTML
    CSS
    JavaScript
    TypeScript
    React
    Vue
    Svelte
    Electron
    Tauri
    Wails
    WebView
    WebView2
    Chromium
    Edge app mode
    localhost webpage as the application UI
    browser-based application architecture
    CDN assets
    web frontend frameworks

The final DOGE desktop interface must NOT be a web application.

The user must never need:

    Chrome
    Edge
    Firefox
    a browser
    localhost
    a web server

to operate the DOGE graphical application.

============================================================
# 2. CHOOSE THE BEST NATIVE WINDOWS TECHNOLOGY
============================================================

DOGE is currently a Go-based security research system.

Do NOT rewrite the entire DOGE research engine merely to satisfy the UI.

Use the best technology for each layer.

For the native Windows desktop UI, use:

    C#
    .NET
    WinUI 3
    Windows App SDK
    XAML

This is a native Windows desktop application architecture.

XAML is allowed.

XAML is NOT HTML.

XAML is a native declarative Windows UI technology.

Use C# for:

    desktop shell
    windows
    navigation
    controls
    menus
    dialogs
    native notifications
    system tray integration
    keyboard shortcuts
    native terminal host
    visualizations
    application settings
    Windows integration
    desktop lifecycle

Keep the DOGE security research engine in Go.

Use Go for:

    research engine
    world model
    research frontier
    hypotheses
    experiments
    strategies
    learning
    validation
    evidence
    policy
    scope
    runtime
    WSL2
    process management
    persistence
    AI routing where appropriate
    CLI
    autonomous research

This is intentional.

DOGE becomes a two-language system because each language is being used
for what it is best suited for:

    C#/.NET:
        native Windows application

    Go:
        DOGE research/runtime engine

Do NOT rewrite working Go subsystems in C# unless there is an overwhelming
architectural reason.

============================================================
# 3. FINAL ARCHITECTURE
============================================================

Build:

                         DOGE.exe
                            │
                 ┌──────────┴──────────┐
                 │                     │
          Native WinUI 3          DOGE Core
            C#/.NET                  Go
                 │                     │
                 │              internal/runtime
                 │                     │
                 │              Research Engine
                 │                     │
                 │              World Model
                 │                     │
                 │              Strategy Engine
                 │                     │
                 │              Validation
                 │                     │
                 │              Evidence
                 │                     │
                 │              Policy / Scope
                 │                     │
                 └──────────┬──────────┘
                            │
                     Native Local IPC
                            │
                    Windows Named Pipes
                            │
                     WSL2 Laboratory
                            │
              ┌─────────────┼──────────────┐
              │             │              │
             tools        source       authorized
                                        targets

The desktop and research engine must be separate processes/components
with a clean contract.

============================================================
# 4. PRIMARY IPC
============================================================

Do NOT make HTTP the primary desktop communication mechanism.

Do NOT make SSE the primary desktop event system.

Use:

    Windows Named Pipes

for the native Windows desktop ↔ DOGE Core communication.

Create a strongly typed IPC protocol.

Conceptually:

    DOGE Desktop
         │
         │ Named Pipe
         ▼
    DOGE Core

Messages:

    Request
    Response
    Event
    Error
    Stream
    Command
    ApprovalRequest

Use structured serialization.

JSON is acceptable as a wire serialization format if useful.

JSON is NOT the UI.

Do not confuse a data serialization format with a web architecture.

The protocol must support:

    request ID
    correlation ID
    message type
    timestamp
    payload
    error
    version

Example:

    {
        type: "research.frontier.updated",
        correlation_id: "...",
        timestamp: "...",
        payload: {...}
    }

Implement versioning from the beginning.

============================================================
# 5. KEEP THE EXISTING HTTP API AS SECONDARY
============================================================

The existing localhost API may remain for:

    CLI
    diagnostics
    testing
    automation
    integrations
    future external tooling

But the native desktop application MUST NOT depend on:

    localhost HTTP
    browser rendering
    web server availability

The desktop must communicate directly with DOGE Core.

============================================================
# 6. PRODUCT IDENTITY
============================================================

DOGE is:

    SECURITY RESEARCH OPERATING ENVIRONMENT

It is NOT:

    generic vulnerability scanner
    generic pentesting dashboard
    AI chatbot
    terminal wrapper
    browser application
    Burp clone
    Nmap GUI
    vulnerability database frontend

DOGE should feel like a new category of professional software.

The user's mental model should be:

    "I opened my security research workstation."

============================================================
# 7. USE THE PROVIDED DESIGN AS VISUAL INSPIRATION
============================================================

The provided DOGE screenshot establishes the visual direction.

Use:

    dark obsidian background
    blue-black surfaces
    cyan primary accent
    violet secondary accent
    emerald success
    amber warning
    crimson critical
    dense professional information layout
    technical typography
    graph visualization
    integrated terminal
    researcher-centric navigation

BUT DO NOT COPY THE SCREENSHOT LITERALLY.

Improve the product.

The screenshot currently resembles a security dashboard.

DOGE should evolve beyond that.

The final application must emphasize:

    research
    uncertainty
    world model
    hypotheses
    experiments
    evidence
    reasoning
    validation
    research frontier

rather than merely:

    scans
    vulnerabilities
    exploit buttons
    severity counters

============================================================
# 8. NATIVE APPLICATION WINDOW
============================================================

Create a real Windows application.

Application name:

    DOGE

Window title:

    DOGE — Security Research Workstation

Provide:

    native window
    native minimize
    native maximize
    native close
    application icon
    native menu
    keyboard shortcuts
    system tray
    notifications
    settings
    startup/recovery
    multiple windows where useful

The application must launch as:

    DOGE.exe

Double-clicking DOGE.exe must open the application.

No terminal window should be required.

No browser should open.

============================================================
# 9. SOLUTION STRUCTURE
============================================================

Create a clean repository structure.

Conceptually:

    /cmd
        /workspace
        ...

    /internal
        /runtime
        /research
        /world
        /strategy
        /evidence
        /validation
        /policy
        ...

    /desktop
        DOGE.Desktop.sln

        /DOGE.Desktop
            App.xaml
            App.xaml.cs
            MainWindow.xaml
            MainWindow.xaml.cs

            /Views
            /ViewModels
            /Models
            /Services
            /Controls
            /Graph
            /Terminal
            /IPC
            /Themes
            /Assets

    /protocol
        ...

Do not force this exact structure if the existing repository has a
better organization.

Integrate cleanly with the existing project.

============================================================
# 10. NATIVE UI ONLY
============================================================

Every visible UI element must use native desktop technology.

Use:

    WinUI 3 controls
    XAML
    C#
    native drawing APIs
    native graphics where appropriate

For graph rendering, evaluate:

    WinUI Canvas
    Composition APIs
    Direct2D
    Direct3D
    Win2D if appropriate

Choose based on performance and maintainability.

Do not use a JavaScript graph library.

Do not use a browser canvas.

============================================================
# 11. APPLICATION SHELL
============================================================

Create:

    left navigation rail
    top command/search area
    central workspace
    right inspector
    bottom event/terminal drawer

The basic layout:

┌─────────────────────────────────────────────────────────────────────┐
│ DOGE       Workspace      Target             ● Researching     ⚙   │
├──────────┬──────────────────────────────────────────────┬───────────┤
│          │                                              │           │
│ Mission  │                                              │ Inspector │
│ Surface  │                                              │           │
│ Research │             CURRENT WORKSPACE                │           │
│ World    │                                              │           │
│ Experim. │             Research Canvas                  │           │
│ Findings │                                              │           │
│ Evidence │                                              │           │
│ Bench.   │                                              │           │
│ Terminal │                                              │           │
│ Environ. │                                              │           │
│          ├──────────────────────────────────────────────┤           │
│          │ Terminal / Events                            │           │
└──────────┴──────────────────────────────────────────────┴───────────┘

Everything must be resizable.

============================================================
# 12. NAVIGATION
============================================================

Primary surfaces:

    Mission
    Surface
    Research
    World Model
    Experiments
    Findings
    Evidence
    Benchmarks
    Terminal
    Environment

Additional:

    Notebook
    AI
    Settings

Use icons appropriate for each surface.

Do not use random stock hacker icons.

============================================================
# 13. MISSION
============================================================

Mission is the home screen.

Display:

    target
    authorization
    scope
    objective
    autonomy
    runtime
    budget
    risk
    current activity
    research frontier
    current hypothesis
    current experiment
    recent events
    discoveries

Controls:

    Start
    Pause
    Resume
    Stop
    Take Control

Backend policy is authoritative.

The UI cannot override policy.

============================================================
# 14. MISSION BUILDER
============================================================

Create a native WinUI mission builder.

Fields:

    Workspace
    Target
    Authorization
    Scope
    Objective
    Research mode
    Runtime limit
    Request budget
    Resource budget
    Risk ceiling
    Autonomy
    AI mode

Modes:

    Observe
    Recon
    Research
    Benchmark
    Monitor

Before execution, show a Mission Contract.

Example:

    Target:
        authorized.example

    Authorization:
        verified

    Scope:
        *.authorized.example

    Risk:
        Conservative

    Budget:
        20,000 requests

    State-changing operations:
        Approval required

Then:

    START MISSION

============================================================
# 15. OPERATOR MODE
============================================================

Operator mode is optimized for direct work.

Show:

    targets
    surface
    terminal
    tools
    requests
    notes
    evidence
    environment

The user should be able to work quickly.

============================================================
# 16. SCIENTIST MODE
============================================================

Scientist mode is optimized for understanding DOGE's research.

Show:

    research frontier
    uncertainty
    hypotheses
    experiments
    world model
    causal relationships
    evidence
    strategy
    learning
    concepts

This should feel like a scientific laboratory.

============================================================
# 17. RESEARCH FRONTIER
============================================================

This is a flagship DOGE screen.

Show unresolved research questions.

Example:

    HIGH

    Authorization state transition
    Cache behavior
    Information boundary
    Workflow transition
    Cross-context data flow

Each item displays:

    uncertainty
    expected information gain
    novelty
    security relevance
    cost
    risk
    dependencies
    evidence

The user can ask:

    Why?

and DOGE must explain using structured research state.

============================================================
# 18. HYPOTHESES
============================================================

Hypotheses are first-class objects.

Example:

    H-184

    Authorization decision depends on stale state.

Show:

    confidence
    evidence
    origin
    experiments
    related concepts
    contradictions
    status
    provenance

States:

    Proposed
    Investigating
    Supported
    Falsified
    Confirmed
    Archived

============================================================
# 19. EXPERIMENTS
============================================================

Every experiment is a first-class object.

Display:

    ID
    objective
    hypothesis
    preconditions
    expected information gain
    novelty
    cost
    risk
    authorization
    execution
    result
    evidence
    world model changes

Actions:

    Inspect
    Replay
    Fork
    Compare

============================================================
# 20. DECISION INSPECTOR
============================================================

Whenever DOGE chooses an experiment, show why.

Example:

    SELECTED EXPERIMENT

    E-421

    Information Gain       0.84
    Novelty                0.72
    Security Relevance     0.88
    Cost                   0.13
    Risk                   0.14

    Alternatives:

        E-419
        E-420
        E-421

    Selection reason:

        Highest-value authorized experiment
        under the current research frontier.

This is one of the defining DOGE UX features.

============================================================
# 21. WORLD MODEL
============================================================

Build a high-performance native graph visualization.

Nodes can represent:

    target
    host
    service
    endpoint
    actor
    state
    capability
    hypothesis
    experiment
    evidence
    concept
    strategy
    invariant

Edges can represent:

    observed
    enables
    depends_on
    causes
    contradicts
    supports
    derived_from
    tested_by
    validated_by

Provide graph projections:

    World
    Surface
    Causal
    Research
    Evidence
    Capability
    Strategy

Features:

    zoom
    pan
    drag
    search
    filter
    focus
    expand
    collapse
    path highlighting
    node inspection
    provenance

Do not create separate UI-only graph truth.

The backend world model is authoritative.

============================================================
# 22. GRAPH PERFORMANCE
============================================================

The graph must remain responsive with:

    hundreds of nodes
    thousands of nodes
    large edge counts

Use:

    virtualization
    spatial indexing
    incremental rendering
    level-of-detail rendering
    background layout calculations

Do not freeze the UI thread.

============================================================
# 23. SURFACE
============================================================

Provide:

    domains
    subdomains
    hosts
    ports
    services
    technologies
    applications
    APIs
    endpoints
    source components

Views:

    tree
    table
    graph
    timeline

Selecting an entity opens contextual information.

============================================================
# 24. NATIVE TERMINAL
============================================================

Build an actual terminal experience.

Do not create a fake text box that executes commands.

Use Windows pseudo-console technology where appropriate:

    ConPTY

and connect it to:

    WSL2

The user should see:

    real shell
    real interactive input
    real stdout
    real stderr
    colors
    cursor
    command history
    tabs
    resizing

The terminal should behave like a serious terminal.

============================================================
# 25. TERMINAL ARCHITECTURE
============================================================

Conceptually:

    WinUI Terminal Control
             │
           ConPTY
             │
       Windows process
             │
           WSL2
             │
        Linux shell
             │
          tools

Integrate terminal execution with the existing DOGE runtime.

Do not circumvent the runtime's policy controls.

============================================================
# 26. RESEARCH-AWARE TERMINAL
============================================================

Terminal output should flow through the existing DOGE architecture where
appropriate.

Conceptually:

    command
       ↓
    runtime
       ↓
    WSL
       ↓
    process
       ↓
    stdout/stderr
       ↓
    parser
       ↓
    observation
       ↓
    world model

The user should not have to manually import every command result.

============================================================
# 27. FINDINGS
============================================================

Create a professional native Findings interface.

States:

    Candidate
    Investigating
    Validating
    Validated
    Rejected
    Proven

Display:

    title
    severity
    confidence
    novelty
    target
    validation
    evidence

Never display a candidate as confirmed.

============================================================
# 28. FINDING INSPECTOR
============================================================

Show:

    Summary
    Security property
    Root cause
    Preconditions
    Impact
    Evidence
    Validation
    Timeline
    Hypotheses
    Experiments
    Proof
    Confidence
    Provenance
    Mitigation
    Report

Actions:

    Replay
    Export
    Generate Report
    Copy Finding ID

============================================================
# 29. EVIDENCE STUDIO
============================================================

Create:

    evidence browser
    evidence timeline
    artifact viewer
    request/response viewer
    screenshot viewer
    command output viewer
    proof chain

Every artifact has:

    ID
    source
    timestamp
    hash
    relationships

============================================================
# 30. EVIDENCE REPLAY
============================================================

Build a native replay interface.

Timeline:

    E1
    E2
    E3
    E4
    E5

Controls:

    play
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
    state
    validation

============================================================
# 31. TIMELINE
============================================================

Universal research timeline.

Events:

    mission started
    observation
    entity discovered
    hypothesis created
    experiment selected
    experiment executed
    anomaly
    validation
    finding
    strategy update
    concept discovery
    frontier update
    policy block
    approval request
    AI proposal

Searchable.

Filterable.

Virtualized for long sessions.

============================================================
# 32. AUTONOMY
============================================================

Create an Autonomy Center.

Levels:

    1 Observe
    2 Suggest
    3 Low-risk authorized execution
    4 Continuous bounded research
    5 Full bounded mission autonomy

Display:

    current level
    current strategy
    current hypothesis
    current experiment
    pending approvals
    budget
    risk
    frontier

Controls:

    Pause
    Resume
    Stop
    Take Control

Policy remains authoritative.

============================================================
# 33. SYSTEM TRAY
============================================================

DOGE should continue operating in the background when explicitly configured
to do so.

Tray:

    DOGE

States:

    Ready
    Researching
    Paused
    Attention Required
    Finding
    Error

Actions:

    Show DOGE
    Pause
    Resume
    Open Mission
    Open Latest Finding
    Stop
    Exit

============================================================
# 34. NATIVE WINDOWS NOTIFICATIONS
============================================================

Use Windows-native notifications.

Notify for:

    validated finding
    approval required
    mission completion
    important research milestone
    runtime failure
    WSL failure

Do not spam notifications.

============================================================
# 35. ENVIRONMENT CENTER
============================================================

Show:

    Windows
    WSL2
    distribution
    CPU
    RAM
    disk
    process count
    DOGE runtime
    toolchain
    AI providers

Tools:

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

For each:

    status
    version
    path
    availability

Do not silently install tools.

============================================================
# 36. WSL LABORATORY
============================================================

WSL is the research laboratory.

The desktop should expose it as:

    Laboratory

not overwhelm users with implementation details.

Show:

    distribution
    status
    health
    workspace
    resources
    toolchain

Advanced diagnostics may show:

    distro
    PID
    mount paths
    process state
    logs

============================================================
# 37. WORKSPACE
============================================================

Workspace is central.

Opening a workspace restores:

    target
    mission
    policy
    world model
    hypotheses
    experiments
    strategies
    evidence
    findings
    notes
    sessions
    timeline
    benchmarks

Implement:

    New Workspace
    Open Workspace
    Recent
    Close
    Recover

============================================================
# 38. NOTEBOOK
============================================================

Build a native research notebook.

Notes can be linked to:

    target
    entity
    hypothesis
    experiment
    finding
    evidence
    strategy

Support:

    rich text
    Markdown import/export where useful
    tags
    backlinks
    timestamps

Do not require a web editor.

============================================================
# 39. SESSION MANAGEMENT
============================================================

Support:

    checkpoints
    restore
    replay
    fork
    compare

A researcher should be able to branch an investigation.

Example:

    Session 1842
       │
       ├── baseline
       │
       ├── hypothesis A
       │      ├── experiment A1
       │      └── experiment A2
       │
       └── hypothesis B
              └── experiment B1

============================================================
# 40. BENCHMARK CENTER
============================================================

Show:

    discovery
    novelty
    critical findings
    validation
    false positives
    time
    experiments
    requests
    information gain
    unknown-space reduction

Support:

    run
    compare
    replay
    export

Do not make unsupported claims about competitors.

============================================================
# 41. AI SYSTEM
============================================================

AI is optional.

DOGE must operate without an AI connection wherever the existing
algorithmic system supports the capability.

Providers should be abstracted.

Support:

    No AI
    Local model
    OpenAI-compatible local endpoint
    OpenRouter
    future providers

The AI layer may assist with:

    hypothesis generation
    semantic analysis
    source explanation
    research summarization
    concept proposal
    strategy proposals
    report generation

AI output is a proposal.

AI output is NOT authoritative truth.

============================================================
# 42. AI INSPECTOR
============================================================

Show:

    provider
    model
    role
    request
    response
    latency
    token usage where available
    accepted/rejected
    downstream effect

This allows the researcher to understand exactly where AI participated.

============================================================
# 43. LLM-FREE MODE
============================================================

Provide:

    ALGORITHMIC ONLY

The UI must explicitly show:

    AI: OFF

    DOGE CORE: ACTIVE

Do not pretend a capability is algorithmic if it actually requires an AI
provider.

============================================================
# 44. CONTEXTUAL AI ASSISTANT
============================================================

Do NOT make the AI assistant a giant ChatGPT clone.

The assistant should be contextual.

If the researcher selects:

    finding

then the AI receives finding context.

If they select:

    hypothesis

then the AI receives hypothesis context.

If they select:

    experiment

then it receives experiment context.

Context must be selected intentionally.

Do not dump the entire database into every model request.

============================================================
# 45. COMMAND PALETTE
============================================================

Ctrl+Shift+P

Native command palette.

Commands:

    New Mission
    Open Workspace
    Start Research
    Pause
    Resume
    Stop
    Inspect Frontier
    Open World Model
    Open Surface
    Open Terminal
    Open Finding
    Replay Evidence
    Fork Session
    Compare Strategies
    Run Benchmark
    Open Environment
    Change AI Provider
    Toggle Operator Mode
    Toggle Scientist Mode
    Settings

Fuzzy search.

Keyboard navigation.

============================================================
# 46. KEYBOARD-FIRST DESIGN
============================================================

Security researchers should be able to operate DOGE primarily from the
keyboard.

Implement sensible shortcuts for:

    command palette
    terminal
    search
    navigation
    mission controls
    workspace
    findings

Do not create unnecessary shortcut conflicts.

============================================================
# 47. APPLICATION SEARCH
============================================================

Ctrl+P or equivalent should search across:

    targets
    endpoints
    findings
    hypotheses
    experiments
    evidence
    notes
    sessions
    concepts

Example:

    > H-184

returns:

    hypothesis
    related experiments
    evidence
    findings
    world nodes
    notes

This should feel like IDE-grade search.

============================================================
# 48. RIGHT-SIDE INSPECTOR
============================================================

The inspector is contextual.

Selecting anything should update it.

Target:

    status
    technologies
    scope
    evidence

Hypothesis:

    confidence
    evidence
    experiments
    contradictions

Experiment:

    objective
    cost
    risk
    result
    evidence

Finding:

    severity
    validation
    proof
    impact

World node:

    relationships
    provenance
    confidence

============================================================
# 49. BOTTOM DRAWER
============================================================

Bottom drawer:

    Terminal
    Events
    Logs
    Approvals

Tabs.

Resizable.

Collapsible.

The user should be able to keep the terminal visible while researching.

============================================================
# 50. APPROVAL CENTER
============================================================

Create a dedicated approval interface.

When an operation requires approval:

    show operation
    target
    reason
    risk
    scope
    expected effect
    policy

Controls:

    Approve
    Reject
    Inspect

Never hide approval requests.

Never allow the frontend alone to authorize them.

============================================================
# 51. SECURITY MODEL
============================================================

DOGE itself must be treated as security-sensitive software.

Implement:

    strict IPC authentication where appropriate
    process isolation
    scope validation
    path validation
    command validation
    policy enforcement
    safe serialization
    secure secret handling
    safe logging

The UI is untrusted input.

The Go core remains authoritative.

============================================================
# 52. SECRETS
============================================================

Never expose credentials in:

    UI logs
    terminal logs
    screenshots
    events
    source
    Git
    reports unless explicitly requested

Use secure Windows credential storage where appropriate.

The UI should show:

    Configured

not:

    actual credential

============================================================
# 53. FILE SYSTEM
============================================================

Protect workspace boundaries.

Validate:

    paths
    symlinks
    workspace roots
    imported artifacts

Prevent accidental operations outside intended workspace.

============================================================
# 54. OFFLINE OPERATION
============================================================

DOGE Desktop itself must work completely offline.

Offline means:

    no cloud backend
    no CDN
    no browser
    no remote UI
    no telemetry requirement
    no online license dependency

The user should be able to take DOGE into:

    air-gapped
    isolated
    laboratory
    restricted

environments.

AI may be absent.

============================================================
# 55. GRAPHICS
============================================================

Do not use web canvas.

Use native Windows graphics.

For simple views:

    WinUI Canvas

For large graphs:

    Composition / DirectX / GPU-backed rendering

Evaluate performance.

Do not introduce a massive dependency merely to draw a graph.

============================================================
# 56. TERMINAL GRAPHICS
============================================================

The terminal must support:

    ANSI
    colors
    cursor
    resize
    interactive programs
    shell state

Use ConPTY.

Do not fake terminal behavior with a multiline text control.

============================================================
# 57. APPLICATION THEME
============================================================

DOGE is dark-first.

Create a coherent theme.

Base:

    obsidian
    dark blue-black

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

Use restrained glow.

Do not create a stereotypical "hacker movie" interface.

Professional first.

============================================================
# 58. VISUAL HIERARCHY
============================================================

Important:

    research state
    frontier
    hypothesis
    experiment
    finding

Secondary:

    runtime
    resource usage
    event stream

Tertiary:

    raw logs
    implementation diagnostics

Do not let telemetry overwhelm research.

============================================================
# 59. ANIMATION
============================================================

Use native transitions where useful.

Animation should communicate:

    discovery
    state change
    progress
    finding
    navigation

Avoid:

    constant pulsing
    excessive glow
    unnecessary particle effects
    distracting animations

Provide reduced-motion support.

============================================================
# 60. LONG-RUNNING RESEARCH
============================================================

DOGE may run:

    minutes
    hours
    days

The UI must remain responsive.

Persist state continuously.

Show:

    elapsed time
    progress
    recent changes
    discoveries
    remaining uncertainty
    frontier
    strategy evolution

============================================================
# 61. RECOVERY
============================================================

Handle:

    UI crash
    DOGE Core crash
    WSL crash
    tool crash
    AI provider failure
    network failure
    interrupted experiment
    power loss

Never mark incomplete operations as successful.

On restart:

    recover workspace
    reconnect to core
    recover session
    identify incomplete operations
    allow safe recovery

============================================================
# 62. PERFORMANCE
============================================================

The application must remain responsive.

Avoid:

    UI-thread blocking
    giant synchronous queries
    rendering entire datasets
    unbounded event history in memory

Use:

    async operations
    virtualization
    caching
    incremental updates
    background workers
    pagination

============================================================
# 63. DESKTOP PROCESS MODEL
============================================================

Design for:

    DOGE.exe

and optionally:

    DOGE Core process

depending on the existing runtime architecture.

Preferred conceptual model:

    DOGE.exe
       │
       ├── Native UI
       │
       └── connects to
              │
              ▼
          DOGE Core
              │
              ▼
            WSL2

If separating the core into a separate process materially improves
reliability, do so.

The desktop must be able to recover from core failure.

============================================================
# 64. CORE ↔ DESKTOP LIFECYCLE
============================================================

Startup:

    DOGE.exe
       ↓
    initialize UI
       ↓
    start/connect DOGE Core
       ↓
    initialize runtime
       ↓
    verify WSL
       ↓
    load workspace
       ↓
    READY

Shutdown:

    UI shutdown
       ↓
    gracefully stop desktop
       ↓
    preserve research state
       ↓
    core shutdown if owned by desktop

Do not lose research state.

============================================================
# 65. MULTI-WINDOW DESIGN
============================================================

Consider native windows for:

    terminal
    finding detail
    evidence replay
    world model
    benchmark comparison

Do not implement this unless it improves workflow.

The primary application should remain coherent.

============================================================
# 66. SYSTEM INTEGRATION
============================================================

Use Windows-native capabilities where useful:

    clipboard
    file dialogs
    notifications
    system tray
    application lifecycle
    file associations
    jump lists where appropriate
    native menus
    drag/drop
    keyboard shortcuts

DOGE should feel like a Windows application.

============================================================
# 67. FILE ASSOCIATIONS
============================================================

Consider a DOGE workspace extension:

    .doge

Double-click:

    project.doge

should open DOGE and load the workspace.

Only implement after workspace format is stable.

============================================================
# 68. INSTALLER
============================================================

Build:

    DOGE-Setup.exe

Installer should provide:

    DOGE.exe
    desktop shortcut
    Start Menu entry
    optional PATH integration
    optional .doge association

Do not require PowerShell to launch DOGE.

============================================================
# 69. DEVELOPMENT VS PRODUCTION
============================================================

Development:

    Visual Studio
    dotnet
    Go toolchain

Production:

    DOGE.exe

The production application must not depend on development servers.

No:

    npm start
    localhost
    browser
    web server

============================================================
# 70. TESTING
============================================================

Build tests for:

    desktop startup
    IPC
    reconnect
    workspace loading
    mission lifecycle
    event propagation
    graph data
    findings
    evidence
    terminal lifecycle
    WSL integration
    environment detection
    recovery
    policy enforcement

Maintain existing:

    go test ./...

Do not break existing DOGE tests.

============================================================
# 71. IPC TESTING
============================================================

Test:

    connect
    disconnect
    reconnect
    malformed message
    unknown message
    version mismatch
    timeout
    cancellation
    event delivery
    stream delivery
    concurrent requests

============================================================
# 72. NATIVE UI TESTING
============================================================

Test:

    startup
    workspace
    mission creation
    mission start
    pause
    resume
    stop
    navigation
    graph
    terminal
    findings
    evidence
    settings
    command palette
    Operator/Scientist
    restart/recovery

============================================================
# 73. ACCESSIBILITY
============================================================

Use:

    keyboard navigation
    focus indicators
    accessible names
    readable contrast
    scalable text
    reduced motion

============================================================
# 74. NO FAKE DATA
============================================================

This is mandatory.

Do not display:

    fake vulnerabilities
    fake targets
    fake ports
    fake CPU
    fake WSL status
    fake findings
    fake AI activity
    fake graph nodes

unless explicitly running:

    Demo Mode
    Test Mode
    Benchmark Fixture

Production UI must reflect actual DOGE state.

============================================================
# 75. NO FAKE AUTONOMY
============================================================

Do not animate:

    "AI thinking"

while nothing is happening.

Every displayed autonomous action must correspond to actual research state.

If DOGE is idle:

    show idle.

If DOGE is blocked:

    show blocked.

If DOGE is waiting for approval:

    show approval required.

============================================================
# 76. PRODUCT DIFFERENTIATION
============================================================

DOGE must be different from conventional security products.

The core workflow is:

    OBSERVE
       ↓
    MODEL
       ↓
    IDENTIFY UNCERTAINTY
       ↓
    BUILD FRONTIER
       ↓
    HYPOTHESIZE
       ↓
    DESIGN EXPERIMENT
       ↓
    POLICY CHECK
       ↓
    EXECUTE
       ↓
    OBSERVE
       ↓
    VALIDATE
       ↓
    UPDATE WORLD MODEL
       ↓
    LEARN
       ↓
    CONTINUE

The application must make this visible.

============================================================
# 77. DOGE AS A RESEARCH INSTRUMENT
============================================================

DOGE should feel like:

    microscope
    laboratory
    notebook
    terminal
    graph engine
    experiment manager
    evidence system

combined into one workstation.

The researcher should be able to understand the entire investigation
without opening five unrelated tools.

============================================================
# 78. DO NOT TURN THE HOME SCREEN INTO A SCANNER DASHBOARD
============================================================

The screenshot contains:

    findings counters
    scan status
    quick scan
    deep recon
    exploit path

These can exist.

But they are secondary.

The central experience should become:

    CURRENT RESEARCH

not:

    CURRENT SCAN

For example:

    Research Frontier:
        8 unresolved regions

    Current Hypothesis:
        H-184

    Current Experiment:
        E-421

    World Model:
        842 entities

    Evidence:
        1,241 artifacts

    Validated Findings:
        4

============================================================
# 79. RESEARCH WORKSPACE
============================================================

The most important screen should visually combine:

    frontier
    world model
    hypothesis
    experiment
    timeline

Example:

┌──────────────────────────────────────────────────────────────────┐
│ RESEARCH MISSION                                                 │
│ authorized.example                                               │
├───────────────────────┬───────────────────────────┬──────────────┤
│ FRONTIER              │ WORLD MODEL               │ INSPECTOR    │
│                       │                           │              │
│ HIGH                  │       ○──────○            │ H-184        │
│ Auth state            │      /        \           │              │
│ Cache boundary        │    ○            ○         │              │
│ Workflow              │     \          /          │ confidence   │
│                       │       ○──────○             │ 0.81        │
│ MEDIUM                │                           │              │
│ Timing                │                           │ evidence     │
│ State sync            │                           │ 7            │
├───────────────────────┴───────────────────────────┴──────────────┤
│ CURRENT EXPERIMENT                                               │
│ E-421                                                           │
│ Information gain 0.84   Novelty 0.72   Risk 0.14               │
├──────────────────────────────────────────────────────────────────┤
│ TERMINAL / EVENTS                                                │
└──────────────────────────────────────────────────────────────────┘

============================================================
# 80. RESEARCH TIMELINE
============================================================

Make the entire mission navigable as a timeline.

Example:

    00:00 Mission
    00:02 Surface discovery
    00:07 World model
    00:11 anomaly
    00:12 hypothesis
    00:15 experiment
    00:18 falsified
    00:21 new hypothesis
    00:26 validation
    00:28 finding

Clicking an event should reveal exactly what happened.

============================================================
# 81. STRATEGY VIEW
============================================================

Show the current research strategy.

Display:

    strategy ID
    objective
    active researchers
    current frontier
    resource allocation
    recent outcomes
    success
    failures
    learned preferences

Do not expose internal implementation details unnecessarily.

============================================================
# 82. LEARNING VIEW
============================================================

Show:

    learned strategies
    failed strategies
    successful strategies
    concepts
    target-specific knowledge
    generalized knowledge
    benchmark improvements

Make provenance visible.

============================================================
# 83. CROSS-TARGET KNOWLEDGE
============================================================

When supported by DOGE Core, show:

    transferred concept
    source target
    destination target
    abstraction
    confidence
    provenance

Do not expose credentials or target-sensitive information.

============================================================
# 84. BENCHMARKING
============================================================

DOGE must measure itself.

Show:

    discovery rate
    novel discovery rate
    critical discovery rate
    time to discovery
    time to validation
    requests per finding
    experiments per finding
    information gain
    false positives
    coverage
    unknown-space reduction
    adaptation after failure
    cross-session learning

Never claim superiority without measurement.

============================================================
# 85. RESEARCHER EXPERIENCE
============================================================

The application should save the researcher from repetitive work.

Examples:

    automatic observation capture
    automatic endpoint indexing
    evidence linking
    finding provenance
    timeline construction
    session persistence
    world-model updates
    command history
    contextual notes
    report generation
    experiment replay

The researcher should spend time:

    thinking
    investigating
    validating

rather than:

    copying logs
    organizing screenshots
    manually tracking endpoints
    manually connecting evidence
    rebuilding context

============================================================
# 86. SAFETY
============================================================

DOGE is for explicitly authorized security research.

The implementation must preserve:

    deterministic scope
    authorization
    policy
    resource limits
    risk controls
    approval gates
    validation

Do not implement mechanisms intended to bypass:

    authorization
    access controls
    scope
    approval
    safety mechanisms

All autonomous execution remains bounded by the DOGE policy system.

============================================================
# 87. IMPORTANT ARCHITECTURAL RULE
============================================================

Never allow the native UI to become the authority.

Architecture:

    UI
      ↓
    command
      ↓
    IPC
      ↓
    DOGE Core
      ↓
    policy
      ↓
    execution

NOT:

    UI
      ↓
    direct shell
      ↓
    target

============================================================
# 88. RESEARCH ENGINE REMAINS HEADLESS
============================================================

The Go research engine must be capable of running without the desktop.

This preserves:

    CLI
    benchmarks
    CI
    automated testing
    headless research
    future Linux deployment

Desktop is an interface.

DOGE Core is the system.

============================================================
# 89. MULTI-PLATFORM FUTURE
============================================================

The immediate target is Windows.

Do not sacrifice Windows UX merely to achieve theoretical portability.

However, keep DOGE Core platform-independent where practical.

Future:

    Windows desktop
    Linux desktop
    headless server
    research laboratory

The Windows desktop should be excellent first.

============================================================
# 90. DOCUMENTATION
============================================================

Create/update:

    desktop architecture document
    IPC protocol document
    build instructions
    developer setup
    packaging instructions
    architecture diagram
    UI architecture
    recovery model
    security model

============================================================
# 91. IMPLEMENTATION METHOD
============================================================

DO NOT blindly generate the whole project in one giant pass.

FIRST:

    inspect repository

THEN:

    map existing architecture

THEN:

    identify reusable code

THEN:

    design desktop boundary

THEN:

    implement native shell

THEN:

    implement IPC

THEN:

    connect runtime

THEN:

    expose research state

THEN:

    build UI surfaces

THEN:

    integrate terminal

THEN:

    implement graph

THEN:

    implement evidence/findings

THEN:

    implement AI

THEN:

    implement tray/notifications

THEN:

    package

At every stage:

    compile
    test
    inspect
    fix
    continue

============================================================
# 92. DO NOT STOP AT THE PLAN
============================================================

You are not being asked merely to tell me how to build DOGE.

You are being asked to BUILD IT.

After inspecting the repository:

    implement the architecture.

Create the required source files.

Write the actual production code.

Wire the components together.

Compile it.

Run tests.

Fix compilation errors.

Fix runtime errors.

Continue until the implemented system is coherent.

Do not leave:

    TODO

    placeholder

    fake implementation

    "implement later"

for core functionality that you have been asked to build.

If something genuinely cannot be implemented because a dependency or
existing subsystem is missing, document exactly why and implement the
strongest correct boundary possible.

============================================================
# 93. CODE QUALITY
============================================================

Write production-quality code.

Avoid:

    giant files
    god classes
    global state
    duplicated logic
    UI logic inside the Go research engine
    research logic inside C#
    unsafe command construction
    hidden background operations

Use:

    interfaces
    dependency injection where appropriate
    typed models
    cancellation
    async programming
    structured logging
    error propagation
    tests

============================================================
# 94. C# QUALITY
============================================================

Use modern C#.

Prefer:

    async/await
    nullable reference types
    records where appropriate
    MVVM
    dependency injection
    cancellation tokens
    strongly typed IPC messages

Keep ViewModels testable.

Do not place research logic in code-behind.

============================================================
# 95. GO QUALITY
============================================================

Follow idiomatic Go.

Keep:

    context.Context
    cancellation
    interfaces
    structured errors
    deterministic policy
    tests

Do not contaminate the Go core with Windows UI dependencies.

============================================================
# 96. IPC CONTRACT
============================================================

Create a formal contract.

Version:

    v1

Define:

    handshake
    authentication
    requests
    responses
    events
    streams
    errors
    cancellation

Examples:

    GetStatus
    GetWorkspace
    CreateMission
    StartMission
    PauseMission
    ResumeMission
    StopMission
    GetFrontier
    GetHypotheses
    GetExperiments
    GetWorldModel
    GetFindings
    GetEvidence
    GetTimeline
    ExecuteTerminal
    GetEnvironment
    GetToolchain
    GetAIProviders

============================================================
# 97. EVENT CONTRACT
============================================================

Events:

    MissionStarted
    MissionPaused
    MissionResumed
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

The desktop should update from events rather than repeatedly polling.

============================================================
# 98. NATIVE SEARCH
============================================================

Search must be fast.

Implement application-wide search across DOGE objects.

Search:

    target
    host
    endpoint
    hypothesis
    experiment
    finding
    evidence
    concept
    note
    session

============================================================
# 99. OFFLINE AI
============================================================

If a local model exists:

    connect directly.

If OpenRouter is configured:

    connect only when requested/configured.

If neither exists:

    DOGE continues using its algorithmic capabilities.

The application should never fail because an AI provider is unavailable.

============================================================
# 100. FINAL PRODUCT TEST
============================================================

When finished, perform this mental test:

A professional security researcher installs DOGE.

They double-click:

    DOGE.exe

No terminal opens.

No browser opens.

No webpage opens.

A real Windows desktop application appears.

They create:

    Security Research Workspace

They configure an explicitly authorized target.

They create a mission.

They press:

    START RESEARCH

DOGE initializes its laboratory.

The user sees:

    target
    scope
    research frontier
    world model
    current hypothesis
    current experiment
    evidence
    terminal
    timeline

DOGE conducts authorized research through the existing core.

The user can:

    inspect decisions
    use the terminal
    inspect the world model
    inspect hypotheses
    replay experiments
    inspect evidence
    review findings
    pause autonomy
    take control
    change AI provider
    continue without AI
    recover sessions
    compare strategies
    generate reports

The whole thing feels like:

    one coherent security workstation.

NOT:

    ten tools glued together.

============================================================
# 101. FINAL DEFINITION OF DONE
============================================================

[ ] DOGE.exe exists

[ ] Native Windows desktop application

[ ] WinUI 3

[ ] C#/.NET desktop layer

[ ] Go DOGE Core preserved

[ ] No HTML

[ ] No CSS

[ ] No JavaScript

[ ] No TypeScript

[ ] No React

[ ] No Electron

[ ] No Tauri

[ ] No Wails

[ ] No WebView

[ ] No browser dependency for UI

[ ] No localhost UI dependency

[ ] No CDN

[ ] Offline UI

[ ] Native IPC

[ ] Windows Named Pipes

[ ] Workspace system

[ ] Mission system

[ ] Operator mode

[ ] Scientist mode

[ ] Research Frontier

[ ] Hypotheses

[ ] Experiments

[ ] Decision Inspector

[ ] Native World Model graph

[ ] Surface visualization

[ ] Native WSL terminal

[ ] ConPTY integration

[ ] Findings

[ ] Evidence Studio

[ ] Evidence Replay

[ ] Timeline

[ ] Autonomy Center

[ ] Approval Center

[ ] Environment Center

[ ] AI provider system

[ ] LLM-free mode

[ ] System tray

[ ] Native notifications

[ ] Command palette

[ ] Keyboard-first workflow

[ ] Notebook

[ ] Session recovery

[ ] Benchmarks

[ ] Crash recovery

[ ] Deterministic policy

[ ] Explicit authorization boundaries

[ ] Existing Go tests remain green

[ ] Desktop tests pass

[ ] Production build works

[ ] Installer works

[ ] No fake production data

[ ] No fake autonomy

============================================================
# 102. THE STANDARD
============================================================

Do not optimize for:

    "looks cool"

Optimize for:

    "a security researcher could actually spend their entire workday
     inside this application."

DOGE should reduce cognitive overhead.

The researcher should not have to constantly switch between:

    terminal
    browser
    notes
    scanner
    proxy
    evidence folder
    vulnerability tracker
    graph
    AI chat
    report editor

DOGE should bring these research activities into one coherent environment.

The application should make the researcher's workflow:

    faster
    more observable
    more reproducible
    more organized
    more explainable
    safer
    less repetitive

while keeping the underlying DOGE research engine autonomous and
algorithmically meaningful.

============================================================
# 103. MOST IMPORTANT FINAL RULE
============================================================

BUILD A NATIVE APPLICATION.

Not a website pretending to be an application.

Not a browser pretending to be a desktop.

Not an Electron shell.

Not a Wails shell.

Not an HTML dashboard.

Not a localhost interface.

Build:

                         DOGE.exe

              C# / .NET / WinUI 3

                         │
                    Native IPC
                         │
                         ▼

                    DOGE CORE

                         │
                    WSL2 LAB

                         │
                         ▼

              Authorized Research

The user should be able to forget that there are separate technologies
underneath.

They should simply experience:

                         DOGE

          SECURITY RESEARCH WORKSTATION

Now inspect the existing repository and begin.
```

### One architectural decision I strongly recommend

Don't ask the coding agent to rewrite DOGE from Go into C# just because the UI is C#.

Use the split deliberately:

| Layer                    | Technology                                           | Why                                            |
| ------------------------ | ---------------------------------------------------- | ---------------------------------------------- |
| **Native desktop**       | **C# + WinUI 3**                                     | Best fit for a Windows-first native GUI        |
| **DOGE research engine** | **Go**                                               | Existing engine, concurrency, CLI, portability |
| **Native IPC**           | **Windows Named Pipes**                              | No browser/HTTP dependency                     |
| **Terminal**             | **ConPTY + WSL2**                                    | Real interactive Linux terminal                |
| **World graph**          | **WinUI/Composition/DirectX**                        | Native high-performance visualization          |
| **Storage**              | Existing DOGE persistence + SQLite where appropriate | Durable local workspace                        |
| **AI**                   | Go/C# provider abstraction                           | Local, OpenRouter, or none                     |
| **Packaging**            | Windows executable + installer                       | Actual desktop product                         |

That gives you something much closer to **"VS Code for security research"** architecturally, without copying VS Code's internals.

And importantly, **XAML is fine**. You said no HTML/CSS/web application. XAML is a native Windows UI description language, not a web frontend. The final artifact is still a genuine Windows desktop application.

The really interesting part is that your current Go runtime can remain underneath this whole thing:

```text
                         ┌─────────────────────────┐
                         │        DOGE.exe          │
                         │                         │
                         │  ┌───────────────────┐  │
                         │  │    WinUI 3        │  │
                         │  │                   │  │
                         │  │ Research          │  │
                         │  │ World Model       │  │
                         │  │ Terminal           │  │
                         │  │ Findings           │  │
                         │  │ Evidence           │  │
                         │  │ Frontier           │  │
                         │  └─────────┬─────────┘  │
                         └────────────┼────────────┘
                                      │
                              Named Pipe IPC
                                      │
                         ┌────────────▼────────────┐
                         │       DOGE CORE          │
                         │          Go              │
                         │                          │
                         │ World Model              │
                         │ Research Director        │
                         │ AXIOM / discovery        │
                         │ Experiments              │
                         │ Strategy                 │
                         │ Validation               │
                         │ Evidence                 │
                         │ Policy                   │
                         │ Runtime                  │
                         └────────────┬─────────────┘
                                      │
                                    WSL2
                                      │
                         ┌────────────▼─────────────┐
                         │      DOGE LABORATORY      │
                         │                           │
                         │ tools / source / targets  │
                         └───────────────────────────┘
```

**That is the version of DOGE I would build.** The desktop isn't a skin over the engine. It becomes the **native operating environment through which the researcher experiences the engine**.
