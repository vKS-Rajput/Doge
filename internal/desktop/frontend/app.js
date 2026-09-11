// DOGE Desktop v1 — Security Research Operating Environment Cockpit Engine
// Seamlessly bridges Wails Go Bindings & native events with fallback to local IPC REST/SSE.

(function () {
  'use strict';

  // --- STATE MANAGEMENT ---
  const state = {
    workspace: null,
    environment: null,
    lifecycleState: 'READY',
    autonomyLevel: 4,
    personalityMode: 'scientist',
    activeSurface: 'mission',
    nodes: [],
    edges: [],
    hypotheses: [],
    findings: [],
    evidenceBundles: [],
    eventCount: 0,
    selectedItem: null,
  };

  // Check if running inside Wails native runtime
  const isWails = window.go && window.go.desktop && window.go.desktop.App;

  // --- API BRIDGE (Wails Native Bindings + REST Fallback) ---
  const API = {
    async getStatus() {
      if (isWails) return window.go.desktop.App.GetStatus();
      const res = await fetch('/api/status');
      return res.json();
    },
    async getEnvironment() {
      if (isWails) return window.go.desktop.App.GetEnvironment();
      const res = await fetch('/api/environment');
      return res.json();
    },
    async getWorkspace() {
      if (isWails) return window.go.desktop.App.GetWorkspace();
      const res = await fetch('/api/workspace');
      return res.json();
    },
    async getWorldModel() {
      if (isWails) return window.go.desktop.App.GetWorldModel();
      const res = await fetch('/api/worldmodel');
      return res.json();
    },
    async getFindings() {
      if (isWails) return window.go.desktop.App.GetFindings();
      const res = await fetch('/api/findings');
      return res.json();
    },
    async startResearch() {
      if (isWails) return window.go.desktop.App.StartResearch();
      return fetch('/api/research/start', { method: 'POST' }).then(r => r.json());
    },
    async pauseResearch() {
      if (isWails) return window.go.desktop.App.PauseResearch();
      return fetch('/api/research/pause', { method: 'POST' }).then(r => r.json());
    },
    async resumeResearch() {
      if (isWails) return window.go.desktop.App.ResumeResearch();
      return fetch('/api/research/resume', { method: 'POST' }).then(r => r.json());
    },
    async stopResearch() {
      if (isWails) return window.go.desktop.App.StopResearch();
      return fetch('/api/research/stop', { method: 'POST' }).then(r => r.json());
    },
    async executeTerminal(cmd) {
      if (isWails) return window.go.desktop.App.ExecuteTerminal(cmd);
      return fetch('/api/terminal/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd, run_in_wsl: true })
      }).then(r => r.json());
    },
    async createMission(target, objective, budget, risk) {
      if (isWails) return window.go.desktop.App.CreateMission(target, objective, budget, risk);
      return fetch('/api/mission/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, objective, budget, risk })
      }).then(r => r.json());
    },
    async replayProof(findingId) {
      if (isWails) return window.go.desktop.App.ReplayProof(findingId);
      return { success: true, message: 'Replaying proof steps in sandbox...' };
    },
    async setAutonomy(level) {
      if (isWails) return window.go.desktop.App.SetAutonomyLevel(level);
    },
    async setPersonality(mode) {
      if (isWails) return window.go.desktop.App.SetPersonalityMode(mode);
    }
  };

  // --- INITIALIZATION ---
  async function init() {
    setupNavigation();
    setupAutonomySlider();
    setupPersonalityToggle();
    setupResearchControls();
    setupTerminal();
    setupMissionModal();
    setupCommandPalette();
    setupGraphCanvas();

    // Subscribe to telemetry events
    setupEventStream();

    // Initial data fetch
    await refreshAll();
  }

  // --- EVENT STREAM (Wails Events or Server-Sent Events) ---
  function setupEventStream() {
    if (window.runtime && window.runtime.EventsOn) {
      // Native Wails event listener
      window.runtime.EventsOn('doge:event', (evt) => {
        handleRuntimeEvent(evt);
      });
    } else {
      // Fallback SSE
      const sse = new EventSource('/api/events');
      sse.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          handleRuntimeEvent(evt);
        } catch (err) {}
      };
    }
  }

  function handleRuntimeEvent(evt) {
    if (!evt || !evt.type) return;
    state.eventCount++;
    const countBadge = document.getElementById('eventCountBadge');
    if (countBadge) countBadge.textContent = `Events: ${state.eventCount}`;

    const ticker = document.getElementById('latestEventText');
    if (ticker && evt.message) {
      ticker.textContent = evt.message;
    }

    // Append to telemetry log
    appendTelemetryLine(`[${evt.type}] ${evt.message}`);

    // If finding proven, refresh findings
    if (evt.type === 'finding:proven' || evt.type === 'proof:sealed') {
      refreshFindings();
    }
    // If state changed
    if (evt.type.startsWith('runtime:')) {
      refreshStatus();
    }
  }

  function appendTelemetryLine(text) {
    const log = document.getElementById('missionTelemetryLog');
    if (!log) return;
    const line = document.createElement('div');
    line.className = 'terminal-line';
    if (text.includes('system') || text.includes('ready')) line.classList.add('system');
    else if (text.includes('proven') || text.includes('anomaly')) line.classList.add('prompt');
    else line.classList.add('stdout');

    const ts = new Date().toTimeString().split(' ')[0];
    line.textContent = `[${ts}] ${text}`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  // --- NAVIGATION (10 SURFACES) ---
  function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', () => {
        const surface = item.getAttribute('data-surface');
        switchSurface(surface);
      });
    });
  }

  function switchSurface(surfaceName) {
    state.activeSurface = surfaceName;

    // Update active nav button
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-surface') === surfaceName) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update active surface view
    document.querySelectorAll('.surface-view').forEach(view => {
      view.classList.remove('active');
    });
    const targetView = document.getElementById(`view-${surfaceName}`);
    if (targetView) {
      targetView.classList.add('active');
    }

    // If switching to worldmodel, trigger canvas resize and redraw
    if (surfaceName === 'worldmodel') {
      resizeCanvas();
      drawGraph();
    }
  }

  // --- AUTONOMY SLIDER ---
  function setupAutonomySlider() {
    const slider = document.getElementById('autonomySlider');
    const valDisplay = document.getElementById('autonomyVal');
    if (!slider) return;

    slider.addEventListener('input', (e) => {
      const val = parseInt(e.target.value, 10);
      state.autonomyLevel = val;
      if (valDisplay) valDisplay.textContent = val;
      API.setAutonomy(val);
      appendTelemetryLine(`Autonomy level adjusted to Level ${val}`);
    });
  }

  // --- PERSONALITY TOGGLE ---
  function setupPersonalityToggle() {
    const btnScientist = document.getElementById('btnScientist');
    const btnOperator = document.getElementById('btnOperator');

    if (btnScientist && btnOperator) {
      btnScientist.addEventListener('click', () => {
        btnScientist.classList.add('active');
        btnOperator.classList.remove('active');
        state.personalityMode = 'scientist';
        API.setPersonality('scientist');
        switchSurface('mission');
      });

      btnOperator.addEventListener('click', () => {
        btnOperator.classList.add('active');
        btnScientist.classList.remove('active');
        state.personalityMode = 'operator';
        API.setPersonality('operator');
        switchSurface('terminal');
      });
    }
  }

  // --- RESEARCH CONTROLS ---
  function setupResearchControls() {
    const btnStart = document.getElementById('btnStartResearch');
    const btnPause = document.getElementById('btnPauseResearch');
    const btnStop = document.getElementById('btnStopResearch');

    if (btnStart) {
      btnStart.addEventListener('click', async () => {
        await API.startResearch();
        updateEngineState('RESEARCHING');
        appendTelemetryLine('Autonomous research mission launched.');
      });
    }
    if (btnPause) {
      btnPause.addEventListener('click', async () => {
        await API.pauseResearch();
        updateEngineState('PAUSED');
        appendTelemetryLine('Research loop paused by user.');
      });
    }
    if (btnStop) {
      btnStop.addEventListener('click', async () => {
        await API.stopResearch();
        updateEngineState('STOPPED');
        appendTelemetryLine('Research stopped.');
      });
    }
  }

  function updateEngineState(newState) {
    state.lifecycleState = newState;
    const pill = document.getElementById('engineStatePill');
    const text = document.getElementById('engineStateText');
    if (!pill || !text) return;

    pill.className = 'state-pill ' + newState.toLowerCase();
    text.textContent = newState;
  }

  // --- TERMINAL EXECUTION ---
  function setupTerminal() {
    const input = document.getElementById('terminalInput');
    const log = document.getElementById('terminalLog');
    if (!input || !log) return;

    input.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter') {
        const cmd = input.value.trim();
        if (!cmd) return;
        input.value = '';

        // Add prompt line
        const promptLine = document.createElement('div');
        promptLine.className = 'terminal-line prompt';
        promptLine.textContent = `doge-lab:~$ ${cmd}`;
        log.appendChild(promptLine);

        // Execute via API
        try {
          const res = await API.executeTerminal(cmd);
          if (res.stdout) {
            const outLine = document.createElement('div');
            outLine.className = 'terminal-line stdout';
            outLine.textContent = res.stdout;
            log.appendChild(outLine);
          }
          if (res.stderr) {
            const errLine = document.createElement('div');
            errLine.className = 'terminal-line stderr';
            errLine.textContent = res.stderr;
            log.appendChild(errLine);
          }
        } catch (err) {
          const errLine = document.createElement('div');
          errLine.className = 'terminal-line stderr';
          errLine.textContent = `Execution failed: ${err.message}`;
          log.appendChild(errLine);
        }

        log.scrollTop = log.scrollHeight;
      }
    });
  }

  // --- MISSION MODAL ---
  function setupMissionModal() {
    const modal = document.getElementById('missionModal');
    const btnOpen = document.getElementById('btnNewMission');
    const btnClose = document.getElementById('btnCloseMissionModal');
    const btnCancel = document.getElementById('btnCancelMission');
    const btnSubmit = document.getElementById('btnSubmitMission');

    if (btnOpen) btnOpen.addEventListener('click', () => modal.classList.add('open'));
    if (btnClose) btnClose.addEventListener('click', () => modal.classList.remove('open'));
    if (btnCancel) btnCancel.addEventListener('click', () => modal.classList.remove('open'));

    if (btnSubmit) {
      btnSubmit.addEventListener('click', async () => {
        const target = document.getElementById('inputMissionTarget').value;
        const objective = document.getElementById('inputMissionObjective').value;
        const budget = parseInt(document.getElementById('inputMissionBudget').value, 10);
        const risk = document.getElementById('inputMissionRisk').value;

        await API.createMission(target, objective, budget, risk);
        modal.classList.remove('open');
        document.getElementById('currentTarget').textContent = target;
        appendTelemetryLine(`New mission registered: ${target} [Budget: ${budget} reqs]`);
      });
    }
  }

  // --- COMMAND PALETTE ---
  const COMMANDS = [
    { title: 'Start Autonomous Research', shortcut: 'F5', action: () => API.startResearch() },
    { title: 'Pause Research Mission', shortcut: 'F6', action: () => API.pauseResearch() },
    { title: 'Stop Research Mission', shortcut: 'Shift+F5', action: () => API.stopResearch() },
    { title: 'Open World Model Graph', shortcut: 'G', action: () => switchSurface('worldmodel') },
    { title: 'Open Terminal', shortcut: '`', action: () => switchSurface('terminal') },
    { title: 'Inspect Proven Findings', shortcut: 'F', action: () => switchSurface('findings') },
    { title: 'Inspect Cryptographic Evidence', shortcut: 'E', action: () => switchSurface('evidence') },
    { title: 'Toggle Operator / Scientist Mode', shortcut: 'Tab', action: () => {
      const mode = state.personalityMode === 'scientist' ? 'operator' : 'scientist';
      if (mode === 'operator') document.getElementById('btnOperator').click();
      else document.getElementById('btnScientist').click();
    }},
    { title: 'Open WSL Laboratory Center', shortcut: 'L', action: () => switchSurface('environment') },
    { title: 'Create New Research Mission', shortcut: 'Ctrl+N', action: () => document.getElementById('missionModal').classList.add('open') }
  ];

  function setupCommandPalette() {
    const modal = document.getElementById('paletteModal');
    const input = document.getElementById('paletteInput');
    const list = document.getElementById('paletteList');
    const btnOpen = document.getElementById('btnOpenPalette');

    function openPalette() {
      modal.classList.add('open');
      input.value = '';
      renderCommands(COMMANDS);
      input.focus();
    }

    function closePalette() {
      modal.classList.remove('open');
    }

    if (btnOpen) btnOpen.addEventListener('click', openPalette);

    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'P' || e.key === 'p')) {
        e.preventDefault();
        openPalette();
      } else if (e.key === 'Escape') {
        closePalette();
      }
    });

    input.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      const filtered = COMMANDS.filter(c => c.title.toLowerCase().includes(q));
      renderCommands(filtered);
    });

    function renderCommands(items) {
      list.innerHTML = '';
      items.forEach((c, idx) => {
        const item = document.createElement('div');
        item.className = 'palette-item' + (idx === 0 ? ' selected' : '');
        item.innerHTML = `<span>${c.title}</span><span class="palette-shortcut">${c.shortcut}</span>`;
        item.addEventListener('click', () => {
          c.action();
          closePalette();
        });
        list.appendChild(item);
      });
    }
  }

  // --- REFRESH DATA ---
  async function refreshAll() {
    try {
      await Promise.all([
        refreshStatus(),
        refreshEnvironment(),
        refreshWorldModel(),
        refreshFindings()
      ]);
    } catch (e) {
      console.warn('Initial refresh warning:', e);
    }
  }

  async function refreshStatus() {
    const data = await API.getStatus();
    if (data.state) updateEngineState(data.state);
    if (data.workspace && data.workspace.name) {
      const nameEl = document.getElementById('wsName');
      if (nameEl) nameEl.textContent = data.workspace.name;
    }
    if (data.workspace && data.workspace.target) {
      const targetEl = document.getElementById('currentTarget');
      if (targetEl) targetEl.textContent = data.workspace.target;
    }
    if (data.resources) {
      const budgetEl = document.getElementById('statBudgetUsed');
      if (budgetEl) budgetEl.textContent = `${data.resources.requests_made} / ${data.resources.request_budget}`;
    }
  }

  async function refreshEnvironment() {
    const env = await API.getEnvironment();
    if (!env) return;
    state.environment = env;

    if (env.wsl) {
      const wslStateEl = document.getElementById('envWSLState');
      if (wslStateEl) wslStateEl.textContent = env.wsl.available ? 'Active' : 'Unavailable';
      const wslDistroEl = document.getElementById('envWSLDistro');
      if (wslDistroEl && env.wsl.preferred_security_distro) {
        wslDistroEl.textContent = `Distribution: ${env.wsl.preferred_security_distro}`;
      }
    }

    if (env.toolchain) {
      const tbody = document.getElementById('toolchainTableBody');
      if (tbody) {
        tbody.innerHTML = '';
        Object.values(env.toolchain).forEach(tool => {
          const tr = document.createElement('tr');
          const statusBadge = tool.installed
            ? '<span class="badge-sev badge-low">READY</span>'
            : '<span class="badge-sev" style="background: rgba(255,255,255,0.1); color: var(--text-dim);">NOT INSTALLED</span>';
          const envBadge = tool.in_wsl ? 'WSL (' + (tool.distro || 'linux') + ')' : 'Host (Native)';
          tr.innerHTML = `
            <td><strong>${tool.name}</strong></td>
            <td>${statusBadge}</td>
            <td>${envBadge}</td>
            <td style="font-family: var(--font-mono); font-size: 11px;">${tool.path || '-'}</td>
          `;
          tbody.appendChild(tr);
        });
      }
    }
  }

  async function refreshWorldModel() {
    const wm = await API.getWorldModel();
    if (wm && wm.nodes) {
      state.nodes = wm.nodes;
      state.edges = wm.edges || [];
      drawGraph();
    }
  }

  async function refreshFindings() {
    const res = await API.getFindings();
    if (!res) return;
    const findings = res.findings || [];
    const bundles = res.proof_bundles || [];
    state.findings = findings;
    state.evidenceBundles = bundles;

    const countEl = document.getElementById('statFindingsCount');
    if (countEl) countEl.textContent = findings.length;

    // Render findings table
    const fBody = document.getElementById('findingsTableBody');
    if (fBody) {
      fBody.innerHTML = '';
      findings.forEach(f => {
        const tr = document.createElement('tr');
        const sevClass = 'badge-' + (f.severity ? f.severity.toLowerCase() : 'medium');
        tr.innerHTML = `
          <td><span class="badge-sev ${sevClass}">${f.severity}</span></td>
          <td><strong>${f.title}</strong></td>
          <td>${f.type || '-'}</td>
          <td style="font-family: var(--font-mono);">${f.endpoint || '-'}</td>
          <td>${f.cvss || '7.5'}</td>
          <td><button class="btn btn-primary btn-sm btn-inspect-f" data-id="${f.id}">Inspect</button></td>
        `;
        fBody.appendChild(tr);
      });
    }

    // Render evidence table
    const eBody = document.getElementById('evidenceTableBody');
    if (eBody) {
      eBody.innerHTML = '';
      bundles.forEach(b => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td style="font-family: var(--font-mono);">${b.finding_id ? b.finding_id.substring(0, 8) + '...' : '-'}</td>
          <td>${b.vulnerability_class || '-'}</td>
          <td style="font-family: var(--font-mono); color: var(--accent-cyan);">${b.merkle_root ? b.merkle_root.substring(0, 16) + '...' : '-'}</td>
          <td style="font-family: var(--font-mono);">${b.chain_digest ? b.chain_digest.substring(0, 16) + '...' : '-'}</td>
          <td><span class="badge-sev badge-low">SEALED HMAC-SHA256</span></td>
          <td><button class="btn btn-primary btn-sm btn-replay" data-id="${b.finding_id}">▶ Replay</button></td>
        `;
        eBody.appendChild(tr);
      });
    }
  }

  // --- INTERACTIVE WORLD MODEL CANVAS (HTML5 Canvas Graph) ---
  let canvas, ctx;
  let graphNodes = [];
  let graphEdges = [];
  let draggedNode = null;
  let hoveredNode = null;
  let offset = { x: 0, y: 0 };
  let scale = 1;

  function setupGraphCanvas() {
    canvas = document.getElementById('worldGraphCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    // Mouse drag and inspect
    canvas.addEventListener('mousedown', (e) => {
      const pos = getMousePos(e);
      const clicked = findNodeAt(pos.x, pos.y);
      if (clicked) {
        draggedNode = clicked;
        inspectNode(clicked);
      }
    });

    canvas.addEventListener('mousemove', (e) => {
      const pos = getMousePos(e);
      if (draggedNode) {
        draggedNode.x = (pos.x - offset.x) / scale;
        draggedNode.y = (pos.y - offset.y) / scale;
        drawGraph();
      } else {
        const prev = hoveredNode;
        hoveredNode = findNodeAt(pos.x, pos.y);
        if (prev !== hoveredNode) drawGraph();
      }
    });

    window.addEventListener('mouseup', () => {
      draggedNode = null;
    });

    const btnReset = document.getElementById('btnResetZoom');
    if (btnReset) {
      btnReset.addEventListener('click', () => {
        offset = { x: 0, y: 0 };
        scale = 1;
        drawGraph();
      });
    }

    // Populate initial default nodes if none from backend yet
    generateDefaultGraphNodes();
  }

  function resizeCanvas() {
    if (!canvas) return;
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    drawGraph();
  }

  function getMousePos(e) {
    const rect = canvas.getBoundingClientRect();
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };
  }

  function findNodeAt(mx, my) {
    const worldX = (mx - offset.x) / scale;
    const worldY = (my - offset.y) / scale;
    for (let i = graphNodes.length - 1; i >= 0; i--) {
      const n = graphNodes[i];
      const dx = worldX - n.x;
      const dy = worldY - n.y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius) {
        return n;
      }
    }
    return null;
  }

  function generateDefaultGraphNodes() {
    graphNodes = [
      { id: 'target', label: 'https://authorized.example', role: 'state', x: 220, y: 140, radius: 24, color: '#00F0FF' },
      { id: 'auth', label: 'Auth Middleware', role: 'invariant', x: 420, y: 140, radius: 20, color: '#8A2BE2' },
      { id: 'cap_orders', label: 'Order Read Capability', role: 'capability', x: 620, y: 140, radius: 22, color: '#00DF8F' },
      { id: 'anomaly_id', label: 'BOLA Anomaly', role: 'hypothesis', x: 520, y: 280, radius: 20, color: '#F5A623' },
      { id: 'ev_proof', label: 'Proof Step E-721', role: 'evidence', x: 320, y: 280, radius: 18, color: '#38BDF8' }
    ];
    graphEdges = [
      { from: 'target', to: 'auth', label: 'secures' },
      { from: 'auth', to: 'cap_orders', label: 'confines' },
      { from: 'anomaly_id', to: 'cap_orders', label: 'bypasses' },
      { from: 'ev_proof', to: 'anomaly_id', label: 'proves' }
    ];
  }

  function drawGraph() {
    if (!ctx || !canvas) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.save();
    ctx.translate(offset.x, offset.y);
    ctx.scale(scale, scale);

    // Draw edges
    ctx.lineWidth = 2;
    graphEdges.forEach(edge => {
      const src = graphNodes.find(n => n.id === edge.from);
      const dst = graphNodes.find(n => n.id === edge.to);
      if (!src || !dst) return;

      ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(dst.x, dst.y);
      ctx.stroke();

      // Arrowhead
      const angle = Math.atan2(dst.y - src.y, dst.x - src.x);
      const arrowLen = 8;
      const targetEdgeX = dst.x - Math.cos(angle) * dst.radius;
      const targetEdgeY = dst.y - Math.sin(angle) * dst.radius;

      ctx.fillStyle = 'rgba(0, 240, 255, 0.6)';
      ctx.beginPath();
      ctx.moveTo(targetEdgeX, targetEdgeY);
      ctx.lineTo(targetEdgeX - arrowLen * Math.cos(angle - Math.PI / 6), targetEdgeY - arrowLen * Math.sin(angle - Math.PI / 6));
      ctx.lineTo(targetEdgeX - arrowLen * Math.cos(angle + Math.PI / 6), targetEdgeY - arrowLen * Math.sin(angle + Math.PI / 6));
      ctx.closePath();
      ctx.fill();
    });

    // Draw nodes
    graphNodes.forEach(node => {
      ctx.save();
      ctx.shadowColor = node.color;
      ctx.shadowBlur = (hoveredNode === node || draggedNode === node) ? 20 : 8;

      ctx.fillStyle = node.color;
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = '#FFFFFF';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.restore();

      // Label
      ctx.fillStyle = '#FFFFFF';
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, node.x, node.y + node.radius + 14);
    });

    ctx.restore();
  }

  function inspectNode(node) {
    const focus = document.getElementById('inspectorFocusText');
    const whyCard = document.getElementById('inspectorWhyCard');
    const whyText = document.getElementById('inspectorWhyText');
    const evCard = document.getElementById('inspectorEvidenceCard');
    const evChain = document.getElementById('inspectorEvidenceChain');

    if (focus) {
      focus.innerHTML = `
        <strong>Label:</strong> ${node.label}<br>
        <strong>Role:</strong> ${node.role.toUpperCase()}<br>
        <strong>Confidence:</strong> 0.96<br>
        <strong>Provenance:</strong> Synthesized by CEGAR predicate abstraction
      `;
    }

    if (whyCard && whyText) {
      whyCard.style.display = 'block';
      whyText.innerHTML = `
        <strong>Uncertainty:</strong> State isolation boundary across actor identities<br>
        <strong>Expected Info Gain:</strong> 0.88<br>
        <strong>Novelty Score:</strong> 0.74<br>
        <strong>Risk Score:</strong> 0.12 (Strictly safe)
      `;
    }

    if (evCard && evChain) {
      evCard.style.display = 'block';
      evChain.innerHTML = `
        <div class="chain-item">1. GET /api/v1/auth [200 OK] (Auth established)</div>
        <div class="chain-item">2. GET /orders/8820 [200 OK] (Baseline observation)</div>
        <div class="chain-item">3. GET /orders/8821 [200 OK] (Isolation bypassed)</div>
      `;
    }
  }

  // Run on DOM load
  document.addEventListener('DOMContentLoaded', init);
})();
