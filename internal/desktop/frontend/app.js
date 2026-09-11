// DOGE Security Research Workstation — Cockpit Engine
// Exact visual implementation matching the native desktop workstation architecture.

(function () {
  'use strict';

  // --- STATE ---
  const state = {
    target: {
      name: 'example.com',
      ip: '192.168.1.10',
      status: 'Active',
      tech: 'Nginx 1.24.0',
      waf: 'Not Detected',
      ports: '80, 443, 22, 3306, 6379',
      os: 'Linux (Ubuntu)',
      location: '🇺🇸 United States',
      riskScore: '8.7 / 10'
    },
    scan: {
      title: 'Deep Recon',
      status: 'Running...',
      percent: 73,
      timer: null
    },
    findings: {
      critical: 12,
      high: 28,
      medium: 47,
      low: 93
    },
    system: {
      wsl: 'kali-linux',
      cpu: '32%',
      ram: '5.1/16 GB',
      disk: '120 GB free'
    },
    activeView: 'dashboard',
    activeVisTab: 'network',
    activeResTab: 'scan',
    zoom: 1.0,
    pan: { x: 0, y: 0 },
    isDragging: false,
    dragStart: { x: 0, y: 0 },
    draggedNode: null,
    terminalHistory: [],
    historyIndex: -1
  };

  // Wails Go binding bridge
  const isWails = window.go && window.go.desktop && window.go.desktop.App;

  // --- ATTACK SURFACE GRAPH DATA ---
  const graphNodes = [
    // Center Target
    { id: 'target', label: 'example.com', sub: '192.168.1.10', x: 0, y: 0, r: 24, type: 'target', color: '#00f0ff' },
    // Left Subdomains
    { id: 'sub1', label: 'mail.example.com', x: -160, y: -90, r: 16, type: 'internal', color: '#00d2df' },
    { id: 'sub2', label: 'dev.example.com', x: -180, y: -25, r: 16, type: 'internal', color: '#00d2df' },
    { id: 'sub3', label: 'api.example.com', x: -170, y: 45, r: 16, type: 'external', color: '#00f0ff' },
    { id: 'sub4', label: 'staging.example.com', x: -140, y: 110, r: 16, type: 'internal', color: '#00d2df' },
    // Right Ports / Services
    { id: 'port80', label: 'Port 80', sub: 'HTTP', x: 160, y: -100, r: 18, type: 'discovered', color: '#00f0ff', port: 80 },
    { id: 'port443', label: 'Port 443', sub: 'HTTPS', x: 180, y: -40, r: 18, type: 'discovered', color: '#00cc88', port: 443 },
    { id: 'port22', label: 'Port 22', sub: 'SSH', x: 175, y: 20, r: 18, type: 'exploitable', color: '#ff7700', port: 22 },
    { id: 'port3306', label: 'Port 3306', sub: 'MySQL', x: 165, y: 80, r: 18, type: 'vulnerable', color: '#ff3366', port: 3306 },
    { id: 'port6379', label: 'Port 6379', sub: 'Redis', x: 140, y: 135, r: 18, type: 'exploitable', color: '#ffcc00', port: 6379 }
  ];

  const graphEdges = [
    { from: 'sub1', to: 'target', color: '#00d2df' },
    { from: 'sub2', to: 'target', color: '#ff3366' }, // vulnerable connection
    { from: 'sub3', to: 'target', color: '#00f0ff' },
    { from: 'sub4', to: 'target', color: '#00d2df' },
    { from: 'target', to: 'port80', color: '#00f0ff' },
    { from: 'target', to: 'port443', color: '#00cc88' },
    { from: 'target', to: 'port22', color: '#ff7700' },
    { from: 'target', to: 'port3306', color: '#ff3366' },
    { from: 'target', to: 'port6379', color: '#ffcc00' }
  ];

  // Particles animating along edges
  const particles = graphEdges.map((e, idx) => ({
    edgeIdx: idx,
    progress: Math.random(),
    speed: 0.005 + Math.random() * 0.005
  }));

  // --- INITIALIZATION ---
  window.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initWindowControls();
    initAttackSurfaceCanvas();
    initQuickActions();
    initAiAssistant();
    initTerminal();
    initTableTabs();
    initVisualizerTabs();
    initGlobalControls();
    initCommandPalette();
    startScanStatusAnimation();

    // Hook backend if Wails runtime available
    if (isWails) {
      window.go.desktop.App.GetStatus().then(updateSystemStatus).catch(() => {});
      window.go.desktop.App.GetEnvironment().then(updateEnvironmentStatus).catch(() => {});
    }
  });

  // --- NAVIGATION RAIL ---
  function initNavigation() {
    const railItems = document.querySelectorAll('.rail-item');
    railItems.forEach(item => {
      item.addEventListener('click', () => {
        railItems.forEach(r => r.classList.remove('active'));
        item.classList.add('active');
        const view = item.getAttribute('data-view');
        state.activeView = view;
        appendTerminalLine(`Switched perspective to: [${view.toUpperCase()}]`);
      });
    });
  }

  // --- NATIVE WINDOW CONTROLS ---
  function initWindowControls() {
    const btnMin = document.getElementById('winMin');
    const btnMax = document.getElementById('winMax');
    const btnClose = document.getElementById('winClose');

    if (btnMin) {
      btnMin.addEventListener('click', () => {
        if (window.runtime && window.runtime.WindowMinimise) window.runtime.WindowMinimise();
      });
    }
    if (btnMax) {
      btnMax.addEventListener('click', () => {
        if (window.runtime && window.runtime.WindowToggleMaximise) window.runtime.WindowToggleMaximise();
      });
    }
    if (btnClose) {
      btnClose.addEventListener('click', () => {
        if (window.runtime && window.runtime.Quit) window.runtime.Quit();
        else window.close();
      });
    }
  }

  // --- ATTACK SURFACE VISUALIZER CANVAS ---
  function initAttackSurfaceCanvas() {
    const canvas = document.getElementById('attackSurfaceCanvas');
    const container = document.getElementById('canvasContainer');
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d');

    function resize() {
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    // Zoom buttons
    document.getElementById('btnZoomIn')?.addEventListener('click', () => {
      state.zoom = Math.min(state.zoom + 0.15, 2.5);
    });
    document.getElementById('btnZoomOut')?.addEventListener('click', () => {
      state.zoom = Math.max(state.zoom - 0.15, 0.5);
    });

    // Mouse drag interaction
    canvas.addEventListener('mousedown', (e) => {
      const rect = canvas.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - canvas.width / 2 - state.pan.x) / state.zoom;
      const mouseY = (e.clientY - rect.top - canvas.height / 2 - state.pan.y) / state.zoom;

      // Check if clicked a node
      for (const node of graphNodes) {
        const dx = mouseX - node.x;
        const dy = mouseY - node.y;
        if (Math.sqrt(dx * dx + dy * dy) <= node.r) {
          state.draggedNode = node;
          selectNode(node);
          return;
        }
      }

      state.isDragging = true;
      state.dragStart = { x: e.clientX - state.pan.x, y: e.clientY - state.pan.y };
    });

    window.addEventListener('mousemove', (e) => {
      if (state.draggedNode) {
        const rect = canvas.getBoundingClientRect();
        state.draggedNode.x = (e.clientX - rect.left - canvas.width / 2 - state.pan.x) / state.zoom;
        state.draggedNode.y = (e.clientY - rect.top - canvas.height / 2 - state.pan.y) / state.zoom;
      } else if (state.isDragging) {
        state.pan.x = e.clientX - state.dragStart.x;
        state.pan.y = e.clientY - state.dragStart.y;
      }
    });

    window.addEventListener('mouseup', () => {
      state.isDragging = false;
      state.draggedNode = null;
    });

    // Render loop
    function render() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.save();
      ctx.translate(canvas.width / 2 + state.pan.x, canvas.height / 2 + state.pan.y);
      ctx.scale(state.zoom, state.zoom);

      // Draw Edges (curved glowing lines)
      graphEdges.forEach((edge, idx) => {
        const fromNode = graphNodes.find(n => n.id === edge.from);
        const toNode = graphNodes.find(n => n.id === edge.to);
        if (!fromNode || !toNode) return;

        ctx.beginPath();
        ctx.moveTo(fromNode.x, fromNode.y);

        // Curved control point
        const cx = (fromNode.x + toNode.x) / 2;
        const cy = (fromNode.y + toNode.y) / 2 + (fromNode.y > toNode.y ? -15 : 15);
        ctx.quadraticCurveTo(cx, cy, toNode.x, toNode.y);

        ctx.strokeStyle = edge.color;
        ctx.lineWidth = edge.color === '#ff3366' ? 2 : 1.2;
        ctx.shadowColor = edge.color;
        ctx.shadowBlur = 8;
        ctx.stroke();
        ctx.shadowBlur = 0;
      });

      // Draw Traveling Particles
      particles.forEach(p => {
        const edge = graphEdges[p.edgeIdx];
        const fromNode = graphNodes.find(n => n.id === edge.from);
        const toNode = graphNodes.find(n => n.id === edge.to);
        if (!fromNode || !toNode) return;

        p.progress += p.speed;
        if (p.progress > 1) p.progress = 0;

        const t = p.progress;
        const cx = (fromNode.x + toNode.x) / 2;
        const cy = (fromNode.y + toNode.y) / 2 + (fromNode.y > toNode.y ? -15 : 15);

        // Quadratic bezier formula
        const px = (1 - t) * (1 - t) * fromNode.x + 2 * (1 - t) * t * cx + t * t * toNode.x;
        const py = (1 - t) * (1 - t) * fromNode.y + 2 * (1 - t) * t * cy + t * t * toNode.y;

        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = edge.color;
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Draw Nodes
      graphNodes.forEach(node => {
        // Outer glow circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r + 3, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(10, 20, 36, 0.9)';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
        ctx.strokeStyle = node.color;
        ctx.lineWidth = node.type === 'target' ? 2.5 : 1.8;
        ctx.shadowColor = node.color;
        ctx.shadowBlur = 10;
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Inner icon / fill
        ctx.fillStyle = node.color;
        ctx.font = node.type === 'target' ? 'bold 11px sans-serif' : '9px monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        if (node.type === 'target') {
          ctx.fillText('🌐', node.x, node.y - 1);
        } else if (node.port) {
          ctx.fillText(node.port, node.x, node.y);
        } else {
          ctx.fillText('💻', node.x, node.y - 1);
        }

        // Labels
        ctx.font = '10px sans-serif';
        ctx.fillStyle = '#e2e8f0';
        ctx.shadowColor = '#000';
        ctx.shadowBlur = 4;
        const labelY = node.y + node.r + 12;
        ctx.fillText(node.label, node.x, labelY);

        if (node.sub) {
          ctx.font = '8px monospace';
          ctx.fillStyle = '#94a3b8';
          ctx.fillText(node.sub, node.x, labelY + 10);
        }
        ctx.shadowBlur = 0;
      });

      ctx.restore();
      requestAnimationFrame(render);
    }
    render();
  }

  function selectNode(node) {
    const nameEl = document.getElementById('detailTargetName');
    const ipEl = document.getElementById('detailTargetIP');
    if (nameEl) nameEl.textContent = node.label;
    if (ipEl && node.sub) ipEl.textContent = node.sub;
    appendTerminalLine(`Inspecting node: ${node.label} (${node.type})`);
  }

  // --- QUICK ACTIONS ---
  function initQuickActions() {
    const bindQA = (id, cmd) => {
      document.getElementById(id)?.addEventListener('click', () => {
        executeTerminalCommand(cmd);
      });
    };

    bindQA('qaRunNmap', 'nmap -sV -sC -p 80,443,22,3306,6379 192.168.1.10');
    bindQA('qaDirectoryScan', 'ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,403');
    bindQA('qaFindSubdomains', 'subfinder -d example.com -silent | httpx -title -status-code');
    bindQA('qaCheckVulns', 'nuclei -u https://example.com -severity critical,high -silent');
    bindQA('qaExploitSearch', 'searchsploit "Nginx 1.24.0"');
    bindQA('qaOpenTerminal', 'clear');
  }

  // --- AI SECURITY ASSISTANT ---
  function initAiAssistant() {
    const chatBody = document.getElementById('aiChatBody');
    const input = document.getElementById('aiInput');
    const sendBtn = document.getElementById('btnSendAI');
    const chips = document.querySelectorAll('.preset-chip');

    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        const prompt = chip.getAttribute('data-prompt');
        sendUserMessage(prompt);
      });
    });

    const handleSend = () => {
      const text = input.value.trim();
      if (!text) return;
      input.value = '';
      sendUserMessage(text);
    };

    sendBtn?.addEventListener('click', handleSend);
    input?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleSend();
    });

    function sendUserMessage(msg) {
      appendChatMessage('user', msg);

      // Generate context-aware response
      setTimeout(() => {
        const reply = generateAiResponse(msg);
        appendChatMessage('assistant', reply);
      }, 500);
    }

    function appendChatMessage(role, text) {
      const msgDiv = document.createElement('div');
      msgDiv.className = `chat-message ${role}`;

      if (role === 'assistant') {
        msgDiv.innerHTML = `
          <div class="chat-avatar">
            <svg viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
          </div>
          <div class="chat-bubble">${formatMarkdown(text)}</div>
        `;
      } else {
        msgDiv.innerHTML = `<div class="chat-bubble">${escapeHtml(text)}</div>`;
      }

      chatBody.appendChild(msgDiv);
      chatBody.scrollTop = chatBody.scrollHeight;
    }

    function generateAiResponse(prompt) {
      const p = prompt.toLowerCase();
      if (p.includes('scan results') || p.includes('analyze')) {
        return `Target **example.com (192.168.1.10)** has 5 open ports. Key findings:\n` +
          `• **SQL Injection** at \`/login\` (Critical — Risk 8.7)\n` +
          `• **RCE** in \`/api/v1/users\` via deserialization\n` +
          `• **MySQL (3306)** & **Redis (6379)** directly exposed without perimeter firewall.\n` +
          `Recommended next step: Run directory fuzzing and verify authentication state machine boundaries.`;
      } else if (p.includes('vulnerability') || p.includes('explain')) {
        return `The SQL injection on \`/login\` allows authentication bypass via Boolean-based blind vectors. The input parameter \`username\` is concatenated directly into SQLite/Postgres query without prepared statements.`;
      } else if (p.includes('suggest') || p.includes('next steps')) {
        return `1. Verify SSRF on \`/api/fetch\` to pivot into internal redis instance (\`127.0.0.1:6379\`).\n` +
          `2. Inspect \`/admin\` panel for default credentials.\n` +
          `3. Seal cryptographic proof bundle with Merkle root hash.`;
      } else if (p.includes('exploit') || p.includes('probe') || p.includes('script')) {
        return `Generating non-destructive verification probe:\n` +
          `\`\`\`bash\ncurl -s -X POST https://example.com/login -d "user=' OR 1=1--" -H "Accept: application/json"\n\`\`\`\n` +
          `Probe sent to sandbox replayer. Status: Response invariant confirmed.`;
      } else if (p.includes('privilege') || p.includes('escalation')) {
        return `Nginx runs under \`www-data\`. Kernel is \`Linux 5.15.0-generic\`. Check for local SUID binaries or sudo misconfigurations on \`/usr/bin/find\` or docker socket permissions in \`/var/run/docker.sock\`.`;
      } else if (p.includes('report')) {
        return `Audit Report generated: **DOGE-Report-example.com-2026.pdf**. Contains 12 Critical/High findings, raw HTTP request/response proofs, and OWASP Top 10 remediation roadmap.`;
      }
      return `I am monitoring the target **example.com**. 47 endpoints mapped, 12 vulnerabilities confirmed. Ask me to analyze specific routes, ports, or findings.`;
    }
  }

  // --- TERMINAL ---
  function initTerminal() {
    const input = document.getElementById('termCliInput');
    const output = document.getElementById('terminalOutput');
    const btnClear = document.getElementById('btnClearTerm');

    btnClear?.addEventListener('click', () => {
      output.innerHTML = `
        <div class="term-line term-prompt">┌──(kali㉿doge)-[~/workspace/example.com]</div>
        <div class="term-input-line">
          <span class="term-cmd">└─$&nbsp;</span>
          <input type="text" class="term-cli-input" id="termCliInput" autofocus autocomplete="off">
        </div>
      `;
      initTerminal();
    });

    input?.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter') {
        const cmd = input.value.trim();
        if (!cmd) return;

        state.terminalHistory.push(cmd);
        state.historyIndex = state.terminalHistory.length;

        // Print entered command
        appendTerminalLine(`└─$ ${cmd}`, 'term-cmd');
        input.value = '';

        // Execute via Wails or local simulation
        if (cmd === 'clear') {
          btnClear.click();
          return;
        }

        if (isWails) {
          try {
            const res = await window.go.desktop.App.ExecuteTerminal(cmd);
            if (res && res.stdout) appendTerminalLine(res.stdout, 'term-info');
            if (res && res.stderr) appendTerminalLine(res.stderr, 'term-prompt');
          } catch (err) {
            appendTerminalLine(`Error: ${err}`, 'term-prompt');
          }
        } else {
          simulateTerminalOutput(cmd);
        }
      }
    });
  }

  function appendTerminalLine(text, cssClass = 'term-info') {
    const output = document.getElementById('terminalOutput');
    if (!output) return;

    const inputLine = output.querySelector('.term-input-line');
    const line = document.createElement('div');
    line.className = `term-line ${cssClass}`;
    line.textContent = text;

    if (inputLine) {
      output.insertBefore(line, inputLine);
    } else {
      output.appendChild(line);
    }
    output.scrollTop = output.scrollHeight;
  }

  function simulateTerminalOutput(cmd) {
    if (cmd.startsWith('nmap')) {
      appendTerminalLine('Starting Nmap 7.94 ( https://nmap.org )...');
      appendTerminalLine('Nmap scan report for example.com (192.168.1.10)');
      appendTerminalLine('Host is up (0.021s latency).');
      appendTerminalLine('PORT     STATE SERVICE VERSION');
      appendTerminalLine('22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu');
      appendTerminalLine('80/tcp   open  http    nginx 1.24.0');
      appendTerminalLine('443/tcp  open  https   nginx 1.24.0');
      appendTerminalLine('3306/tcp open  mysql   MySQL 8.0.32');
      appendTerminalLine('6379/tcp open  redis   Redis 7.0.11');
    } else if (cmd.startsWith('whoami')) {
      appendTerminalLine('kali');
    } else if (cmd.startsWith('uname')) {
      appendTerminalLine('Linux kali-doge 5.15.153.1-microsoft-standard-WSL2 x86_64 GNU/Linux');
    } else {
      appendTerminalLine(`[WSL2:kali-linux] executed: ${cmd}`);
    }
  }

  function executeTerminalCommand(cmd) {
    const input = document.getElementById('termCliInput');
    if (input) {
      input.value = cmd;
      const event = new KeyboardEvent('keydown', { key: 'Enter' });
      input.dispatchEvent(event);
    }
  }

  // --- TABLE TABS ---
  function initTableTabs() {
    const tabs = document.querySelectorAll('.res-tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        state.activeResTab = tab.getAttribute('data-restab');
      });
    });

    const rows = document.querySelectorAll('.findings-table .table-row');
    rows.forEach(row => {
      row.addEventListener('click', () => {
        const title = row.querySelector('.row-title')?.textContent;
        const target = row.querySelector('.row-target')?.textContent;
        appendTerminalLine(`[Finding Triage] ${title} on ${target}`);
      });
    });
  }

  // --- VISUALIZER TABS ---
  function initVisualizerTabs() {
    const tabs = document.querySelectorAll('.vis-tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        state.activeVisTab = tab.getAttribute('data-vistab');
        appendTerminalLine(`Visualizer mode: ${state.activeVisTab}`);
      });
    });
  }

  // --- GLOBAL BUTTONS & DIALOGS ---
  function initGlobalControls() {
    document.getElementById('btnStart')?.addEventListener('click', () => {
      const btnText = document.getElementById('startBtnText');
      if (btnText.textContent === 'Start') {
        btnText.textContent = 'Pause';
        if (isWails) window.go.desktop.App.StartResearch();
        appendTerminalLine('▶ Autonomous Research Loop STARTED');
      } else {
        btnText.textContent = 'Start';
        if (isWails) window.go.desktop.App.PauseResearch();
        appendTerminalLine('⏸ Autonomous Research Loop PAUSED');
      }
    });

    document.getElementById('btnNewTarget')?.addEventListener('click', () => {
      const target = prompt('Enter authorized research target:', 'https://example.com');
      if (target) {
        state.target.name = target.replace(/^https?:\/\//, '');
        document.getElementById('metricTargetName').textContent = state.target.name;
        document.getElementById('detailTargetName').textContent = state.target.name;
        document.getElementById('statusWs').textContent = state.target.name;
        appendTerminalLine(`New target registered: ${target}`);
      }
    });

    document.getElementById('btnReport')?.addEventListener('click', () => {
      alert('Audit Report generated successfully!\nPath: .doge/evidence/report-example.com.pdf');
    });

    document.getElementById('btnQuickScan')?.addEventListener('click', () => {
      executeTerminalCommand('nmap -F -sV 192.168.1.10');
    });

    document.getElementById('btnDeepRecon')?.addEventListener('click', () => {
      executeTerminalCommand('subfinder -d example.com | httpx -status-code -title');
    });

    document.getElementById('btnExploitPath')?.addEventListener('click', () => {
      const tab = document.querySelector('.vis-tab[data-vistab="attackpath"]');
      tab?.click();
    });

    document.getElementById('btnOpenAI')?.addEventListener('click', () => {
      document.getElementById('aiInput')?.focus();
    });
  }

  // --- COMMAND PALETTE ---
  function initCommandPalette() {
    const modal = document.getElementById('paletteModal');
    const input = document.getElementById('paletteSearch');
    const list = document.getElementById('paletteList');
    const trigger = document.getElementById('searchTrigger');

    const commands = [
      { name: 'DOGE: New Research Mission...', key: 'Ctrl+N', action: () => document.getElementById('btnNewTarget').click() },
      { name: 'DOGE: Start Autonomous Research Loop', key: 'F5', action: () => document.getElementById('btnStart').click() },
      { name: 'DOGE: Run Quick Port & Banner Scan', key: 'Ctrl+Shift+Q', action: () => document.getElementById('btnQuickScan').click() },
      { name: 'DOGE: Deep Reconnaissance & Asset Discovery', key: 'Ctrl+Shift+D', action: () => document.getElementById('btnDeepRecon').click() },
      { name: 'DOGE: Open WSL2 Kali Linux Terminal', key: 'Ctrl+`', action: () => document.getElementById('termCliInput').focus() },
      { name: 'DOGE: Inspect Attack Surface Visualizer', key: 'Ctrl+1', action: () => document.querySelector('.rail-item[data-view="world_map"]').click() },
      { name: 'DOGE: Export Certified Audit Report', key: 'Ctrl+E', action: () => document.getElementById('btnReport').click() },
      { name: 'DOGE: Ask AI Security Assistant', key: 'Ctrl+Space', action: () => document.getElementById('btnOpenAI').click() }
    ];

    function openPalette() {
      modal.classList.add('active');
      input.value = '';
      renderPaletteItems(commands);
      input.focus();
    }

    function closePalette() {
      modal.classList.remove('active');
    }

    trigger?.addEventListener('click', openPalette);
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'p' || e.key === 'P')) {
        e.preventDefault();
        openPalette();
      }
      if (e.key === 'Escape' && modal.classList.contains('active')) {
        closePalette();
      }
    });

    modal?.addEventListener('click', (e) => {
      if (e.target === modal) closePalette();
    });

    input?.addEventListener('input', () => {
      const q = input.value.toLowerCase();
      const filtered = commands.filter(c => c.name.toLowerCase().includes(q));
      renderPaletteItems(filtered);
    });

    function renderPaletteItems(items) {
      list.innerHTML = '';
      items.forEach(item => {
        const row = document.createElement('div');
        row.className = 'palette-item';
        row.innerHTML = `<span>${escapeHtml(item.name)}</span><span class="palette-item-key">${item.key}</span>`;
        row.addEventListener('click', () => {
          closePalette();
          item.action();
        });
        list.appendChild(row);
      });
    }
  }

  // --- SCAN STATUS ANIMATION ---
  function startScanStatusAnimation() {
    setInterval(() => {
      if (state.scan.percent < 99) {
        state.scan.percent += 1;
        const pctEl = document.getElementById('metricScanPct');
        const barEl = document.getElementById('metricScanProgressBar');
        if (pctEl) pctEl.textContent = `${state.scan.percent}%`;
        if (barEl) barEl.style.width = `${state.scan.percent}%`;
      }
    }, 4500);
  }

  function updateSystemStatus(status) {
    if (status && status.state) {
      document.getElementById('metricScanState').textContent = status.state;
    }
  }

  function updateEnvironmentStatus(env) {
    if (env && env.WSL) {
      document.getElementById('statusWslDistro').textContent = env.WSL.Distro || 'kali-linux';
    }
  }

  // Utility helpers
  function escapeHtml(str) {
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }

  function formatMarkdown(text) {
    let html = escapeHtml(text);
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/`(.*?)`/g, '<code>$1</code>');
    html = html.replace(/\n/g, '<br>');
    return html;
  }
})();
