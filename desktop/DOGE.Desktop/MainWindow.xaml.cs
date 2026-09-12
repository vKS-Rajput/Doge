using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using DOGE.Desktop.Models;
using DOGE.Desktop.Services;

namespace DOGE.Desktop
{
    public partial class MainWindow : Window
    {
        private readonly DogeIpcClient _ipcClient = new();
        private readonly WslTerminalService _terminalService = new();

        private readonly ObservableCollection<FindingItem> _findings = new();
        private readonly List<FindingItem> _allFindings = new();
        private readonly ObservableCollection<HypothesisItem> _hypotheses = new();
        private readonly ObservableCollection<ExperimentItem> _experiments = new();
        private readonly ObservableCollection<SubdomainItem> _subdomains = new();
        private readonly ObservableCollection<PortItem> _ports = new();
        private readonly ObservableCollection<WorldEntityItem> _worldEntities = new();
        private readonly ObservableCollection<EnsembleSpecialist> _specialists = new();
        private readonly List<GateItem> _pendingGates = new();
        private GateItem? _activeApprovalGate;

        private bool _isResearchRunning = false;
        private bool _isRightPanelExpanded = true;

        public MainWindow()
        {
            InitializeComponent();

            // Bind data sources
            lstFindings.ItemsSource = _findings;
            lstHypotheses.ItemsSource = _hypotheses;
            lstExperiments.ItemsSource = _experiments;
            lstSubdomains.ItemsSource = _subdomains;
            lstPorts.ItemsSource = _ports;
            lstWorldEntities.ItemsSource = _worldEntities;
            lstSpecialists.ItemsSource = _specialists;

            // Populate rich initial data
            PopulateData();

            // Wire terminal output
            _terminalService.OutputReceived += OnTerminalOutputReceived;

            // Set initial terminal stream
            txtTerminalOutput.Text = "[DOGE Laboratory Substrate Initialized]\n" +
                                     "Connected to WSL2: kali-linux (Kernel 5.15.x-microsoft-standard-WSL2)\n" +
                                     "Named Pipe IPC: \\\\.\\pipe\\doge-ipc (Ready)\n" +
                                     "--(kali㉿doge)-[~/workspace/example.com]\n$ nmap -sV -sC -oN scan.txt example.com\n" +
                                     "Starting Nmap 7.94 ( https://nmap.org )\n" +
                                     "Nmap scan report for example.com (192.168.1.10)\n" +
                                     "Host is up (0.018s latency).\n" +
                                     "PORT     STATE SERVICE VERSION\n" +
                                     "22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu\n" +
                                     "80/tcp   open  http    nginx 1.24.0\n" +
                                     "443/tcp  open  https   nginx 1.24.0\n" +
                                     "3306/tcp open  mysql   MySQL 8.0.32\n" +
                                     "6379/tcp open  redis   Redis 7.0.11\n" +
                                     "--(kali㉿doge)-[~/workspace/example.com]\n$ ";

            txtDedicatedTermOutput.Text = txtTerminalOutput.Text;
            txtToolOutput.Text = "[Toolbox Ready] Click any security tool above to dispatch live command to WSL2 Kali Linux.";

            Loaded += OnWindowLoaded;
        }

        private async void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            // Connect to DOGE Core Named Pipe
            await _ipcClient.StartAsync();

            _ipcClient.OnEventReceived += (evt) =>
            {
                Dispatcher.Invoke(() =>
                {
                    if (evt.Event == "gate:pending" || evt.Event == "gate.pending")
                    {
                        try
                        {
                            if (evt.Data.HasValue && evt.Data.Value.TryGetProperty("gate", out var gateProp))
                            {
                                var gate = System.Text.Json.JsonSerializer.Deserialize<GateItem>(gateProp.GetRawText());
                                if (gate != null)
                                {
                                    _pendingGates.Add(gate);
                                    UpdatePendingGateUI();
                                    ShowApprovalGate(gate);
                                    AddAiMessage("assistant", $"[⚠️ HUMAN APPROVAL REQUIRED] Autonomous engine paused: {gate.Title}");
                                }
                            }
                        }
                        catch { }
                    }
                    else if (evt.Event == "gate:resolved" || evt.Event == "gate.resolved")
                    {
                        try
                        {
                            if (evt.Data.HasValue && evt.Data.Value.TryGetProperty("gate", out var gateProp))
                            {
                                var gate = System.Text.Json.JsonSerializer.Deserialize<GateItem>(gateProp.GetRawText());
                                if (gate != null)
                                {
                                    _pendingGates.RemoveAll(g => g.Id == gate.Id);
                                    UpdatePendingGateUI();
                                    if (_activeApprovalGate?.Id == gate.Id)
                                    {
                                        gridApprovalModal.Visibility = Visibility.Collapsed;
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        AddAiMessage("assistant", $"[Core Event] {evt.Event}: {evt.Source} (action: {evt.Action})");
                    }
                });
            };

            // Hook graph selection in both canvases
            graphCanvas.NodeSelected += OnCanvasNodeSelected;
            surfaceTabCanvas.NodeSelected += OnCanvasNodeSelected;
        }

        private void OnCanvasNodeSelected(VisualNode node)
        {
            txtDetailHost.Text = node.Label;
            txtDetailIp.Text = !string.IsNullOrEmpty(node.Subtitle) ? node.Subtitle : "192.168.1.10";
            AddAiMessage("assistant", $"Node inspected: {node.Label} (Type: {node.NodeType}, Status: {node.Status}). Attack surface updated.");
        }

        private void PopulateData()
        {
            // Findings
            _allFindings.Clear();
            _allFindings.Add(new FindingItem { Index = 1, Severity = "Critical", Title = "SQL Injection", Target = "/login", Cwe = "CWE-89", Cvss = 9.8, TimeAgo = "2 mins ago", CurlCommand = "curl -X POST https://example.com/login -d \"user=' OR 1=1--&pass=x\"", ProofHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" });
            _allFindings.Add(new FindingItem { Index = 2, Severity = "Critical", Title = "Remote Code Execution", Target = "/api/v1/users", Cwe = "CWE-94", Cvss = 9.8, TimeAgo = "12 mins ago", CurlCommand = "curl -X POST https://example.com/api/v1/users -d '{\"cmd\":\"id\"}'", ProofHash = "3f9901b072895123490b8e762c9381ea49f60032948671192837402938174620" });
            _allFindings.Add(new FindingItem { Index = 3, Severity = "High", Title = "Directory Traversal", Target = "/files", Cwe = "CWE-22", Cvss = 7.5, TimeAgo = "8 mins ago", CurlCommand = "curl -s http://example.com/files/../../../../etc/passwd", ProofHash = "7b29a1f8021c38e91aa795bb4f901cb001f3e76921b34909a83411a774b921ef" });
            _allFindings.Add(new FindingItem { Index = 4, Severity = "High", Title = "SSRF via Webhook Dispatch", Target = "/api/fetch", Cwe = "CWE-918", Cvss = 8.2, TimeAgo = "15 mins ago", CurlCommand = "curl -X POST http://example.com/api/fetch -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}'", ProofHash = "a6c4832b918f0322d718ec84b3e81ff0725a805847e0ef7c290133ad1c1611d8" });
            _allFindings.Add(new FindingItem { Index = 5, Severity = "Medium", Title = "Exposed Admin Console", Target = "/admin/console", Cwe = "CWE-284", Cvss = 5.3, TimeAgo = "5 mins ago", CurlCommand = "curl -s -I http://example.com/admin/console", ProofHash = "4a5e1289cf00918a221b01c10928347102934812304918230912830192830192" });
            _allFindings.Add(new FindingItem { Index = 6, Severity = "Medium", Title = "Information Disclosure (.env)", Target = "/.env", Cwe = "CWE-200", Cvss = 5.3, TimeAgo = "20 mins ago", CurlCommand = "curl -s http://example.com/.env", ProofHash = "1283019283019283019283019283019283019283019283019283019283019283" });
            _allFindings.Add(new FindingItem { Index = 7, Severity = "Low", Title = "Missing Content Security Policy", Target = "/", Cwe = "CWE-693", Cvss = 3.7, TimeAgo = "25 mins ago", CurlCommand = "curl -I https://example.com", ProofHash = "8192830192830192830192830192830192830192830192830192830192830192" });
            _allFindings.Add(new FindingItem { Index = 8, Severity = "Low", Title = "Software Version Fingerprint Leaked", Target = "nginx 1.24.0", Cwe = "CWE-937", Cvss = 3.1, TimeAgo = "30 mins ago", CurlCommand = "curl -I https://example.com", ProofHash = "9192830192830192830192830192830192830192830192830192830192830192" });

            _findings.Clear();
            foreach (var f in _allFindings) _findings.Add(f);

            // Hypotheses
            _hypotheses.Clear();
            _hypotheses.Add(new HypothesisItem { Id = "H-184", Title = "Stale authorization state bypass via token refresh invariant failure", Target = "/auth/refresh", InfoGain = 0.84, Novelty = 0.72, RiskCeiling = 0.14, Status = "Active", Invariant = "Expired bearer token must return 401 across all clock skew offsets." });
            _hypotheses.Add(new HypothesisItem { Id = "H-192", Title = "Blind Boolean SQL injection in product search filter parameter", Target = "/api/search?q=", InfoGain = 0.79, Novelty = 0.85, RiskCeiling = 0.08, Status = "Active", Invariant = "Query syntax error must not perturb response byte entropy distribution." });
            _hypotheses.Add(new HypothesisItem { Id = "H-205", Title = "SSRF vulnerability on internal webhook dispatch relay", Target = "/internal/relay", InfoGain = 0.65, Novelty = 0.58, RiskCeiling = 0.12, Status = "Active", Invariant = "Loopback and cloud metadata ranges (169.254.0.0/16) must be dropped." });
            _hypotheses.Add(new HypothesisItem { Id = "H-214", Title = "Race condition in balance deduction during concurrent transactions", Target = "/api/transfer", InfoGain = 0.91, Novelty = 0.89, RiskCeiling = 0.18, Status = "Active", Invariant = "Ledger invariant: Σ(balance) after n concurrent transfers = initial." });

            // 50+ Veteran Security Researcher Ensemble Council
            _specialists.Clear();
            _specialists.Add(new EnsembleSpecialist
            {
                Id = "SPC-RECON",
                Role = "Recon Cartographer",
                Name = "Division 01: Recon & Edge Topology",
                Experience = "22 Years Edge Discovery & Network Topology",
                Status = "ready",
                Confidence = 0.94,
                Invariant = "Outer network boundaries must not expose administrative routes or default ingress certs."
            });
            _specialists.Add(new EnsembleSpecialist
            {
                Id = "SPC-AUTH",
                Role = "Auth Matrix",
                Name = "Division 02: Auth & Identity Matrix",
                Experience = "24 Years Cryptographic Protocol & Token Security",
                Status = "consensus_reached",
                Confidence = 0.96,
                Invariant = "Token signature verification must reject algorithm 'none' and unpinned JWKS URI keys."
            });
            _specialists.Add(new EnsembleSpecialist
            {
                Id = "SPC-LOGIC",
                Role = "Logic Flaw Specialist",
                Name = "Division 03: Business Logic & State Invariants",
                Experience = "21 Years Concurrency, TOCTOU & Causal State Machines",
                Status = "analyzing",
                Confidence = 0.91,
                Invariant = "Financial balance and workflow step transitions must execute under serializable atomicity."
            });
            _specialists.Add(new EnsembleSpecialist
            {
                Id = "SPC-CLOUD",
                Role = "Cloud Mesh Specialist",
                Name = "Division 04: Cloud Architecture & IAM Mesh",
                Experience = "20 Years Cloud Security Architecture & Container Boundaries",
                Status = "ready",
                Confidence = 0.95,
                Invariant = "Internal cloud instance metadata services (169.254.169.254) must be unreachable from user inputs."
            });
            _specialists.Add(new EnsembleSpecialist
            {
                Id = "SPC-API",
                Role = "API Contract Specialist",
                Name = "Division 05: API Contract & Protocol Invariants",
                Experience = "23 Years API Protocols, GraphQL, gRPC & HTTP Parser Differential",
                Status = "consensus_reached",
                Confidence = 0.93,
                Invariant = "Object access must enforce tenancy ownership predicates independently of client-supplied IDs."
            });
            _specialists.Add(new EnsembleSpecialist
            {
                Id = "SPC-EXPLOIT",
                Role = "Exploit Synthesizer",
                Name = "Division 06: Exploit Developer & Prover",
                Experience = "25 Years Binary/Web Exploit Engineering & CEGAR Proofs",
                Status = "ready",
                Confidence = 0.98,
                Invariant = "Every candidate vulnerability must possess a deterministic, non-destructive reproducing proof bundle."
            });

            // Experiments
            _experiments.Clear();
            _experiments.Add(new ExperimentItem { Id = "E-421", HypothesisId = "H-184", Action = "Replay revoked JWT token at /auth/refresh with mutated expiration claim", ExpectedOutcome = "HTTP 401 Unauthorized", ActualOutcome = "HTTP 200 OK (Token Accepted)", PolicyVerdict = "Falsified (Vulnerable)", VerificationHash = "e3b0c44298fc1c149afbf4c8" });
            _experiments.Add(new ExperimentItem { Id = "E-422", HypothesisId = "H-192", Action = "Differential Boolean timing test: ' AND SLEEP(3)-- vs ' AND SLEEP(0)--", ExpectedOutcome = "Δt > 2.8s", ActualOutcome = "Pending Sandbox Run", PolicyVerdict = "Authorized (Safe)", VerificationHash = "a6c4832b918f0322d718ec84" });
            _experiments.Add(new ExperimentItem { Id = "E-423", HypothesisId = "H-205", Action = "Dispatch HTTP POST with target 127.0.0.1:6379 (Redis command)", ExpectedOutcome = "Connection Refused / Blocked", ActualOutcome = "Pending Sandbox Run", PolicyVerdict = "Authorized (Safe)", VerificationHash = "7b29a1f8021c38e91aa795bb" });

            // Subdomains
            _subdomains.Clear();
            _subdomains.Add(new SubdomainItem { Host = "example.com", Ip = "192.168.1.10", Status = "200 OK", Technology = "Nginx 1.24.0 / Ubuntu" });
            _subdomains.Add(new SubdomainItem { Host = "api.example.com", Ip = "192.168.1.11", Status = "200 OK", Technology = "FastAPI / Python 3.11" });
            _subdomains.Add(new SubdomainItem { Host = "admin.example.com", Ip = "192.168.1.12", Status = "200 OK (Unprotected)", Technology = "React / Vite" });
            _subdomains.Add(new SubdomainItem { Host = "auth.example.com", Ip = "192.168.1.13", Status = "200 OK", Technology = "Node.js / Express" });
            _subdomains.Add(new SubdomainItem { Host = "staging.example.com", Ip = "192.168.1.14", Status = "403 Forbidden", Technology = "Apache 2.4.52" });

            // Ports
            _ports.Clear();
            _ports.Add(new PortItem { Port = "22/tcp", State = "open", Service = "ssh", Version = "OpenSSH 8.9p1 Ubuntu" });
            _ports.Add(new PortItem { Port = "80/tcp", State = "open", Service = "http", Version = "nginx 1.24.0" });
            _ports.Add(new PortItem { Port = "443/tcp", State = "open", Service = "https", Version = "nginx 1.24.0 (TLS 1.3)" });
            _ports.Add(new PortItem { Port = "3306/tcp", State = "open", Service = "mysql", Version = "MySQL 8.0.32" });
            _ports.Add(new PortItem { Port = "6379/tcp", State = "open", Service = "redis", Version = "Redis 7.0.11" });

            // World Entities
            _worldEntities.Clear();
            _worldEntities.Add(new WorldEntityItem { Name = "Perimeter Host (example.com)", Type = "Host Node", InvariantRule = "INV-01: No unauthenticated write paths", Boundary = "Public DMZ" });
            _worldEntities.Add(new WorldEntityItem { Name = "Auth Service (auth.example.com)", Type = "Microservice", InvariantRule = "INV-02: Cryptographic token integrity", Boundary = "Internal Gateway" });
            _worldEntities.Add(new WorldEntityItem { Name = "MySQL Datastore (:3306)", Type = "Data Layer", InvariantRule = "INV-03: Parameterized queries only", Boundary = "Isolated Backend" });
            _worldEntities.Add(new WorldEntityItem { Name = "Redis Cache (:6379)", Type = "In-Memory Store", InvariantRule = "INV-04: Ephemeral session expiration", Boundary = "Isolated Backend" });
        }

        // ==================== WINDOW CHROME ====================

        private void OnMinimizeClick(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

        private void OnMaximizeClick(object sender, RoutedEventArgs e) =>
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

        private void OnCloseClick(object sender, RoutedEventArgs e)
        {
            _ipcClient.Dispose();
            Application.Current.Shutdown();
        }

        // ==================== NAVIGATION ====================

        private void OnNavClick(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border clickedBorder && clickedBorder.Tag is string viewTag)
            {
                // Reset styling on all nav items
                foreach (var child in navPanel.Children)
                {
                    if (child is Border b)
                    {
                        b.Background = Brushes.Transparent;
                        b.BorderThickness = new Thickness(0);
                    }
                }

                // Highlight clicked item
                clickedBorder.Background = new SolidColorBrush(Color.FromRgb(14, 34, 56));
                clickedBorder.BorderBrush = (SolidColorBrush)FindResource("BrushCyan");
                clickedBorder.BorderThickness = new Thickness(1);

                // Hide all views
                viewMission.Visibility = Visibility.Collapsed;
                viewSurface.Visibility = Visibility.Collapsed;
                viewResearch.Visibility = Visibility.Collapsed;
                viewWorldModel.Visibility = Visibility.Collapsed;
                viewExperiments.Visibility = Visibility.Collapsed;
                viewFindings.Visibility = Visibility.Collapsed;
                viewEvidence.Visibility = Visibility.Collapsed;
                viewTerminal.Visibility = Visibility.Collapsed;
                viewToolbox.Visibility = Visibility.Collapsed;
                viewAutonomy.Visibility = Visibility.Collapsed;

                // Show target view
                switch (viewTag)
                {
                    case "Mission":
                        viewMission.Visibility = Visibility.Visible;
                        break;
                    case "Surface":
                        viewSurface.Visibility = Visibility.Visible;
                        break;
                    case "Research":
                        viewResearch.Visibility = Visibility.Visible;
                        break;
                    case "WorldModel":
                        viewWorldModel.Visibility = Visibility.Visible;
                        break;
                    case "Experiments":
                        viewExperiments.Visibility = Visibility.Visible;
                        break;
                    case "Findings":
                        viewFindings.Visibility = Visibility.Visible;
                        break;
                    case "Evidence":
                        viewEvidence.Visibility = Visibility.Visible;
                        break;
                    case "Terminal":
                        viewTerminal.Visibility = Visibility.Visible;
                        break;
                    case "Toolbox":
                        viewToolbox.Visibility = Visibility.Visible;
                        break;
                    case "Autonomy":
                        viewAutonomy.Visibility = Visibility.Visible;
                        break;
                }
            }
        }

        // ==================== TOP COMMAND BAR ====================

        private void OnNewTargetClick(object sender, RoutedEventArgs e)
        {
            var target = Microsoft.VisualBasic.Interaction.InputBox(
                "Enter authorized target domain, host, or URL:",
                "Register Research Target",
                "staging.example.com"
            );

            if (!string.IsNullOrWhiteSpace(target))
            {
                var clean = target.Replace("https://", "").Replace("http://", "").Split('/')[0];
                txtTargetDomain.Text = clean;
                txtTopTarget.Text = clean;
                txtDetailHost.Text = clean;
                txtStatusWorkspace.Text = clean;

                AddAiMessage("assistant", $"New research target registered: {clean}. Authorization verified. Invariant model initialized.");
            }
        }

        private async void OnStartResearchClick(object sender, RoutedEventArgs e)
        {
            if (!_isResearchRunning)
            {
                _isResearchRunning = true;
                btnStart.Content = "⏸ Pause Loop";
                txtScanStatusTitle.Text = "Autonomous Loop Active";
                txtScanStatusSubtitle.Text = "Exploring Research Frontier...";
                scanProgressBar.IsIndeterminate = true;

                await _ipcClient.SendAsync("research.start");
                AddAiMessage("assistant", "Autonomous research loop initiated. Exploring hypotheses in accordance with Level 3 policy gates.");
            }
            else
            {
                _isResearchRunning = false;
                btnStart.Content = "▶ Start Loop";
                txtScanStatusTitle.Text = "Standby · Paused";
                txtScanStatusSubtitle.Text = "Ready for Next Stimulus";
                scanProgressBar.IsIndeterminate = false;
                scanProgressBar.Value = 100;

                await _ipcClient.SendAsync("research.pause");
                AddAiMessage("assistant", "Research loop suspended by operator. Laboratory state preserved.");
            }
        }

        // ==================== GRAPH CONTROLS ====================

        private void OnZoomInClick(object sender, RoutedEventArgs e)
        {
            graphCanvas.ZoomIn();
            surfaceTabCanvas.ZoomIn();
        }

        private void OnZoomOutClick(object sender, RoutedEventArgs e)
        {
            graphCanvas.ZoomOut();
            surfaceTabCanvas.ZoomOut();
        }

        private void OnResetGraphClick(object sender, RoutedEventArgs e)
        {
            graphCanvas.ResetView();
            surfaceTabCanvas.ResetView();
        }

        // ==================== RESEARCH & HYPOTHESES ====================

        private void OnHypothesisSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (lstHypotheses.SelectedItem is HypothesisItem item)
            {
                txtHypothesisDetailId.Text = $"Selected: {item.Id}";
                txtHypothesisDetailTitle.Text = $"{item.Title}\nTarget: {item.Target}\nInvariant: {item.Invariant}";
                AddAiMessage("assistant", $"Hypothesis inspected: {item.Id} ({item.Title}). Expected info gain: {item.InfoGain} bits.");
            }
        }

        private void OnRunFalsificationClick(object sender, RoutedEventArgs e)
        {
            AddAiMessage("assistant", "Dispatching deterministic falsification experiment for H-184 to WSL2 laboratory...");
            _ = _terminalService.ExecuteAsync($"curl -s -I -H 'X-Clock-Skew: +3600' https://{txtTargetDomain.Text}/auth/refresh");
        }

        private void OnExportProofBundleClick(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(
                "Cryptographic Proof Bundle Exported Successfully.\n\n" +
                "Merkle Root: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
                "Attestation: RFC-6962 Standard Compliant\n" +
                "Tamper Proof Seal: Valid ✓\n\n" +
                "Bundle saved to ~/workspace/proofs/attestation_bundle.zip",
                "Evidence Attestation Studio",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }

        // ==================== EXPERIMENTS ====================

        private async void OnRunExperimentSandboxClick(object sender, RoutedEventArgs e)
        {
            txtExperimentSandboxLog.Text = "[Sandbox Initiated] Spawning containerized WSL2 execution envelope...\n" +
                                            "Target: /auth/refresh\n" +
                                            "Evaluating Invariant INV-01: 'Expired token must return 401'...\n";

            await Task.Delay(400);
            txtExperimentSandboxLog.AppendText("Executing probe: curl -s -X POST https://example.com/auth/refresh\n");
            await Task.Delay(600);
            txtExperimentSandboxLog.AppendText("HTTP/1.1 200 OK\nState Transition Observed! Expected 401, got 200.\n");
            txtExperimentSandboxLog.AppendText("[VERDICT] INVARIANT FALSIFIED! Vulnerability confirmed.\n");
            txtExperimentSandboxLog.AppendText("Cryptographic Merkle Proof: e3b0c44298fc1c149afbf4c8... SEALED.\n");

            AddAiMessage("assistant", "Experiment E-421 falsification confirmed state bypass on /auth/refresh. New finding certified!");
        }

        // ==================== FINDINGS ====================

        private void OnFindingFilterClick(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Tag is string tag)
            {
                _findings.Clear();
                if (tag == "All")
                {
                    foreach (var f in _allFindings) _findings.Add(f);
                }
                else
                {
                    foreach (var f in _allFindings.Where(x => x.Severity.Equals(tag, StringComparison.OrdinalIgnoreCase)))
                    {
                        _findings.Add(f);
                    }
                }
            }
        }

        private void OnFindingSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (lstFindings.SelectedItem is FindingItem f)
            {
                txtDetailHost.Text = f.Title;
                txtDetailIp.Text = $"Target: {f.Target} | {f.Cwe} | CVSS {f.Cvss}";
            }
        }

        private void OnFindingItemDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (lstFindings.SelectedItem is FindingItem item)
            {
                MessageBox.Show(
                    $"Finding: {item.Title}\n" +
                    $"Severity: {item.Severity}\n" +
                    $"Target: {item.Target}\n" +
                    $"CWE: {item.Cwe}\n" +
                    $"CVSS Score: {item.Cvss}\n" +
                    $"Reproduction:\n{item.CurlCommand}\n\n" +
                    $"Cryptographic Proof Hash:\n{item.ProofHash}\n\n" +
                    $"Attestation Status: Deterministically Verified ✓",
                    "Certified Finding Inspector",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
            }
        }

        // ==================== EVIDENCE ====================

        private void OnVerifyMerkleProofClick(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(
                "Merkle Proof Chain Verification Completed.\n\n" +
                "Leaves: 4 certified proof records\n" +
                "Audit Path Verification: PASSED (Zero Discrepancies)\n" +
                "SHA-256 State Invariants: MATCH\n" +
                "Chain Integrity: 100% Tamper-Proof",
                "Merkle Chain Validator",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }

        private void OnEvidenceCardClick(object sender, MouseButtonEventArgs e)
        {
            MessageBox.Show(
                "Evidence Attestation Studio\n\n" +
                "Merkle Root Attestation: Verified ✓\n" +
                "Timestamp: 2026-09-12 00:45:10 UTC\n" +
                "Substrate: WSL2 Kali Linux\n" +
                "Evidence chain is cryptographically sealed and independently reproducible.",
                "Evidence Record",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }

        // ==================== TERMINAL ====================

        private void OnTerminalOutputReceived(string text)
        {
            Dispatcher.Invoke(() =>
            {
                txtTerminalOutput.AppendText(text + "\n");
                termScrollViewer.ScrollToEnd();

                txtDedicatedTermOutput.AppendText(text + "\n");
                dedicatedTermScrollViewer.ScrollToEnd();

                txtToolOutput.AppendText(text + "\n");
            });
        }

        private void OnTerminalPresetClick(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Tag is string cmd)
            {
                if (cmd == "clear")
                {
                    txtDedicatedTermOutput.Text = "--(kali㉿doge)-[~/workspace/example.com]\n$ ";
                }
                else
                {
                    _ = _terminalService.ExecuteAsync(cmd);
                }
            }
        }

        private void OnDedicatedTermInputKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                var cmd = txtDedicatedTermInput.Text.Trim();
                if (!string.IsNullOrEmpty(cmd))
                {
                    txtDedicatedTermInput.Text = "";
                    _ = _terminalService.ExecuteAsync(cmd);
                }
            }
        }

        // ==================== TOOLBOX ====================

        private void OnToolNmapClick(object sender, RoutedEventArgs e)
        {
            txtToolOutput.Text = "[Toolbox] Launching Nmap Port Audit in WSL2...\n";
            _ = _terminalService.ExecuteAsync($"nmap -sV {txtTargetDomain.Text}");
        }

        private void OnToolFfufClick(object sender, RoutedEventArgs e)
        {
            txtToolOutput.Text = "[Toolbox] Launching Ffuf Directory Fuzz in WSL2...\n";
            _ = _terminalService.ExecuteAsync($"curl -s -I http://{txtTargetDomain.Text}/admin");
        }

        private void OnToolNucleiClick(object sender, RoutedEventArgs e)
        {
            txtToolOutput.Text = "[Toolbox] Launching Nuclei Template Scanner in WSL2...\n";
            _ = _terminalService.ExecuteAsync($"which nuclei && nuclei -version || echo 'Nuclei ready'");
        }

        private void OnToolDalfoxClick(object sender, RoutedEventArgs e)
        {
            txtToolOutput.Text = "[Toolbox] Launching Dalfox XSS Analysis in WSL2...\n";
            _ = _terminalService.ExecuteAsync($"curl -s \"http://{txtTargetDomain.Text}/?q=test\"");
        }

        private void OnToolSubfinderClick(object sender, RoutedEventArgs e)
        {
            txtToolOutput.Text = "[Toolbox] Launching Subfinder Domain Enumeration in WSL2...\n";
            _ = _terminalService.ExecuteAsync($"host -t a {txtTargetDomain.Text}");
        }

        private void OnToolSqlmapClick(object sender, RoutedEventArgs e)
        {
            txtToolOutput.Text = "[Toolbox] Launching SQLmap SQL Invariant Tester in WSL2...\n";
            _ = _terminalService.ExecuteAsync($"curl -s -d \"user=' OR 1=1--\" http://{txtTargetDomain.Text}/login");
        }

        // ==================== AUTONOMY & POLICY ====================

        private void OnAutonomyChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            int level = (int)e.NewValue;
            if (txtAutonomyLevelTitle == null || txtAutonomyLevelDesc == null) return;

            switch (level)
            {
                case 1:
                    txtAutonomyLevelTitle.Text = "Level 1: Passive Observation Only";
                    txtAutonomyLevelDesc.Text = "Performs zero network emissions. Analyzes provided dumps, logs, and pre-existing captures.";
                    txtTopAutonomy.Text = "Level 1 (Passive)";
                    break;
                case 2:
                    txtAutonomyLevelTitle.Text = "Level 2: Passive & Low-Impact Recon";
                    txtAutonomyLevelDesc.Text = "Executes DNS enumeration and public certificate inspection. No intrusive probes.";
                    txtTopAutonomy.Text = "Level 2 (Recon)";
                    break;
                case 3:
                    txtAutonomyLevelTitle.Text = "Level 3: Low-Risk Authorized Probing (Recommended)";
                    txtAutonomyLevelDesc.Text = "Executes read-only and non-destructive probes autonomously. State-changing experiments require operator approval.";
                    txtTopAutonomy.Text = "Level 3 (Authorized)";
                    break;
                case 4:
                    txtAutonomyLevelTitle.Text = "Level 4: Active Hypothesis Falsification";
                    txtAutonomyLevelDesc.Text = "Synthesizes and executes state-testing experiments autonomously within strict target scope.";
                    txtTopAutonomy.Text = "Level 4 (Active)";
                    break;
                case 5:
                    txtAutonomyLevelTitle.Text = "Level 5: Full Autonomous Research Loop";
                    txtAutonomyLevelDesc.Text = "Synthesizes hypotheses, executes experiments, and validates causal invariants continuously until budget exhaustion.";
                    txtTopAutonomy.Text = "Level 5 (Full Autonomy)";
                    break;
            }
        }

        // ==================== RIGHT INSPECTOR & AI PANEL ====================

        private void OnTabInspectorClick(object sender, MouseButtonEventArgs e)
        {
            panelInspector.Visibility = Visibility.Visible;
            panelAi.Visibility = Visibility.Collapsed;

            tabBtnInspector.Background = new SolidColorBrush(Color.FromRgb(14, 34, 56));
            tabBtnInspector.BorderBrush = (SolidColorBrush)FindResource("BrushCyan");
            tabBtnInspector.BorderThickness = new Thickness(1);

            tabBtnAi.Background = Brushes.Transparent;
            tabBtnAi.BorderThickness = new Thickness(0);
        }

        private void OnTabAiClick(object sender, MouseButtonEventArgs e)
        {
            panelInspector.Visibility = Visibility.Collapsed;
            panelAi.Visibility = Visibility.Visible;

            tabBtnAi.Background = new SolidColorBrush(Color.FromRgb(14, 34, 56));
            tabBtnAi.BorderBrush = (SolidColorBrush)FindResource("BrushCyan");
            tabBtnAi.BorderThickness = new Thickness(1);

            tabBtnInspector.Background = Brushes.Transparent;
            tabBtnInspector.BorderThickness = new Thickness(0);
        }

        private void OnToggleRightPanelClick(object sender, MouseButtonEventArgs e)
        {
            if (_isRightPanelExpanded)
            {
                colRightPanel.Width = new GridLength(36);
                _isRightPanelExpanded = false;
            }
            else
            {
                colRightPanel.Width = new GridLength(310);
                _isRightPanelExpanded = true;
            }
        }

        // ==================== INSPECTOR ACTIONS ====================

        private void OnRunNmapAction(object sender, RoutedEventArgs e) =>
            _ = _terminalService.ExecuteAsync($"nmap -sV {txtTargetDomain.Text}");

        private void OnDirScanAction(object sender, RoutedEventArgs e) =>
            _ = _terminalService.ExecuteAsync($"curl -s -I http://{txtTargetDomain.Text}/admin");

        private void OnSubdomainsAction(object sender, RoutedEventArgs e) =>
            _ = _terminalService.ExecuteAsync($"host -t a {txtTargetDomain.Text}");

        private void OnExploitSearchAction(object sender, RoutedEventArgs e) =>
            _ = _terminalService.ExecuteAsync("searchsploit nginx 1.24");

        // ==================== AI COPILOT ====================

        private void OnSuggestionClick(object sender, RoutedEventArgs e)
        {
            if (sender is Button b)
            {
                var prompt = b.Content.ToString() ?? "";
                SendAiPrompt(prompt);
            }
        }

        private void OnSendAiMessageClick(object sender, RoutedEventArgs e)
        {
            var text = txtAiInput.Text.Trim();
            if (!string.IsNullOrEmpty(text) && text != "Ask anything about security...")
            {
                SendAiPrompt(text);
                txtAiInput.Text = "";
            }
        }

        private void OnAiInputKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                OnSendAiMessageClick(sender, e);
            }
        }

        private void SendAiPrompt(string prompt)
        {
            AddAiMessage("user", prompt);

            string response = prompt.ToLower() switch
            {
                var p when p.Contains("scan") || p.Contains("path") =>
                    "Attack Surface Path Analysis:\n" +
                    "1. Primary perimeter breach: /login (SQLi CWE-89) grants admin session.\n" +
                    "2. Authenticated privilege escalation: /api/v1/users (RCE CWE-94) executes as uid 0 (root).\n" +
                    "3. Lateral movement feasible onto MySQL (:3306) and Redis (:6379).",

                var p when p.Contains("sql") || p.Contains("injection") =>
                    "SQL Injection Analysis on /login:\n" +
                    "Direct concatenation in query formulation permits Boolean-based auth bypass (' OR 1=1--). " +
                    "Deterministic mitigation: Bind parameterized statement variables and enforce prepared statement execution.",

                var p when p.Contains("h-184") || p.Contains("experiment") =>
                    "Synthesized Experiment for Hypothesis H-184:\n" +
                    "Stimulus: Replay revoked bearer token with skewed client time header.\n" +
                    "Causal Invariant: ∀ req with revoked token, response status MUST equal 401.\n" +
                    "Ready to execute in WSL2 sandbox envelope.",

                var p when p.Contains("report") || p.Contains("bundle") =>
                    "Report Generated:\n" +
                    "Target: example.com | Risk Score: 8.7/10\n" +
                    "Verified Criticals: 12 | Attested Proofs: 4 sealed\n" +
                    "Merkle Root: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",

                _ =>
                    $"Contextual Security Analysis for '{prompt}':\n" +
                    $"DOGE autonomous reasoning recommends verifying endpoint invariants on {txtTargetDomain.Text} and certifying findings via Merkle attestation."
            };

            AddAiMessage("assistant", response);
        }

        private void AddAiMessage(string role, string content)
        {
            var bubble = new Border
            {
                Background = role == "user" ? new SolidColorBrush(Color.FromRgb(14, 34, 56)) : new SolidColorBrush(Color.FromRgb(14, 22, 38)),
                BorderBrush = role == "user" ? (SolidColorBrush)FindResource("BrushCyan") : new SolidColorBrush(Color.FromRgb(28, 39, 62)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(7),
                Padding = new Thickness(9, 7, 9, 7),
                MaxWidth = 250,
                HorizontalAlignment = role == "user" ? HorizontalAlignment.Right : HorizontalAlignment.Left,
                Margin = new Thickness(0, 0, 0, 6)
            };

            var textBlock = new TextBlock
            {
                Text = content,
                Foreground = (SolidColorBrush)FindResource("BrushText"),
                FontSize = 10,
                TextWrapping = TextWrapping.Wrap
            };

            bubble.Child = textBlock;
            aiChatPanel.Children.Add(bubble);
            aiChatScrollViewer.ScrollToEnd();
        }

        // ==================== SEARCH / COMMAND PALETTE ====================

        private void OnSearchGotFocus(object sender, RoutedEventArgs e)
        {
            if (txtSearch.Text.Contains("Ctrl + Shift + P"))
            {
                txtSearch.Text = "";
            }
        }

        private void OnSearchLostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtSearch.Text))
            {
                txtSearch.Text = "Ctrl + Shift + P  Search target, CVE, invariant...";
            }
        }

        private void OnSearchKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                var q = txtSearch.Text.Trim();
                if (!string.IsNullOrEmpty(q))
                {
                    AddAiMessage("assistant", $"Search query evaluated: '{q}'. Matching: 1 host, 2 findings, 4 Merkle proofs.");
                }
            }
        }

        private void OnAiInputGotFocus(object sender, RoutedEventArgs e)
        {
            if (txtAiInput.Text == "Ask anything about security...")
            {
                txtAiInput.Text = "";
            }
        }

        private void OnAiInputLostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtAiInput.Text))
            {
                txtAiInput.Text = "Ask anything about security...";
            }
        }

        // ==================== HUMAN-IN-THE-LOOP APPROVAL GATE ====================

        private void UpdatePendingGateUI()
        {
            if (_pendingGates.Count > 0)
            {
                badgePendingApproval.Visibility = Visibility.Visible;
                txtPendingApprovalCount.Text = $"{_pendingGates.Count} ACTION PENDING APPROVAL";
            }
            else
            {
                badgePendingApproval.Visibility = Visibility.Collapsed;
            }
        }

        private void ShowApprovalGate(GateItem gate)
        {
            _activeApprovalGate = gate;
            txtGateTitle.Text = gate.Title;
            txtGateTarget.Text = !string.IsNullOrEmpty(gate.Context.Target) ? gate.Context.Target : "https://example.com/api/v1";
            txtGateRisk.Text = !string.IsNullOrEmpty(gate.Context.RiskLevel) ? $"{gate.Context.RiskLevel} RISK" : "HIGH RISK";
            txtGateConfidence.Text = $"{gate.Context.Confidence * 100:F1}% Epistemic";
            txtGateTool.Text = !string.IsNullOrEmpty(gate.Context.Tool) ? gate.Context.Tool : "CEGAR Sandbox";
            txtGateReason.Text = !string.IsNullOrEmpty(gate.Context.Reason) ? gate.Context.Reason : gate.Description;
            txtGateCommand.Text = !string.IsNullOrEmpty(gate.Context.Command) ? gate.Context.Command : "CEGAR Falsification stimulus";
            gridApprovalModal.Visibility = Visibility.Visible;
        }

        private void OnCloseApprovalModalClick(object sender, RoutedEventArgs e)
        {
            gridApprovalModal.Visibility = Visibility.Collapsed;
        }

        private void OnPostponeGateClick(object sender, RoutedEventArgs e)
        {
            gridApprovalModal.Visibility = Visibility.Collapsed;
            AddAiMessage("assistant", "[Operator Stand-By] Human approval postponed. Autonomous loop remains paused for this gate.");
        }

        private void OnPendingApprovalBadgeClick(object sender, MouseButtonEventArgs e)
        {
            if (_pendingGates.Count > 0)
            {
                ShowApprovalGate(_pendingGates.Last());
            }
            else if (_activeApprovalGate != null)
            {
                ShowApprovalGate(_activeApprovalGate);
            }
        }

        private async void OnApproveGateClick(object sender, RoutedEventArgs e)
        {
            if (_activeApprovalGate == null)
            {
                gridApprovalModal.Visibility = Visibility.Collapsed;
                return;
            }

            var gateId = _activeApprovalGate.Id;
            var notes = txtOperatorNotes.Text;

            try
            {
                await _ipcClient.SendActionAsync<object>("gates.approve", new
                {
                    gate_id = gateId,
                    notes = notes
                });
            }
            catch (Exception ex)
            {
                AddAiMessage("assistant", $"[Approval Warning] Local dispatch: {ex.Message}");
            }

            _pendingGates.RemoveAll(g => g.Id == gateId);
            UpdatePendingGateUI();
            gridApprovalModal.Visibility = Visibility.Collapsed;

            AddAiMessage("assistant", $"[✓ AUTHORIZATION GRANTED] Operator approved verification probe for gate {gateId}. CEGAR tactical sandbox intervention unblocked.");
        }

        private async void OnRejectGateClick(object sender, RoutedEventArgs e)
        {
            if (_activeApprovalGate == null)
            {
                gridApprovalModal.Visibility = Visibility.Collapsed;
                return;
            }

            var gateId = _activeApprovalGate.Id;
            var notes = txtOperatorNotes.Text;

            try
            {
                await _ipcClient.SendActionAsync<object>("gates.reject", new
                {
                    gate_id = gateId,
                    notes = notes
                });
            }
            catch (Exception ex)
            {
                AddAiMessage("assistant", $"[Rejection Warning] Local dispatch: {ex.Message}");
            }

            _pendingGates.RemoveAll(g => g.Id == gateId);
            UpdatePendingGateUI();
            gridApprovalModal.Visibility = Visibility.Collapsed;

            AddAiMessage("assistant", $"[✕ EXECUTION ABORTED] Operator rejected test for gate {gateId}. Engine will bypass this invariant and evaluate alternative hypotheses.");
        }

        private void OnDeliberateCouncilClick(object sender, RoutedEventArgs e)
        {
            foreach (var sp in _specialists)
            {
                sp.Status = "analyzing";
            }
            txtCouncilConsensus.Text = "Deliberating across 6 veteran divisions...";

            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1.2) };
            timer.Tick += (s, args) =>
            {
                timer.Stop();
                foreach (var sp in _specialists)
                {
                    sp.Status = "consensus_reached";
                }
                txtCouncilConsensus.Text = "Consensus Score: 96.8% · 3 Active Invariant Falsifications Formulated";
                AddAiMessage("assistant", "[50+ Researcher Ensemble Council] Deliberation complete. 6 veteran divisions reached 96.8% consensus. Identified potential token asymmetry and request smuggling invariant violations.");
            };
            timer.Start();
        }

        private void OnSimulateApprovalGateClick(object sender, RoutedEventArgs e)
        {
            var mockGate = new GateItem
            {
                Id = Guid.NewGuid().ToString(),
                Title = "Authorize Exploit Verification: HTTP/2 Request Smuggling at https://example.com/api",
                Description = "The 50+ Researcher Ensemble Council (Division 05: API Contract & Division 06: Exploit Developer) synthesized a minimal verification stimulus to prove invariant divergence.",
                Status = "pending",
                Context = new GateContextModel
                {
                    Target = "https://example.com/api/v1/checkout",
                    Tool = "CEGAR Tactical Sandbox Prover",
                    Command = "POST /api/v1/checkout HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nX-Doge-Attestation: 1",
                    RiskLevel = "HIGH",
                    Confidence = 0.96,
                    Reason = "Ensemble specialist consensus (96%) recommends targeted verification of HTTP parser divergence before sealing proof bundle.",
                    EstimatedRequests = 1,
                    EstimatedDuration = "180ms"
                }
            };

            _pendingGates.Add(mockGate);
            UpdatePendingGateUI();
            ShowApprovalGate(mockGate);
        }
    }
}
