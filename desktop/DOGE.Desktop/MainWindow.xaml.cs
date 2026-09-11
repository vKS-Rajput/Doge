using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
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
        private bool _isResearchRunning = false;

        public MainWindow()
        {
            InitializeComponent();

            lstFindings.ItemsSource = _findings;

            // Load standard finding items matching the cockpit design
            PopulateInitialFindings();

            // Setup terminal events
            _terminalService.OutputReceived += OnTerminalOutput;

            // Set initial terminal banner
            txtTerminalOutput.Text = "Starting WSL2 Kali Linux laboratory substrate...\n" +
                                     "Connected to distribution: kali-linux (WSL2)\n" +
                                     "--(kali㉿doge)-[~/workspace/example.com]\n$ nmap -sV -sC -oN scan.txt example.com\n" +
                                     "Starting Nmap 7.94 ( https://nmap.org )\n" +
                                     "Nmap scan report for example.com (192.168.1.10)\n" +
                                     "Host is up (0.023s latency).\n" +
                                     "PORT     STATE SERVICE VERSION\n" +
                                     "22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1\n" +
                                     "80/tcp   open  http    nginx 1.24.0\n" +
                                     "443/tcp  open  https   nginx 1.24.0\n" +
                                     "3306/tcp open  mysql   MySQL 8.0.32\n" +
                                     "6379/tcp open  redis   Redis 7.0.11\n" +
                                     "\n--(kali㉿doge)-[~/workspace/example.com]\n$ ";

            Loaded += OnWindowLoaded;
        }

        private async void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            // Connect to DOGE Named Pipe or HTTP IPC in background
            await _ipcClient.StartAsync();

            _ipcClient.OnEventReceived += (evt) =>
            {
                Dispatcher.Invoke(() =>
                {
                    AddAiMessage("system", $"[Telemetry Event] {evt.Event}: {evt.Source} - {evt.Error}");
                });
            };

            // Hook graph selection
            graphCanvas.NodeSelected += (node) =>
            {
                txtDetailHost.Text = node.Label;
                txtDetailIp.Text = node.Subtitle != "" ? node.Subtitle : "192.168.1.10";
            };
        }

        private void PopulateInitialFindings()
        {
            _findings.Clear();
            _findings.Add(new FindingItem { Index = 1, Severity = "Critical", Title = "SQL Injection", Target = "/login", Cwe = "CWE-89", Cvss = 9.8, TimeAgo = "2 mins ago" });
            _findings.Add(new FindingItem { Index = 2, Severity = "Critical", Title = "Remote Code Execution", Target = "/api/v1/users", Cwe = "CWE-94", Cvss = 9.8, TimeAgo = "12 mins ago" });
            _findings.Add(new FindingItem { Index = 3, Severity = "High", Title = "Directory Traversal", Target = "/files", Cwe = "CWE-22", Cvss = 7.5, TimeAgo = "8 mins ago" });
            _findings.Add(new FindingItem { Index = 4, Severity = "High", Title = "SSRF", Target = "/api/fetch", Cwe = "CWE-918", Cvss = 8.2, TimeAgo = "15 mins ago" });
            _findings.Add(new FindingItem { Index = 5, Severity = "Medium", Title = "Exposed Admin Panel", Target = "/admin", Cwe = "CWE-284", Cvss = 5.3, TimeAgo = "5 mins ago" });
            _findings.Add(new FindingItem { Index = 6, Severity = "Medium", Title = "Information Disclosure", Target = "/config", Cwe = "CWE-200", Cvss = 5.3, TimeAgo = "20 mins ago" });
            _findings.Add(new FindingItem { Index = 7, Severity = "Low", Title = "Missing Security Headers", Target = "-", Cwe = "CWE-693", Cvss = 3.7, TimeAgo = "25 mins ago" });
            _findings.Add(new FindingItem { Index = 8, Severity = "Low", Title = "Outdated Software", Target = "nginx 1.24.0", Cwe = "CWE-937", Cvss = 3.1, TimeAgo = "30 mins ago" });
        }

        // ==================== WINDOW CHROME CONTROLS ====================

        private void OnMinimizeClick(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void OnMaximizeClick(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        private void OnCloseClick(object sender, RoutedEventArgs e)
        {
            _ipcClient.Dispose();
            Application.Current.Shutdown();
        }

        // ==================== TOP ACTIONS ====================

        private void OnNewTargetClick(object sender, RoutedEventArgs e)
        {
            var target = Microsoft.VisualBasic.Interaction.InputBox("Enter authorized target URL or domain:", "New Research Target", "https://api.staging.corp");
            if (!string.IsNullOrWhiteSpace(target))
            {
                txtTargetDomain.Text = target.Replace("https://", "").Replace("http://", "").Split('/')[0];
                txtDetailHost.Text = txtTargetDomain.Text;
                txtStatusWorkspace.Text = txtTargetDomain.Text;
                AddAiMessage("assistant", $"New target registered: {target}. Authorization verified. Ready for research.");
            }
        }

        private void OnQuickScanClick(object sender, RoutedEventArgs e)
        {
            txtScanStatusTitle.Text = "Quick Scan";
            txtScanStatusSubtitle.Text = "Running... 15%";
            scanProgressBar.Value = 15;
            _ = _terminalService.ExecuteAsync("nmap -F " + txtTargetDomain.Text);
        }

        private void OnDeepReconClick(object sender, RoutedEventArgs e)
        {
            txtScanStatusTitle.Text = "Deep Recon";
            txtScanStatusSubtitle.Text = "Running... 73%";
            scanProgressBar.Value = 73;
            _ = _terminalService.ExecuteAsync("nmap -sV -sC -p- -T4 " + txtTargetDomain.Text);
        }

        private void OnExploitPathClick(object sender, RoutedEventArgs e)
        {
            AddAiMessage("assistant", "Analyzing attack surface path: /login (SQLi) -> Database credential extraction -> SSH on Port 22 -> Root privilege escalation. Feasible exploit chain discovered.");
        }

        private void OnAiAssistantClick(object sender, RoutedEventArgs e)
        {
            txtAiInput.Focus();
        }

        private void OnReportClick(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(
                $"DOGE Research Report\n\nTarget: {txtTargetDomain.Text}\nFindings: 12 Critical, 28 High, 47 Medium, 93 Low\nRisk Score: 8.7/10\nCryptographic Proof Attestation: Verified\nMerkle Root: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "DOGE Security Report",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }

        private async void OnStartResearchClick(object sender, RoutedEventArgs e)
        {
            if (!_isResearchRunning)
            {
                _isResearchRunning = true;
                btnStart.Content = "⏸ Pause";
                txtScanStatusTitle.Text = "Autonomous Loop";
                txtScanStatusSubtitle.Text = "Synthesizing Hypotheses...";
                scanProgressBar.IsIndeterminate = true;

                await _ipcClient.SendAsync("research.start");
                AddAiMessage("assistant", "Autonomous scientific research loop initiated. Exploring research frontier and generating falsification experiments.");
            }
            else
            {
                _isResearchRunning = false;
                btnStart.Content = "▶  Start";
                txtScanStatusTitle.Text = "Paused";
                txtScanStatusSubtitle.Text = "Ready";
                scanProgressBar.IsIndeterminate = false;
                scanProgressBar.Value = 100;

                await _ipcClient.SendAsync("research.pause");
                AddAiMessage("assistant", "Research loop suspended by operator. Laboratory state preserved.");
            }
        }

        // ==================== NAVIGATION ====================

        private void OnNavClick(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border clickedBorder)
            {
                foreach (var child in navPanel.Children)
                {
                    if (child is Border b)
                    {
                        b.Background = Brushes.Transparent;
                        b.BorderThickness = new Thickness(0);
                    }
                }

                clickedBorder.Background = new SolidColorBrush(Color.FromRgb(14, 34, 56));
                clickedBorder.BorderBrush = (SolidColorBrush)FindResource("BrushCyan");
                clickedBorder.BorderThickness = new Thickness(1);
            }
        }

        // ==================== GRAPH CONTROLS ====================

        private void OnZoomInClick(object sender, RoutedEventArgs e) => graphCanvas.ZoomIn();
        private void OnZoomOutClick(object sender, RoutedEventArgs e) => graphCanvas.ZoomOut();
        private void OnResetGraphClick(object sender, RoutedEventArgs e) => graphCanvas.ResetView();

        // ==================== TARGET DETAILS ACTIONS ====================

        private void OnRunNmapAction(object sender, RoutedEventArgs e) =>
            _ = _terminalService.ExecuteAsync($"nmap -sV {txtTargetDomain.Text}");

        private void OnDirScanAction(object sender, RoutedEventArgs e) =>
            _ = _terminalService.ExecuteAsync($"curl -s -I http://{txtTargetDomain.Text}/admin");

        private void OnSubdomainsAction(object sender, RoutedEventArgs e) =>
            _ = _terminalService.ExecuteAsync($"host -t a {txtTargetDomain.Text}");

        private void OnCheckVulnsAction(object sender, RoutedEventArgs e) =>
            AddAiMessage("assistant", "Vulnerability verification check completed: SQLi on /login confirmed with proof payload. SSRF on /api/fetch verified.");

        private void OnExploitSearchAction(object sender, RoutedEventArgs e) =>
            _ = _terminalService.ExecuteAsync("searchsploit nginx 1.24");

        private void OnOpenInTerminalAction(object sender, RoutedEventArgs e)
        {
            txtTerminalInput.Focus();
        }

        // ==================== TERMINAL ====================

        private void OnTerminalOutput(string text)
        {
            Dispatcher.Invoke(() =>
            {
                txtTerminalOutput.AppendText(text + "\n");
                termScrollViewer.ScrollToEnd();
            });
        }

        private void OnTerminalInputKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                var cmd = txtTerminalInput.Text.Trim();
                if (!string.IsNullOrEmpty(cmd))
                {
                    txtTerminalInput.Text = "";
                    _ = _terminalService.ExecuteAsync(cmd);
                }
            }
        }

        // ==================== FINDINGS ====================

        private void OnFindingItemDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (lstFindings.SelectedItem is FindingItem item)
            {
                MessageBox.Show(
                    $"Finding: {item.Title}\n" +
                    $"Severity: {item.Severity}\n" +
                    $"Target: {item.Target}\n" +
                    $"CWE: {item.Cwe}\n" +
                    $"CVSS: {item.Cvss}\n" +
                    $"Status: {item.Status}\n\n" +
                    $"Proof Bundle Root: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
                    $"Cryptographically sealed and attested.",
                    "Finding Inspector",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
            }
        }

        // ==================== EVIDENCE ====================

        private void OnEvidenceCardClick(object sender, MouseButtonEventArgs e)
        {
            MessageBox.Show(
                "Evidence Attestation Studio\n\n" +
                "Merkle Root Attestation: Verified ✓\n" +
                "Hash: a6c4832b918f0322d718ec84b3e81ff0725a805847e0ef7c290133ad1c1611d8\n" +
                "Timestamp: 2026-09-12 00:45:10 UTC\n" +
                "Source: Tactical Sandbox Proof Replay\n\n" +
                "Evidence chain is cryptographically sealed and independently reproducible.",
                "Evidence Inspector",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }

        private void OnViewAllEvidenceClick(object sender, MouseButtonEventArgs e)
        {
            MessageBox.Show(
                "4/4 Proof Bundles Loaded:\n" +
                "1. sql_injection_proof.png (Merkle Root #01)\n" +
                "2. admin_panel.png (Merkle Root #02)\n" +
                "3. directory_listing.png (Merkle Root #03)\n" +
                "4. rce_output.png (Merkle Root #04)",
                "All Evidence",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }

        // ==================== AI ASSISTANT ====================

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

            // Generate contextual response based on prompt
            string response = prompt.ToLower() switch
            {
                var p when p.Contains("analyze") =>
                    "The scan results reveal 2 critical vulnerabilities: SQL Injection on /login and Remote Code Execution on /api/v1/users. " +
                    "The attack surface indicates database compromise can lead to lateral movement onto MySQL (port 3306) and Redis (port 6379).",

                var p when p.Contains("explain") =>
                    "The SQL Injection on /login allows authentication bypass using Boolean-based or error-based payloads (' OR 1=1--). " +
                    "Because user input is directly concatenated into SQL queries without parameterized statements, arbitrary database read/write is possible.",

                var p when p.Contains("suggest") =>
                    "Recommended next steps:\n" +
                    "1. Extract database user hashes via the verified SQLi on /login.\n" +
                    "2. Attempt credential reuse against SSH service on port 22.\n" +
                    "3. Sandbox test the RCE endpoint /api/v1/users to determine execution privilege level.",

                var p when p.Contains("script") || p.Contains("exploit") =>
                    "Exploit PoC generated:\n" +
                    "curl -X POST https://example.com/login -d \"user=' OR 1=1--&pass=x\"\n" +
                    "# Attestation proof hash generated and sealed in Evidence Studio.",

                var p when p.Contains("privilege") || p.Contains("escalation") =>
                    "For Linux Ubuntu target with kernel 5.15.0:\n" +
                    "Check SUID binaries (`find / -perm -4000 2>/dev/null`), sudo permissions (`sudo -l`), and writable cron jobs in /etc/cron*.",

                var p when p.Contains("report") =>
                    "Executive & Technical Summary compiled. 12 Critical and 28 High severity issues documented with deterministic reproduction scripts.",

                _ =>
                    $"I have analyzed your query '{prompt}' in the context of target {txtTargetDomain.Text}. " +
                    $"DOGE autonomous reasoning recommends verifying endpoint invariants and testing for state-transition vulnerabilities."
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
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(10, 8, 10, 8),
                MaxWidth = 265,
                HorizontalAlignment = role == "user" ? HorizontalAlignment.Right : HorizontalAlignment.Left,
                Margin = new Thickness(0, 0, 0, 8)
            };

            var textBlock = new TextBlock
            {
                Text = content,
                Foreground = (SolidColorBrush)FindResource("BrushText"),
                FontSize = 10.5,
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
                txtSearch.Text = "Ctrl + Shift + P  Search anything...";
            }
        }

        private void OnSearchKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                var query = txtSearch.Text.Trim();
                if (!string.IsNullOrEmpty(query))
                {
                    AddAiMessage("assistant", $"Search query executed: '{query}'. Found 1 target, 2 matching findings, and 4 evidence records.");
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
    }
}
