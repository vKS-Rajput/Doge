using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DOGE.Desktop.Services
{
    public enum TerminalShellType
    {
        Auto,
        WslKali,
        PowerShell,
        Cmd
    }

    public class WslTerminalService
    {
        private readonly string _distro = "kali-linux";
        private Process? _activeProcess;
        private readonly object _lock = new();

        public TerminalShellType ShellType { get; set; } = TerminalShellType.Auto;
        public string WorkingDirectory { get; set; } = Environment.CurrentDirectory;
        public bool IsRunning => _activeProcess != null && !_activeProcess.HasExited;

        public event Action<string>? OutputReceived;
        public event Action<bool>? ExecutionStateChanged;

        public void AbortCurrentCommand()
        {
            lock (_lock)
            {
                try
                {
                    if (_activeProcess != null && !_activeProcess.HasExited)
                    {
                        _activeProcess.Kill(true);
                        OutputReceived?.Invoke("\n[✕ Process Terminated by Operator]");
                    }
                }
                catch { }
                finally
                {
                    _activeProcess = null;
                    ExecutionStateChanged?.Invoke(false);
                }
            }
        }

        public async Task ExecuteAsync(string command)
        {
            if (string.IsNullOrWhiteSpace(command)) return;

            var trimmed = command.Trim();
            var promptDir = !string.IsNullOrEmpty(WorkingDirectory) ? Path.GetFileName(WorkingDirectory) : "workspace";
            OutputReceived?.Invoke($"\n[doge:{promptDir}]$ {trimmed}\n");

            ExecutionStateChanged?.Invoke(true);

            await Task.Run(() =>
            {
                lock (_lock)
                {
                    try
                    {
                        var psi = BuildProcessStartInfo(trimmed);
                        var proc = Process.Start(psi);
                        if (proc == null)
                        {
                            OutputReceived?.Invoke("[!] Failed to spawn process.");
                            return;
                        }

                        _activeProcess = proc;

                        // Stream stdout
                        proc.OutputDataReceived += (s, e) =>
                        {
                            if (e.Data != null)
                            {
                                OutputReceived?.Invoke(e.Data);
                            }
                        };

                        // Stream stderr
                        proc.ErrorDataReceived += (s, e) =>
                        {
                            if (e.Data != null)
                            {
                                OutputReceived?.Invoke(e.Data);
                            }
                        };

                        proc.BeginOutputReadLine();
                        proc.BeginErrorReadLine();

                        proc.WaitForExit();

                        if (proc.ExitCode != 0)
                        {
                            OutputReceived?.Invoke($"[Exit Code: {proc.ExitCode}]");
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputReceived?.Invoke($"[Execution Error] {ex.Message}");
                    }
                    finally
                    {
                        _activeProcess = null;
                        ExecutionStateChanged?.Invoke(false);
                        OutputReceived?.Invoke($"\n[doge:{promptDir}]$ ");
                    }
                }
            });
        }

        private ProcessStartInfo BuildProcessStartInfo(string command)
        {
            var targetDir = Directory.Exists(WorkingDirectory) ? WorkingDirectory : Environment.CurrentDirectory;

            // Check if user specifically selected shell or Auto
            bool preferWsl = ShellType == TerminalShellType.WslKali;
            if (ShellType == TerminalShellType.Auto)
            {
                // If command is Linux-specific (e.g. nmap, searchsploit, hydra, nikto, kali tools), use WSL if available
                var cmdLower = command.ToLowerInvariant();
                if (cmdLower.StartsWith("nmap") || cmdLower.StartsWith("searchsploit") || cmdLower.StartsWith("nikto") ||
                    cmdLower.StartsWith("gobuster") || cmdLower.StartsWith("ffuf") || cmdLower.StartsWith("subfinder") ||
                    cmdLower.StartsWith("amass") || cmdLower.StartsWith("sqlmap"))
                {
                    preferWsl = CheckWslAvailable();
                }
            }

            if (preferWsl && CheckWslAvailable())
            {
                var escaped = command.Replace("\"", "\\\"");
                return new ProcessStartInfo
                {
                    FileName = "wsl.exe",
                    Arguments = $"-d {_distro} -- sh -c \"{escaped}\"",
                    WorkingDirectory = targetDir,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };
            }

            // If command starts with doge, resolve doge.exe path
            if (command.StartsWith("doge ", StringComparison.OrdinalIgnoreCase) || command.Equals("doge", StringComparison.OrdinalIgnoreCase))
            {
                var dogeExe = FindDogeExecutable();
                if (!string.IsNullOrEmpty(dogeExe))
                {
                    var args = command.Length > 5 ? command.Substring(5) : "";
                    return new ProcessStartInfo
                    {
                        FileName = dogeExe,
                        Arguments = args,
                        WorkingDirectory = targetDir,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        StandardOutputEncoding = Encoding.UTF8,
                        StandardErrorEncoding = Encoding.UTF8
                    };
                }
            }

            // Default: PowerShell execution
            return new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "\\\"")}\"",
                WorkingDirectory = targetDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
        }

        private bool CheckWslAvailable()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "wsl.exe",
                    Arguments = "-l -q",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p != null)
                {
                    p.WaitForExit(1000);
                    return p.ExitCode == 0;
                }
            }
            catch { }
            return false;
        }

        private string? FindDogeExecutable()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var candidates = new[]
            {
                Path.Combine(baseDir, "doge.exe"),
                Path.Combine(baseDir, "..", "..", "..", "..", "build", "doge.exe"),
                Path.Combine(baseDir, "..", "..", "..", "..", "doge.exe"),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "build", "doge.exe")),
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "doge.exe")),
                "doge.exe"
            };

            foreach (var c in candidates)
            {
                try
                {
                    if (File.Exists(c)) return Path.GetFullPath(c);
                }
                catch { }
            }
            return null;
        }
    }
}
