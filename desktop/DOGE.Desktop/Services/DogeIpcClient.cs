using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DOGE.Desktop.Models;

namespace DOGE.Desktop.Services
{
    public class DogeIpcClient : IDisposable
    {
        private const string PipeName = "doge-ipc";
        private const string HttpFallbackUrl = "http://127.0.0.1:42424";

        private NamedPipeClientStream? _pipeClient;
        private StreamReader? _pipeReader;
        private StreamWriter? _pipeWriter;
        private Process? _spawnedCoreProcess;
        private readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(10) };
        private readonly CancellationTokenSource _cts = new();

        public bool IsConnected { get; private set; }
        public bool IsUsingNamedPipe { get; private set; }

        public event Action<PipeMessage>? OnEventReceived;
        public event Action<string>? OnStatusChanged;

        public async Task StartAsync()
        {
            // 1. Attempt to connect to existing Windows Named Pipe
            if (await TryConnectPipeAsync())
                return;

            // 2. Check if a doge core process is already running on the system
            var existingProcesses = Process.GetProcessesByName("doge")
                .Concat(Process.GetProcessesByName("doge-core"))
                .ToArray();
            if (existingProcesses.Length > 0)
            {
                // Wait briefly for pipe to become available
                for (int i = 0; i < 3; i++)
                {
                    await Task.Delay(800);
                    if (await TryConnectPipeAsync())
                        return;
                }
            }
            else
            {
                // 3. Find a single valid doge.exe candidate
                string? bestCandidate = null;
                var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                var candidates = new[]
                {
                    Path.Combine(baseDir, "doge.exe"),
                    Path.Combine(baseDir, "doge-core.exe"),
                    Path.Combine(baseDir, "..", "..", "..", "..", "build", "doge.exe"),
                    Path.Combine(baseDir, "..", "..", "..", "..", "doge.exe"),
                    Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "build", "doge.exe")),
                    Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "doge.exe")),
                    "doge.exe",
                    "doge-core.exe"
                };

                foreach (var candidate in candidates)
                {
                    try
                    {
                        if (File.Exists(candidate))
                        {
                            bestCandidate = Path.GetFullPath(candidate);
                            break; // Stop at the very first valid executable!
                        }
                    }
                    catch { }
                }

                if (bestCandidate != null)
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = bestCandidate,
                            Arguments = "desktop --headless",
                            WorkingDirectory = Path.GetDirectoryName(bestCandidate),
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        _spawnedCoreProcess = Process.Start(psi);
                        if (_spawnedCoreProcess != null)
                        {
                            for (int i = 0; i < 4; i++)
                            {
                                await Task.Delay(750);
                                if (await TryConnectPipeAsync())
                                    return;
                            }
                        }
                    }
                    catch { }
                }
            }

            // 4. Fallback to HTTP check
            await TryConnectHttpAsync();
        }

        private async Task<bool> TryConnectPipeAsync()
        {
            try
            {
                _pipeClient = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                using var connectCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1500));
                await _pipeClient.ConnectAsync(connectCts.Token);

                _pipeReader = new StreamReader(_pipeClient, Encoding.UTF8);
                _pipeWriter = new StreamWriter(_pipeClient, Encoding.UTF8) { AutoFlush = true };

                IsConnected = true;
                IsUsingNamedPipe = true;
                OnStatusChanged?.Invoke("Connected via Windows Named Pipe (\\\\.\\pipe\\doge-ipc)");

                _ = Task.Run(ListenPipeEventsAsync, _cts.Token);
                return true;
            }
            catch
            {
                _pipeClient?.Dispose();
                _pipeClient = null;
                return false;
            }
        }

        private async Task<bool> TryConnectHttpAsync()
        {
            try
            {
                var resp = await _httpClient.GetAsync($"{HttpFallbackUrl}/api/status", _cts.Token);
                if (resp.IsSuccessStatusCode)
                {
                    IsConnected = true;
                    IsUsingNamedPipe = false;
                    OnStatusChanged?.Invoke($"Connected via Loopback IPC ({HttpFallbackUrl})");
                    return true;
                }
            }
            catch
            {
                // Standalone / offline mode
            }

            IsConnected = false;
            OnStatusChanged?.Invoke("DOGE Core Offline / Laboratory Ready");
            return false;
        }

        public async Task<PipeMessage?> SendActionAsync<T>(string action, object? payload = null) => await SendAsync(action, payload);

        public async Task<PipeMessage?> SendAsync(string action, object? payload = null)
        {
            var req = new PipeMessage
            {
                Id = Guid.NewGuid().ToString(),
                Action = action,
                Payload = payload,
                Timestamp = DateTime.UtcNow.ToString("o"),
                Version = "1.0.0"
            };

            if (IsUsingNamedPipe && _pipeWriter != null && _pipeReader != null)
            {
                try
                {
                    var json = JsonSerializer.Serialize(req);
                    await _pipeWriter.WriteLineAsync(json);

                    var responseLine = await _pipeReader.ReadLineAsync();
                    if (!string.IsNullOrEmpty(responseLine))
                    {
                        return JsonSerializer.Deserialize<PipeMessage>(responseLine);
                    }
                }
                catch (Exception ex)
                {
                    OnStatusChanged?.Invoke("Pipe send error: " + ex.Message);
                }
            }
            else
            {
                try
                {
                    var endpoint = action switch
                    {
                        "status.get" => "/api/status",
                        "environment.get" => "/api/environment",
                        "workspace.get" => "/api/workspace",
                        "research.start" => "/api/research/start",
                        "research.pause" => "/api/research/pause",
                        "research.resume" => "/api/research/resume",
                        "research.stop" => "/api/research/stop",
                        "worldmodel.get" => "/api/worldmodel",
                        "findings.get" => "/api/findings",
                        "notebook.get" => "/api/notebook",
                        "target.get" => "/api/target",
                        "research.get" => "/api/research",
                        "evidence.get" => "/api/evidence",
                        _ => null
                    };

                    if (endpoint != null)
                    {
                        var res = await _httpClient.GetAsync(HttpFallbackUrl + endpoint, _cts.Token);
                        var body = await res.Content.ReadAsStringAsync(_cts.Token);
                        return new PipeMessage
                        {
                            Id = req.Id,
                            Action = action,
                            Success = res.IsSuccessStatusCode,
                            Data = JsonSerializer.Deserialize<JsonElement>(body)
                        };
                    }
                }
                catch (Exception ex)
                {
                    OnStatusChanged?.Invoke("HTTP IPC fallback error: " + ex.Message);
                }
            }

            return null;
        }

        private async Task ListenPipeEventsAsync()
        {
            while (!_cts.Token.IsCancellationRequested && _pipeReader != null)
            {
                try
                {
                    var line = await _pipeReader.ReadLineAsync();
                    if (string.IsNullOrEmpty(line))
                    {
                        await Task.Delay(100, _cts.Token);
                        continue;
                    }

                    var msg = JsonSerializer.Deserialize<PipeMessage>(line);
                    if (msg != null)
                    {
                        OnEventReceived?.Invoke(msg);
                    }
                }
                catch
                {
                    break;
                }
            }
        }

        public void Dispose()
        {
            try { _cts.Cancel(); } catch { }
            try { _cts.Dispose(); } catch { }

            try { _pipeWriter?.Dispose(); } catch { }
            _pipeWriter = null;

            try { _pipeReader?.Dispose(); } catch { }
            _pipeReader = null;

            try { _pipeClient?.Dispose(); } catch { }
            _pipeClient = null;

            try { _httpClient.Dispose(); } catch { }

            if (_spawnedCoreProcess != null && !_spawnedCoreProcess.HasExited)
            {
                try
                {
                    _spawnedCoreProcess.Kill();
                }
                catch { }
            }
        }
    }
}
