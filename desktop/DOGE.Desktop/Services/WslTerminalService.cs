using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace DOGE.Desktop.Services
{
    public class WslTerminalService
    {
        private readonly string _distro = "kali-linux";

        public event Action<string>? OutputReceived;

        public async Task ExecuteAsync(string command)
        {
            OutputReceived?.Invoke($"--(kali㉿doge)-[~/workspace/example.com]\n$ {command}");

            await Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "wsl.exe",
                        Arguments = $"-d {_distro} -- {command}",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        StandardOutputEncoding = Encoding.UTF8,
                        StandardErrorEncoding = Encoding.UTF8
                    };

                    using var proc = Process.Start(psi);
                    if (proc == null)
                    {
                        OutputReceived?.Invoke("[!] Failed to spawn WSL process.");
                        return;
                    }

                    // Read output line by line
                    while (!proc.StandardOutput.EndOfStream)
                    {
                        var line = proc.StandardOutput.ReadLine();
                        if (line != null)
                        {
                            OutputReceived?.Invoke(line);
                        }
                    }

                    while (!proc.StandardError.EndOfStream)
                    {
                        var line = proc.StandardError.ReadLine();
                        if (line != null)
                        {
                            OutputReceived?.Invoke($"[stderr] {line}");
                        }
                    }

                    proc.WaitForExit();
                    OutputReceived?.Invoke($"--(kali㉿doge)-[~/workspace/example.com]\n$ ");
                }
                catch (Exception ex)
                {
                    OutputReceived?.Invoke($"[WSL Error] {ex.Message}");
                    OutputReceived?.Invoke($"--(kali㉿doge)-[~/workspace/example.com]\n$ ");
                }
            });
        }
    }
}
