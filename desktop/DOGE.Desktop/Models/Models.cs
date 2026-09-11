using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DOGE.Desktop.Models
{
    public class PipeMessage
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("correlation_id")]
        public string? CorrelationId { get; set; }

        [JsonPropertyName("action")]
        public string? Action { get; set; }

        [JsonPropertyName("event")]
        public string? Event { get; set; }

        [JsonPropertyName("source")]
        public string? Source { get; set; }

        [JsonPropertyName("payload")]
        public object? Payload { get; set; }

        [JsonPropertyName("data")]
        public JsonElement? Data { get; set; }

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("timestamp")]
        public string? Timestamp { get; set; }

        [JsonPropertyName("version")]
        public string? Version { get; set; }
    }

    public class SystemTelemetry
    {
        public double CpuPercent { get; set; } = 32.0;
        public double RamUsedGb { get; set; } = 5.1;
        public double RamTotalGb { get; set; } = 16.0;
        public double DiskFreeGb { get; set; } = 120.0;
        public string WslDistro { get; set; } = "kali-linux";
        public bool WslOnline { get; set; } = true;
        public int ReadyTools { get; set; } = 24;
    }

    public class TargetDetails
    {
        public string Host { get; set; } = "example.com";
        public string Ip { get; set; } = "192.168.1.10";
        public string Status { get; set; } = "Active";
        public string Technology { get; set; } = "Nginx 1.24.0";
        public string Waf { get; set; } = "Not Detected";
        public string OpenPorts { get; set; } = "80, 443, 22, 3306, 6379";
        public string Os { get; set; } = "Linux (Ubuntu)";
        public string Location { get; set; } = "United States";
        public double RiskScore { get; set; } = 8.7;
    }

    public class FindingItem
    {
        public int Index { get; set; }
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Severity { get; set; } = "Medium";
        public string Title { get; set; } = "";
        public string Target { get; set; } = "";
        public string Cwe { get; set; } = "CWE-200";
        public double Cvss { get; set; } = 5.0;
        public string Status { get; set; } = "Proven";
        public string Description { get; set; } = "";
        public string ProofHash { get; set; } = "";
        public string TimeAgo { get; set; } = "Just now";
    }

    public class EvidenceItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Filename { get; set; } = "";
        public string TimeAgo { get; set; } = "";
        public string PreviewType { get; set; } = "terminal"; // terminal, browser, code
        public string SnippetHeader { get; set; } = "";
        public string SnippetBody { get; set; } = "";
        public string MerkleRoot { get; set; } = "";
    }

    public class VisualNode
    {
        public string Id { get; set; } = "";
        public string Label { get; set; } = "";
        public string Subtitle { get; set; } = "";
        public string NodeType { get; set; } = "center"; // center, subdomain, port
        public string Status { get; set; } = "discovered"; // discovered, vulnerable, exploitable, internal, external
        public double X { get; set; }
        public double Y { get; set; }
        public string ColorHex { get; set; } = "#00F0FF";
    }

    public class VisualEdge
    {
        public string SourceId { get; set; } = "";
        public string TargetId { get; set; } = "";
        public string EdgeType { get; set; } = "default";
        public string ColorHex { get; set; } = "#00F0FF";
    }

    public class ChatMessage
    {
        public string Role { get; set; } = "assistant"; // assistant, user
        public string Content { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public List<string>? QuickSuggestions { get; set; }
    }
}
