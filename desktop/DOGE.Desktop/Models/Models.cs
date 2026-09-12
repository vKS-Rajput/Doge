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
        public string CurlCommand { get; set; } = "";
    }

    public class EvidenceItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Filename { get; set; } = "";
        public string TimeAgo { get; set; } = "";
        public string PreviewType { get; set; } = "terminal";
        public string SnippetHeader { get; set; } = "";
        public string SnippetBody { get; set; } = "";
        public string MerkleRoot { get; set; } = "";
        public string Status { get; set; } = "Cryptographically Sealed";
    }

    public class VisualNode
    {
        public string Id { get; set; } = "";
        public string Label { get; set; } = "";
        public string Subtitle { get; set; } = "";
        public string NodeType { get; set; } = "center";
        public string Status { get; set; } = "discovered";
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
        public string Role { get; set; } = "assistant";
        public string Content { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public List<string>? QuickSuggestions { get; set; }
    }

    public class HypothesisItem
    {
        public string Id { get; set; } = "";
        public string Title { get; set; } = "";
        public string Target { get; set; } = "";
        public double InfoGain { get; set; } = 0.8;
        public double Novelty { get; set; } = 0.7;
        public double RiskCeiling { get; set; } = 0.1;
        public string Status { get; set; } = "Active";
        public string Invariant { get; set; } = "";
        public string FalsificationMethod { get; set; } = "";
    }

    public class ExperimentItem
    {
        public string Id { get; set; } = "";
        public string HypothesisId { get; set; } = "";
        public string Action { get; set; } = "";
        public string ExpectedOutcome { get; set; } = "";
        public string ActualOutcome { get; set; } = "";
        public string PolicyVerdict { get; set; } = "Authorized";
        public string VerificationHash { get; set; } = "";
        public string Status { get; set; } = "Ready";
    }

    public class SubdomainItem
    {
        public string Host { get; set; } = "";
        public string Ip { get; set; } = "";
        public string Status { get; set; } = "200 OK";
        public string Technology { get; set; } = "";
    }

    public class PortItem
    {
        public string Port { get; set; } = "";
        public string State { get; set; } = "open";
        public string Service { get; set; } = "";
        public string Version { get; set; } = "";
    }

    public class WorldEntityItem
    {
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public string InvariantRule { get; set; } = "";
        public string Boundary { get; set; } = "Perimeter";
    }

    public class GateOptionModel
    {
        [JsonPropertyName("index")]
        public int Index { get; set; }

        [JsonPropertyName("label")]
        public string Label { get; set; } = "";

        [JsonPropertyName("description")]
        public string Description { get; set; } = "";

        [JsonPropertyName("priority")]
        public string Priority { get; set; } = "MEDIUM";
    }

    public class GateContextModel
    {
        [JsonPropertyName("target")]
        public string Target { get; set; } = "";

        [JsonPropertyName("tool")]
        public string Tool { get; set; } = "";

        [JsonPropertyName("command")]
        public string Command { get; set; } = "";

        [JsonPropertyName("risk_level")]
        public string RiskLevel { get; set; } = "HIGH";

        [JsonPropertyName("scope_reason")]
        public string ScopeReason { get; set; } = "";

        [JsonPropertyName("hypothesis_title")]
        public string HypothesisTitle { get; set; } = "";

        [JsonPropertyName("confidence")]
        public double Confidence { get; set; } = 0.95;

        [JsonPropertyName("reason")]
        public string Reason { get; set; } = "";

        [JsonPropertyName("estimated_requests")]
        public int EstimatedRequests { get; set; } = 1;

        [JsonPropertyName("estimated_duration")]
        public string EstimatedDuration { get; set; } = "250ms";
    }

    public class GateItem
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = "";

        [JsonPropertyName("type")]
        public string Type { get; set; } = "approval";

        [JsonPropertyName("title")]
        public string Title { get; set; } = "";

        [JsonPropertyName("description")]
        public string Description { get; set; } = "";

        [JsonPropertyName("status")]
        public string Status { get; set; } = "pending";

        [JsonPropertyName("context")]
        public GateContextModel Context { get; set; } = new();

        [JsonPropertyName("options")]
        public List<GateOptionModel>? Options { get; set; }

        [JsonPropertyName("decision_by")]
        public string DecisionBy { get; set; } = "";

        [JsonPropertyName("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class EnsembleSpecialist
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = "";

        [JsonPropertyName("role")]
        public string Role { get; set; } = "";

        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("experience")]
        public string Experience { get; set; } = "";

        [JsonPropertyName("focus_areas")]
        public List<string> FocusAreas { get; set; } = new();

        [JsonPropertyName("status")]
        public string Status { get; set; } = "ready";

        [JsonPropertyName("confidence")]
        public double Confidence { get; set; } = 0.95;

        [JsonPropertyName("invariant_hypothesis")]
        public string Invariant { get; set; } = "";

        [JsonPropertyName("active_probe")]
        public string ActiveProbe { get; set; } = "";

        public string StatusBadgeColor => Status switch
        {
            "consensus_reached" => "#10B981",
            "analyzing" => "#00F0FF",
            "awaiting_approval" => "#F43F5E",
            "deliberating" => "#A855F7",
            _ => "#64748B"
        };
    }
}
