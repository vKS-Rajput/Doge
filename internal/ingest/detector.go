// Package ingest provides automatic tool-output detection and
// bounded ingestion into the DOGE pipeline.
//
// The ingestion subsystem has two components:
//
//   - Detector: identifies which tool produced an output file
//     based on structural content, not filename extension
//
//   - Dispatcher: bounded queue of ingestion jobs with configurable
//     worker count, backpressure, and content-hash deduplication
//
// Architecture:
//
//	Executor output → Dispatcher → Detector → Parser → Observations
//	File drop       → Dispatcher → Detector → Parser → Observations
//
// Unknown output is preserved as an artifact and reported,
// NEVER silently discarded.
package ingest

import (
	"encoding/json"
	"strings"
)

// DetectedTool is the result of tool detection.
type DetectedTool struct {
	// Tool is the canonical tool name (e.g., "nmap").
	Tool string

	// Confidence is how certain the detection is (0.0 - 1.0).
	Confidence float64

	// Reason explains why this tool was detected.
	Reason string
}

// DetectTool identifies which tool produced the given output.
//
// Detection is based on STRUCTURAL CONTENT, not filename extension.
// This is important because:
//   - Files may be renamed
//   - Executor output files have generated names
//   - Piped output has no filename
//
// Returns nil if no tool is recognized. Unknown output must still
// be preserved as an artifact.
func DetectTool(content []byte, filename string) *DetectedTool {
	// Try structural detection first.
	if result := detectByContent(content); result != nil {
		return result
	}

	// Fall back to filename hints.
	if result := detectByFilename(filename); result != nil {
		return result
	}

	return nil
}

// detectByContent inspects the structure of the data.
func detectByContent(content []byte) *DetectedTool {
	trimmed := strings.TrimSpace(string(content))

	// Nmap XML: starts with <?xml and contains <nmaprun
	if strings.HasPrefix(trimmed, "<?xml") && strings.Contains(trimmed, "<nmaprun") {
		return &DetectedTool{Tool: "nmap", Confidence: 0.95, Reason: "XML with <nmaprun> element"}
	}

	// Nmap grepable output.
	if strings.HasPrefix(trimmed, "# Nmap") {
		return &DetectedTool{Tool: "nmap", Confidence: 0.90, Reason: "Nmap grepable format header"}
	}

	// JSON-based tools: try parsing first line or full content.
	if isJSON(trimmed) || isJSONL(trimmed) {
		return detectJSONTool(trimmed)
	}

	return nil
}

// detectJSONTool identifies JSON-based tool output by structure.
func detectJSONTool(content string) *DetectedTool {
	// Try first line for JSONL formats.
	firstLine := content
	if idx := strings.Index(content, "\n"); idx > 0 {
		firstLine = content[:idx]
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(firstLine), &obj); err != nil {
		return nil
	}

	// httpx: has "url", "status_code", "content_length"
	if hasKeys(obj, "url", "status_code") || hasKeys(obj, "url", "status-code") {
		return &DetectedTool{Tool: "httpx", Confidence: 0.90, Reason: "JSON with url + status_code fields"}
	}

	// subfinder: has "host" and "source"
	if hasKeys(obj, "host", "source") {
		return &DetectedTool{Tool: "subfinder", Confidence: 0.85, Reason: "JSON with host + source fields"}
	}

	// dnsx: has "host" and "resolver" or "a" records
	if hasKeys(obj, "host") && (hasKey(obj, "resolver") || hasKey(obj, "a")) {
		return &DetectedTool{Tool: "dnsx", Confidence: 0.85, Reason: "JSON with host + resolver/a fields"}
	}

	// katana: has "request" and "response" or just "endpoint"
	if hasKeys(obj, "request", "response") {
		return &DetectedTool{Tool: "katana", Confidence: 0.85, Reason: "JSON with request + response fields"}
	}
	if hasKey(obj, "endpoint") && hasKey(obj, "source") {
		return &DetectedTool{Tool: "katana", Confidence: 0.80, Reason: "JSON with endpoint + source fields"}
	}

	// nuclei: has "template-id" and "matched-at"
	if hasKey(obj, "template-id") || hasKey(obj, "templateID") {
		return &DetectedTool{Tool: "nuclei", Confidence: 0.90, Reason: "JSON with template-id field"}
	}

	// ffuf: full JSON output has "results" array with "input", "position", "status"
	if hasKey(obj, "results") {
		if results, ok := obj["results"].([]interface{}); ok && len(results) > 0 {
			if first, ok := results[0].(map[string]interface{}); ok {
				if hasKey(first, "input") || hasKey(first, "status") {
					return &DetectedTool{Tool: "ffuf", Confidence: 0.90, Reason: "JSON with results array containing input/status"}
				}
			}
		}
	}

	return nil
}

// detectByFilename uses filename patterns as fallback hints.
func detectByFilename(filename string) *DetectedTool {
	lower := strings.ToLower(filename)

	patterns := []struct {
		contains   string
		tool       string
		confidence float64
	}{
		{"nmap", "nmap", 0.70},
		{"httpx", "httpx", 0.70},
		{"subfinder", "subfinder", 0.70},
		{"dnsx", "dnsx", 0.70},
		{"katana", "katana", 0.70},
		{"ffuf", "ffuf", 0.70},
		{"nuclei", "nuclei", 0.70},
	}

	for _, p := range patterns {
		if strings.Contains(lower, p.contains) {
			return &DetectedTool{
				Tool:       p.tool,
				Confidence: p.confidence,
				Reason:     "Filename contains '" + p.contains + "'",
			}
		}
	}

	// Extension hints.
	if strings.HasSuffix(lower, ".xml") {
		return &DetectedTool{Tool: "nmap", Confidence: 0.50, Reason: "XML file extension (may be nmap)"}
	}

	return nil
}

// --- Helpers ---

func isJSON(s string) bool {
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func isJSONL(s string) bool {
	lines := strings.SplitN(s, "\n", 2)
	return len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "{")
}

func hasKey(obj map[string]interface{}, key string) bool {
	_, ok := obj[key]
	return ok
}

func hasKeys(obj map[string]interface{}, keys ...string) bool {
	for _, k := range keys {
		if !hasKey(obj, k) {
			return false
		}
	}
	return true
}
