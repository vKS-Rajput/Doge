package ingest

import (
	"testing"
)

// --- Detector Tests ---

func TestDetectNmapXML(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sCV 10.10.11.123">
<host><ports><port protocol="tcp" portid="80"></port></ports></host>
</nmaprun>`)

	result := DetectTool(content, "scan.xml")
	if result == nil {
		t.Fatal("should detect nmap XML")
	}
	if result.Tool != "nmap" {
		t.Errorf("tool = %s, want nmap", result.Tool)
	}
	if result.Confidence < 0.9 {
		t.Errorf("confidence = %f, should be >= 0.9", result.Confidence)
	}
}

func TestDetectNmapGrepable(t *testing.T) {
	content := []byte(`# Nmap 7.94 scan initiated Mon Jan  1 00:00:00 2024 as: nmap -sCV 10.10.11.123
Host: 10.10.11.123 ()	Ports: 22/open/tcp//ssh//OpenSSH/`)

	result := DetectTool(content, "output.txt")
	if result == nil {
		t.Fatal("should detect nmap grepable")
	}
	if result.Tool != "nmap" {
		t.Errorf("tool = %s, want nmap", result.Tool)
	}
}

func TestDetectHttpxJSON(t *testing.T) {
	content := []byte(`{"url":"http://10.10.11.123","status_code":200,"content_length":1234,"title":"Test"}`)

	result := DetectTool(content, "output.json")
	if result == nil {
		t.Fatal("should detect httpx")
	}
	if result.Tool != "httpx" {
		t.Errorf("tool = %s, want httpx", result.Tool)
	}
}

func TestDetectSubfinderJSON(t *testing.T) {
	content := []byte(`{"host":"sub.example.com","source":"crtsh"}`)

	result := DetectTool(content, "output.json")
	if result == nil {
		t.Fatal("should detect subfinder")
	}
	if result.Tool != "subfinder" {
		t.Errorf("tool = %s, want subfinder", result.Tool)
	}
}

func TestDetectNucleiJSON(t *testing.T) {
	content := []byte(`{"template-id":"cve-2024-1234","matched-at":"http://10.10.11.123","severity":"high"}`)

	result := DetectTool(content, "nuclei_results.jsonl")
	if result == nil {
		t.Fatal("should detect nuclei")
	}
	if result.Tool != "nuclei" {
		t.Errorf("tool = %s, want nuclei", result.Tool)
	}
}

func TestDetectFfufJSON(t *testing.T) {
	content := []byte(`{"results":[{"input":{"FUZZ":"admin"},"position":1,"status":200}]}`)

	result := DetectTool(content, "output.json")
	if result == nil {
		t.Fatal("should detect ffuf")
	}
	if result.Tool != "ffuf" {
		t.Errorf("tool = %s, want ffuf", result.Tool)
	}
}

func TestDetectKatanaJSON(t *testing.T) {
	content := []byte(`{"request":{"method":"GET","endpoint":"http://10.10.11.123/"},"response":{"status_code":200}}`)

	result := DetectTool(content, "output.jsonl")
	if result == nil {
		t.Fatal("should detect katana")
	}
	if result.Tool != "katana" {
		t.Errorf("tool = %s, want katana", result.Tool)
	}
}

func TestDetectDnsxJSON(t *testing.T) {
	content := []byte(`{"host":"example.com","resolver":"8.8.8.8","a":["93.184.216.34"]}`)

	result := DetectTool(content, "output.json")
	if result == nil {
		t.Fatal("should detect dnsx")
	}
	if result.Tool != "dnsx" {
		t.Errorf("tool = %s, want dnsx", result.Tool)
	}
}

func TestDetectByFilename(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"nmap_scan.xml", "nmap"},
		{"httpx_output.json", "httpx"},
		{"subfinder_results.json", "subfinder"},
		{"ffuf_dir.json", "ffuf"},
		{"nuclei_scan.jsonl", "nuclei"},
	}

	for _, tt := range tests {
		result := DetectTool([]byte("not recognizable content"), tt.filename)
		if result == nil {
			t.Errorf("should detect %s from filename %s", tt.expected, tt.filename)
			continue
		}
		if result.Tool != tt.expected {
			t.Errorf("filename %s: tool = %s, want %s", tt.filename, result.Tool, tt.expected)
		}
		if result.Confidence >= 0.9 {
			t.Errorf("filename-based detection should have lower confidence, got %f", result.Confidence)
		}
	}
}

func TestDetectUnknownOutput(t *testing.T) {
	content := []byte("completely unknown content that no tool would produce")

	result := DetectTool(content, "mystery_file.dat")
	if result != nil {
		t.Errorf("should return nil for unknown output, got %+v", result)
	}
}

func TestDetectEmptyContent(t *testing.T) {
	result := DetectTool([]byte{}, "empty.json")
	// Should not panic.
	_ = result
}

func TestDetectContentPrioritizedOverFilename(t *testing.T) {
	// File named "nmap" but contains httpx JSON.
	content := []byte(`{"url":"http://test.com","status_code":200}`)

	result := DetectTool(content, "nmap_output.json")
	if result == nil {
		t.Fatal("should detect something")
	}
	// Content detection should win over filename.
	if result.Tool != "httpx" {
		t.Errorf("content should override filename: tool = %s, want httpx", result.Tool)
	}
}
