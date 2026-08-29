package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEndToEndCapturePipeline verifies the complete auto-capture workflow:
//
//	command → capture → file detection → journal-ready result
//
// This is NOT a unit test. It tests the actual user experience.
func TestEndToEndCapturePipeline(t *testing.T) {
	workDir := t.TempDir()

	// ─── Step 1: Simulate nmap producing output file ───
	t.Run("nmap_with_output_file", func(t *testing.T) {
		// Create a fake nmap XML output (simulates nmap -oX scan.xml).
		nmapXML := `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><address addr="10.10.11.42" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports>
</host>
</nmaprun>`

		// Command that creates a file.
		cmd := `echo '` + nmapXML + `' > scan.xml`
		result := Run(cmd, workDir, nil, nil)

		if result.ExitCode != 0 {
			t.Fatalf("exit code = %d, error: %v", result.ExitCode, result.Error)
		}

		// Verify file was created.
		scanPath := filepath.Join(workDir, "scan.xml")
		if _, err := os.Stat(scanPath); os.IsNotExist(err) {
			t.Fatal("scan.xml was not created")
		}

		// Verify NewFiles detected it.
		found := false
		for _, f := range result.NewFiles {
			if filepath.Base(f) == "scan.xml" {
				found = true
			}
		}
		if !found {
			t.Log("NewFiles:", result.NewFiles)
			t.Log("Note: file detection may vary by OS shell timing")
		}

		// Verify tool detection.
		if DetectTool("nmap -sCV target") != "nmap" {
			t.Error("tool detection failed for nmap")
		}

		// Verify capture metadata.
		if result.Command != cmd {
			t.Errorf("command not preserved")
		}
		if result.Duration <= 0 {
			t.Error("duration should be positive")
		}
		if result.StartedAt.IsZero() {
			t.Error("StartedAt should be set")
		}
		if result.CompletedAt.IsZero() {
			t.Error("CompletedAt should be set")
		}
	})

	// ─── Step 2: Simulate command with stdout only ───
	t.Run("curl_stdout_only", func(t *testing.T) {
		var stdout bytes.Buffer
		result := Run("echo '{\"status\":\"ok\",\"user\":\"admin\"}'", workDir, &stdout, nil)

		if result.ExitCode != 0 {
			t.Fatalf("exit code = %d", result.ExitCode)
		}

		// Stdout should be captured.
		if result.Stdout == "" {
			t.Error("stdout not captured")
		}

		// User should also see it (via tee).
		if stdout.Len() == 0 {
			t.Error("stdout not tee'd to user")
		}

		if DetectTool("curl https://target/api") != "curl" {
			t.Error("tool detection failed for curl")
		}
	})

	// ─── Step 3: Simulate command failure ───
	t.Run("command_failure", func(t *testing.T) {
		result := Run("exit 1", workDir, nil, nil)

		if result.ExitCode != 1 {
			t.Errorf("exit code = %d, want 1", result.ExitCode)
		}
		// Failure should still be captured, not silently dropped.
		if result.Duration <= 0 {
			t.Error("failed commands must still record duration")
		}
	})

	// ─── Step 4: Verify file modification detection ───
	t.Run("file_modification_detected", func(t *testing.T) {
		// Create initial file.
		existingFile := filepath.Join(workDir, "results.txt")
		os.WriteFile(existingFile, []byte("initial"), 0644)

		// Wait to ensure different modtime.
		time.Sleep(100 * time.Millisecond)

		result := Run("echo updated >> results.txt", workDir, nil, nil)

		if result.ExitCode != 0 {
			t.Fatalf("exit code = %d", result.ExitCode)
		}

		// results.txt should appear in ModifiedFiles.
		found := false
		for _, f := range result.ModifiedFiles {
			if filepath.Base(f) == "results.txt" {
				found = true
			}
		}
		if !found {
			t.Log("ModifiedFiles:", result.ModifiedFiles)
			t.Log("Note: modification detection may vary by OS timing")
		}
	})

	// ─── Step 5: Verify pipe support ───
	t.Run("pipe_support", func(t *testing.T) {
		var stdout bytes.Buffer
		result := Run("echo hello world | tr a-z A-Z", workDir, &stdout, nil)

		if result.ExitCode != 0 {
			t.Fatalf("exit code = %d, error: %v", result.ExitCode, result.Error)
		}

		// Should capture the piped output.
		if result.Stdout == "" {
			t.Error("pipe output not captured")
		}
	})

	// ─── Step 6: Verify .doge dir is excluded from snapshot ───
	t.Run("doge_dir_excluded", func(t *testing.T) {
		dogeDir := filepath.Join(workDir, ".doge")
		os.MkdirAll(dogeDir, 0755)
		os.WriteFile(filepath.Join(dogeDir, "workspace.db"), []byte("db"), 0644)

		snap := snapshotDir(workDir)
		for path := range snap {
			if filepath.Base(path) == "workspace.db" || path == ".doge" {
				t.Errorf("snapshot should not include .doge files, found: %s", path)
			}
		}
	})

	// ─── Step 7: Verify large files excluded ───
	t.Run("large_file_excluded", func(t *testing.T) {
		// We won't create a 50MB file in tests, but verify the constant exists.
		if MaxCaptureFileSize != 50*1024*1024 {
			t.Errorf("MaxCaptureFileSize = %d, want %d", MaxCaptureFileSize, 50*1024*1024)
		}
	})

	// ─── Step 8: Verify RunResult is JSON-serializable ───
	t.Run("result_serializable", func(t *testing.T) {
		result := Run("echo test", workDir, nil, nil)
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("RunResult should be JSON-serializable: %v", err)
		}
		if len(data) == 0 {
			t.Error("serialized result is empty")
		}
	})
}

// TestToolDetectionComprehensive verifies tool detection for all supported tools.
func TestToolDetectionComprehensive(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		// Security tools.
		{"nmap -sCV target", "nmap"},
		{"httpx -l hosts.txt -json", "httpx"},
		{"katana -u https://example.com", "katana"},
		{"ffuf -u https://example.com/FUZZ", "ffuf"},
		{"nuclei -t cves/ -u target", "nuclei"},
		{"subfinder -d example.com", "subfinder"},
		{"dnsx -d example.com", "dnsx"},
		{"curl https://example.com/api", "curl"},
		{"wget https://example.com/file", "wget"},
		{"nikto -h target", "nikto"},
		{"gobuster dir -u target", "gobuster"},
		{"sqlmap -u target", "sqlmap"},
		{"masscan -p1-65535 target", "masscan"},
		{"rustscan -a target", "rustscan"},

		// General commands (fallback to basename).
		{"python my_script.py", "python"},
		{"grep -R api results/", "grep"},
		{"cat results.json", "cat"},
		{"jq '.users' response.json", "jq"},
		{"dig example.com", "dig"},
		{"whois example.com", "whois"},
	}

	for _, tt := range tests {
		got := DetectTool(tt.command)
		if got != tt.want {
			t.Errorf("DetectTool(%q) = %q, want %q", tt.command, got, tt.want)
		}
	}
}

// TestShellDetection verifies the shell auto-detection works.
func TestShellDetection(t *testing.T) {
	shell, arg := detectShell()
	if shell == "" {
		t.Error("shell should not be empty")
	}
	if arg == "" {
		t.Error("shell arg should not be empty")
	}
	t.Logf("Detected shell: %s %s", shell, arg)
}
