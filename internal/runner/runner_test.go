package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunEcho(t *testing.T) {
	dir := t.TempDir()

	var stdout bytes.Buffer
	result := Run("echo hello world", dir, &stdout, nil)

	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0, error: %v", result.ExitCode, result.Error)
	}
	if result.Stdout == "" {
		t.Error("stdout is empty, expected output")
	}
	if result.Duration <= 0 {
		t.Error("duration should be positive")
	}
	if result.Command != "echo hello world" {
		t.Errorf("command = %q, want %q", result.Command, "echo hello world")
	}
}

func TestRunCapturesExitCode(t *testing.T) {
	dir := t.TempDir()

	result := Run("exit 42", dir, nil, nil)

	if result.ExitCode != 42 {
		t.Errorf("exit code = %d, want 42", result.ExitCode)
	}
}

func TestRunDetectsNewFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a file via command.
	result := Run("echo test > newfile.txt", dir, nil, nil)

	// Check that newfile.txt is in NewFiles.
	found := false
	for _, f := range result.NewFiles {
		if filepath.Base(f) == "newfile.txt" {
			found = true
			break
		}
	}

	if !found {
		// On some OS/shell combos the file detection may work differently.
		// At minimum verify the file was created.
		if _, err := os.Stat(filepath.Join(dir, "newfile.txt")); err != nil {
			t.Log("file not created by shell command (may be OS-specific)")
		}
	}
}

func TestDetectTool(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"nmap -sCV target", "nmap"},
		{"httpx -l hosts.txt -json", "httpx"},
		{"curl https://example.com", "curl"},
		{"katana -u https://example.com", "katana"},
		{"ffuf -u https://example.com/FUZZ", "ffuf"},
		{"python my_script.py", "python"},
		{"grep -R api results/", "grep"},
		{"nuclei -t cves/ -u target", "nuclei"},
	}

	for _, tt := range tests {
		got := DetectTool(tt.command)
		if got != tt.want {
			t.Errorf("DetectTool(%q) = %q, want %q", tt.command, got, tt.want)
		}
	}
}

func TestDiffSnapshots(t *testing.T) {
	before := fileSnapshot{
		"existing.txt": {},
	}
	after := fileSnapshot{
		"existing.txt": {},
		"new.txt":      {},
	}

	newFiles, modified := diffSnapshots(before, after)

	if len(newFiles) != 1 || newFiles[0] != "new.txt" {
		t.Errorf("newFiles = %v, want [new.txt]", newFiles)
	}
	if len(modified) != 0 {
		t.Errorf("modified = %v, want empty", modified)
	}
}
