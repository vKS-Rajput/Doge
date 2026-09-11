package runtime

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWSLPathConversions(t *testing.T) {
	mgr := NewWSLManager(nil)

	// Windows -> WSL
	winPath := `C:\Users\test\workspace`
	wslPath := mgr.ConvertPathToWSL(winPath)
	expectedWSL := "/mnt/c/Users/test/workspace"
	if wslPath != expectedWSL {
		t.Errorf("expected %s, got %s", expectedWSL, wslPath)
	}

	// WSL -> Windows
	backToWin := mgr.ConvertPathToWindows(wslPath)
	expectedWin := `C:\Users\test\workspace`
	if backToWin != expectedWin {
		t.Errorf("expected %s, got %s", expectedWin, backToWin)
	}
}

func TestCleanWSLText(t *testing.T) {
	// Normal UTF-8
	raw := []byte("kali-linux Running 2\n")
	cleaned := cleanWSLText(raw)
	if cleaned != "kali-linux Running 2\n" {
		t.Errorf("expected clean string, got %q", cleaned)
	}

	// Null-interleaved (simulating Windows console UTF-16LE)
	nullInterleaved := []byte{'k', 0, 'a', 0, 'l', 0, 'i', 0, '\n', 0}
	cleanedNull := cleanWSLText(nullInterleaved)
	if cleanedNull != "kali\n" {
		t.Errorf("expected %q, got %q", "kali\n", cleanedNull)
	}
}

func TestWorkspaceInitializationAndLoad(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "doge-ws-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	wsMgr := NewWorkspaceManager()

	ws, err := wsMgr.Initialize(tempDir, "Test Research Project", "https://test.local", []string{"test.local", "api.test.local"})
	if err != nil {
		t.Fatalf("failed to initialize workspace: %v", err)
	}

	if ws.Config.Name != "Test Research Project" {
		t.Errorf("expected name %s, got %s", "Test Research Project", ws.Config.Name)
	}
	if ws.Config.Target != "https://test.local" {
		t.Errorf("expected target %s, got %s", "https://test.local", ws.Config.Target)
	}

	// Verify directory exists
	dogeDir := filepath.Join(tempDir, ".doge")
	if _, err := os.Stat(filepath.Join(dogeDir, "workspace.toml")); os.IsNotExist(err) {
		t.Errorf("workspace.toml not created")
	}
	if _, err := os.Stat(filepath.Join(dogeDir, "policy.toml")); os.IsNotExist(err) {
		t.Errorf("policy.toml not created")
	}
	if _, err := os.Stat(filepath.Join(dogeDir, "evidence")); os.IsNotExist(err) {
		t.Errorf("evidence directory not created")
	}

	// Load workspace back
	loaded, err := wsMgr.Load(tempDir)
	if err != nil {
		t.Fatalf("failed to load workspace: %v", err)
	}
	if loaded.Config.Name != "Test Research Project" {
		t.Errorf("expected loaded name %s, got %s", "Test Research Project", loaded.Config.Name)
	}
	if len(loaded.Config.Scope) != 2 {
		t.Errorf("expected 2 scope entries, got %d", len(loaded.Config.Scope))
	}
}

func TestLifecycleTransitions(t *testing.T) {
	b := NewEventBroadcaster(50)
	lm := NewLifecycleManager(b)

	if lm.GetState() != StateUninitialized {
		t.Fatalf("expected initial state %s, got %s", StateUninitialized, lm.GetState())
	}

	// Valid transition: Uninitialized -> Starting
	if err := lm.TransitionTo(StateStarting, "boot"); err != nil {
		t.Fatalf("failed valid transition: %v", err)
	}

	// Valid transition: Starting -> Ready
	if err := lm.TransitionTo(StateReady, "ready"); err != nil {
		t.Fatalf("failed valid transition: %v", err)
	}

	// Valid transition: Ready -> Researching
	if err := lm.TransitionTo(StateResearching, "start research"); err != nil {
		t.Fatalf("failed valid transition: %v", err)
	}

	// Valid transition: Researching -> Paused
	if err := lm.TransitionTo(StatePaused, "pause"); err != nil {
		t.Fatalf("failed valid transition: %v", err)
	}

	// Valid transition: Paused -> Stopped
	if err := lm.TransitionTo(StateStopped, "stop"); err != nil {
		t.Fatalf("failed valid transition: %v", err)
	}

	// Invalid transition: Stopped -> Researching (must go via Starting or Ready)
	if err := lm.TransitionTo(StateResearching, "invalid"); err == nil {
		t.Errorf("expected error for invalid transition from Stopped to Researching")
	}
}

func TestResourceGovernor(t *testing.T) {
	gov := NewResourceGovernor(10, 2, 5)

	if err := gov.CheckExecutionCapacity(); err != nil {
		t.Fatalf("expected capacity available: %v", err)
	}

	// Record 8 requests
	if err := gov.RecordRequests(8); err != nil {
		t.Fatalf("failed to record requests: %v", err)
	}

	// Record 3 more (would exceed budget 10)
	if err := gov.RecordRequests(3); err == nil {
		t.Errorf("expected error when exceeding budget")
	}

	// Concurrency cap test
	gov.IncrementActiveProcess()
	gov.IncrementActiveProcess()
	if err := gov.CheckExecutionCapacity(); err == nil {
		t.Errorf("expected error when active processes reach limit of 2")
	}

	gov.DecrementActiveProcess()
	if err := gov.CheckExecutionCapacity(); err != nil {
		t.Fatalf("expected capacity available after decrement: %v", err)
	}
}

func TestRuntimeBootAndProcessStream(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "doge-runtime-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := RuntimeConfig{
		WorkspaceRoot: tempDir,
		TargetURL:     "http://127.0.0.1:8888",
		Scope:         []string{"127.0.0.1"},
		RequestBudget: 100,
		IPCAddress:    "127.0.0.1:0", // auto port
	}

	rt := NewRuntime(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rt.Start(ctx); err != nil {
		t.Fatalf("failed to boot runtime: %v", err)
	}
	defer func() {
		_ = rt.Stop()
	}()

	if rt.GetState() != StateReady {
		t.Errorf("expected runtime state READY, got %s", rt.GetState())
	}

	// Test Process Execution & Streaming
	var streamedLines []string
	req := ExecutionRequest{
		Command: "go",
		Args:    []string{"version"},
	}

	res, err := rt.Stream(ctx, req, func(line string) {
		streamedLines = append(streamedLines, line)
	}, nil)

	if err != nil {
		t.Fatalf("stream execution failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if len(streamedLines) == 0 {
		t.Errorf("expected streamed output lines")
	}
}

func TestIPCServerEndpoints(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "doge-ipc-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := RuntimeConfig{
		WorkspaceRoot: tempDir,
		TargetURL:     "http://127.0.0.1:9090",
		Scope:         []string{"127.0.0.1"},
		RequestBudget: 100,
		IPCAddress:    "127.0.0.1:0",
	}

	rt := NewRuntime(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := rt.Start(ctx); err != nil {
		t.Fatalf("failed to boot runtime: %v", err)
	}
	defer func() {
		_ = rt.Stop()
	}()

	ipcAddr := rt.ipcServer.Addr()
	if ipcAddr == "" {
		t.Fatalf("IPC server address is empty")
	}

	// 1. Query /api/status
	resp, err := http.Get("http://" + ipcAddr + "/api/status")
	if err != nil {
		t.Fatalf("failed to query /api/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// 2. Query /api/environment
	respEnv, err := http.Get("http://" + ipcAddr + "/api/environment")
	if err != nil {
		t.Fatalf("failed to query /api/environment: %v", err)
	}
	defer respEnv.Body.Close()
	if respEnv.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", respEnv.StatusCode)
	}
}
