package desktop

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/runtime"
)

func TestEmbeddedFrontendAssets(t *testing.T) {
	// Verify index.html exists in embedded assets
	indexBytes, err := assets.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatalf("failed to read embedded index.html: %v", err)
	}
	if len(indexBytes) == 0 {
		t.Errorf("embedded index.html is empty")
	}

	// Verify app.css exists
	cssBytes, err := assets.ReadFile("frontend/app.css")
	if err != nil {
		t.Fatalf("failed to read embedded app.css: %v", err)
	}
	if len(cssBytes) == 0 {
		t.Errorf("embedded app.css is empty")
	}

	// Verify app.js exists
	jsBytes, err := assets.ReadFile("frontend/app.js")
	if err != nil {
		t.Fatalf("failed to read embedded app.js: %v", err)
	}
	if len(jsBytes) == 0 {
		t.Errorf("embedded app.js is empty")
	}
}

func TestAppBindingsAndLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "doge-desktop-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	rtCfg := runtime.RuntimeConfig{
		WorkspaceRoot: tempDir,
		TargetURL:     "https://test.local",
		Scope:         []string{"test.local"},
		RequestBudget: 50,
		IPCAddress:    "127.0.0.1:0",
	}

	rt := runtime.NewRuntime(rtCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rt.Start(ctx); err != nil {
		t.Fatalf("failed to start runtime: %v", err)
	}
	defer func() {
		_ = rt.Stop()
	}()

	app := NewApp(rt)

	// Test GetStatus
	status, err := app.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if status["state"] != "READY" {
		t.Errorf("expected state READY, got %v", status["state"])
	}

	// Test GetEnvironment
	env, err := app.GetEnvironment()
	if err != nil {
		t.Fatalf("GetEnvironment failed: %v", err)
	}
	if env == nil || env.OperatingSystem == "" {
		t.Errorf("expected valid environment object")
	}

	// Test Autonomy Level setting
	if err := app.SetAutonomyLevel(5); err != nil {
		t.Errorf("SetAutonomyLevel failed: %v", err)
	}

	// Test Personality Mode setting
	if err := app.SetPersonalityMode("operator"); err != nil {
		t.Errorf("SetPersonalityMode failed: %v", err)
	}
}

func TestMenuAndCommandsCatalog(t *testing.T) {
	rt := runtime.NewRuntime(runtime.RuntimeConfig{})
	app := NewApp(rt)

	appMenu := CreateApplicationMenu(app)
	if appMenu == nil {
		t.Fatalf("CreateApplicationMenu returned nil")
	}

	trayMenu := CreateTrayMenu(app)
	if trayMenu == nil {
		t.Fatalf("CreateTrayMenu returned nil")
	}

	commands := GetCommandCatalog()
	if len(commands) < 5 {
		t.Errorf("expected at least 5 conceptual commands, got %d", len(commands))
	}
}
