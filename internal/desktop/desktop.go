package desktop

import (
	"context"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vKS-Rajput/doge/internal/runtime"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend
var assets embed.FS

// DesktopConfig parameterizes the DOGE native desktop workstation.
type DesktopConfig struct {
	WorkspaceRoot string
	TargetURL     string
	Scope         []string
	RequestBudget int
	IPCAddress    string
	Headless      bool
}

// Run boots the DOGE operating environment kernel and launches the native Wails workstation window.
func Run(cfg DesktopConfig) error {
	rtCfg := runtime.RuntimeConfig{
		WorkspaceRoot: cfg.WorkspaceRoot,
		TargetURL:     cfg.TargetURL,
		Scope:         cfg.Scope,
		RequestBudget: cfg.RequestBudget,
		IPCAddress:    cfg.IPCAddress,
	}

	rt := runtime.NewRuntime(rtCfg)
	ctx := context.Background()

	// Boot the DOGE runtime kernel (workspace, world model, WSL discovery, IPC)
	if err := rt.Start(ctx); err != nil {
		return fmt.Errorf("failed to start DOGE runtime kernel: %w", err)
	}

	// Headless mode: run kernel in background without opening native window
	if cfg.Headless {
		fmt.Println("◈ DOGE Operating Environment running in headless mode")
		if cfg.IPCAddress != "" {
			fmt.Printf("◈ Local IPC API listening on %s\n", cfg.IPCAddress)
		}
		select {} // Block indefinitely
	}

	// Check for compiled native Windows desktop application (C# / .NET)
	nativeExeCandidates := []string{
		filepath.Join(cfg.WorkspaceRoot, "desktop", "DOGE.Desktop", "bin", "Debug", "net10.0-windows", "DOGE.exe"),
		filepath.Join(cfg.WorkspaceRoot, "desktop", "DOGE.Desktop", "bin", "Release", "net10.0-windows", "DOGE.exe"),
		filepath.Join(cfg.WorkspaceRoot, "DOGE.exe"),
		"DOGE.exe",
	}

	for _, exePath := range nativeExeCandidates {
		if fi, err := os.Stat(exePath); err == nil && !fi.IsDir() {
			fmt.Printf("◈ Launching Native Windows Workstation: %s\n", exePath)
			cmd := exec.Command(exePath)
			if err := cmd.Start(); err == nil {
				return cmd.Wait()
			}
		}
	}

	// Create Wails App bound to DOGE runtime
	app := NewApp(rt)

	// Configure native window options
	appOptions := DefaultWindowOptions(app)
	appOptions.AssetServer = &assetserver.Options{
		Assets: assets,
	}
	appOptions.Menu = CreateApplicationMenu(app)

	// Launch native desktop workstation
	if err := wails.Run(appOptions); err != nil {
		return fmt.Errorf("DOGE desktop execution failed: %w", err)
	}

	return nil
}
