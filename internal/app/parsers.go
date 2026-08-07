package app

import (
	"path/filepath"

	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/parser/httpx"
)

// registerAllParsers registers all available parsers with the registry.
// Register more specific parsers before generic ones (first-match wins).
func registerAllParsers(registry *parser.Registry) {
	registry.Register(httpx.New())
	// Future: registry.Register(nuclei.New())
	// Future: registry.Register(subfinder.New())
	// Future: registry.Register(nmap.New())
}

// artifactsPath returns the path to the artifact content store.
func (a *App) artifactsPath() string {
	return filepath.Join(a.Workspace.RootPath, ".doge", "artifacts")
}
