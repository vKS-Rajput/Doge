package app

import (
	"path/filepath"

	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/parser/dnsx"
	"github.com/vKS-Rajput/doge/internal/parser/ffuf"
	"github.com/vKS-Rajput/doge/internal/parser/httpx"
	"github.com/vKS-Rajput/doge/internal/parser/katana"
	"github.com/vKS-Rajput/doge/internal/parser/nmap"
	"github.com/vKS-Rajput/doge/internal/parser/nuclei"
	"github.com/vKS-Rajput/doge/internal/parser/subfinder"
)

// registerAllParsers registers all available parsers with the registry.
// Register more specific parsers before generic ones (first-match wins).
func registerAllParsers(registry *parser.Registry) {
	// Tier 1: Discovery tools.
	registry.Register(subfinder.New())
	registry.Register(dnsx.New())
	registry.Register(nmap.New())

	// Tier 2: Enumeration.
	registry.Register(httpx.New())
	registry.Register(ffuf.New())
	registry.Register(katana.New())

	// Tier 3: Security scanning.
	registry.Register(nuclei.New())
}

// artifactsPath returns the path to the artifact content store.
func (a *App) artifactsPath() string {
	return filepath.Join(a.Workspace.RootPath, ".doge", "artifacts")
}
