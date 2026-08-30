package app

import (
	"path/filepath"

	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/parser/dns"
	"github.com/vKS-Rajput/doge/internal/parser/dnsx"
	"github.com/vKS-Rajput/doge/internal/parser/ffuf"
	"github.com/vKS-Rajput/doge/internal/parser/generic"
	"github.com/vKS-Rajput/doge/internal/parser/httpresponse"
	"github.com/vKS-Rajput/doge/internal/parser/httpx"
	"github.com/vKS-Rajput/doge/internal/parser/katana"
	"github.com/vKS-Rajput/doge/internal/parser/nmap"
	"github.com/vKS-Rajput/doge/internal/parser/nuclei"
	"github.com/vKS-Rajput/doge/internal/parser/subfinder"
	"github.com/vKS-Rajput/doge/internal/parser/whatweb"
)

// registerAllParsers registers all available parsers with the registry.
// Register more specific parsers before generic ones (first-match wins).
func registerAllParsers(registry *parser.Registry) {
	// Tier 1: Discovery tools.
	registry.Register(subfinder.New())
	registry.Register(dnsx.New())
	registry.Register(nmap.New())          // XML parser (first-match priority)
	registry.Register(nmap.NewTextParser()) // Text parser (stdout capture fallback)
	registry.Register(dns.New())           // dig/host/nslookup text

	// Tier 2: HTTP/Web enumeration.
	registry.Register(httpx.New())
	registry.Register(ffuf.New())
	registry.Register(katana.New())
	registry.Register(whatweb.New())
	registry.Register(httpresponse.New()) // curl/wget output

	// Tier 3: Security scanning.
	registry.Register(nuclei.New())

	// Tier 4: Generic evidence (LAST — broadest detection, lowest priority).
	registry.Register(generic.New())
}

// artifactsPath returns the path to the artifact content store.
func (a *App) artifactsPath() string {
	return filepath.Join(a.Workspace.RootPath, ".doge", "artifacts")
}
