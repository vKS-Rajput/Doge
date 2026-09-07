package app

import (
	"path/filepath"

	"github.com/vKS-Rajput/doge/internal/parser"
	"github.com/vKS-Rajput/doge/internal/parser/amass"
	"github.com/vKS-Rajput/doge/internal/parser/assetfinder"
	"github.com/vKS-Rajput/doge/internal/parser/dalfox"
	"github.com/vKS-Rajput/doge/internal/parser/dirsearch"
	"github.com/vKS-Rajput/doge/internal/parser/dns"
	"github.com/vKS-Rajput/doge/internal/parser/dnsrecon"
	"github.com/vKS-Rajput/doge/internal/parser/dnsx"
	"github.com/vKS-Rajput/doge/internal/parser/feroxbuster"
	"github.com/vKS-Rajput/doge/internal/parser/ffuf"
	"github.com/vKS-Rajput/doge/internal/parser/gau"
	"github.com/vKS-Rajput/doge/internal/parser/generic"
	"github.com/vKS-Rajput/doge/internal/parser/gobuster"
	"github.com/vKS-Rajput/doge/internal/parser/hakrawler"
	"github.com/vKS-Rajput/doge/internal/parser/httpresponse"
	"github.com/vKS-Rajput/doge/internal/parser/httpx"
	"github.com/vKS-Rajput/doge/internal/parser/katana"
	"github.com/vKS-Rajput/doge/internal/parser/kxss"
	"github.com/vKS-Rajput/doge/internal/parser/masscan"
	"github.com/vKS-Rajput/doge/internal/parser/nmap"
	"github.com/vKS-Rajput/doge/internal/parser/nuclei"
	"github.com/vKS-Rajput/doge/internal/parser/sqlmap"
	"github.com/vKS-Rajput/doge/internal/parser/subfinder"
	"github.com/vKS-Rajput/doge/internal/parser/whatweb"
	"github.com/vKS-Rajput/doge/internal/parser/whois"
)

// RegisterParsers registers all available parsers with the registry.
// Register more specific parsers before generic ones (first-match wins).
func RegisterParsers(registry *parser.Registry) {
	// Tier 1: Subdomain and Asset Discovery.
	registry.Register(subfinder.New())
	registry.Register(assetfinder.New())
	registry.Register(amass.New())
	registry.Register(dnsx.New())
	registry.Register(dnsrecon.New())
	registry.Register(dns.New())           // dig/host/nslookup text
	registry.Register(whois.New())

	// Tier 2: Port and Service Discovery.
	registry.Register(nmap.New())          // XML parser (first-match priority)
	registry.Register(nmap.NewTextParser()) // Text parser (stdout capture fallback)
	registry.Register(masscan.New())

	// Tier 3: HTTP/Web enumeration & Crawling.
	registry.Register(httpx.New())
	registry.Register(whatweb.New())
	registry.Register(httpresponse.New()) // curl/wget output
	registry.Register(katana.New())
	registry.Register(hakrawler.New())
	registry.Register(gau.New())          // gau and waybackurls

	// Tier 4: Directory & Content Fuzzing.
	registry.Register(ffuf.New())
	registry.Register(feroxbuster.New())
	registry.Register(gobuster.New())
	registry.Register(dirsearch.New())

	// Tier 5: Vulnerability Analysis & Reflection.
	registry.Register(nuclei.New())
	registry.Register(dalfox.New())
	registry.Register(kxss.New())
	registry.Register(sqlmap.New())

	// Tier 6: Generic evidence (LAST — broadest detection, lowest priority).
	registry.Register(generic.New())
}

// artifactsPath returns the path to the artifact content store.
func (a *App) artifactsPath() string {
	return filepath.Join(a.Workspace.RootPath, ".doge", "artifacts")
}
