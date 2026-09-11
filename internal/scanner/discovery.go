package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sort"
)

// DiscoveredEndpoint represents a real endpoint found during reconnaissance.
type DiscoveredEndpoint struct {
	URL        string
	Method     string
	StatusCode int
	ContentType string
	HasParams  bool
	Params     []string
	Source     string // how it was discovered: "crawl", "robots", "sitemap", "bruteforce", "api-schema"
}

// Discovery performs real endpoint reconnaissance against a target.
type Discovery struct {
	client     *RateLimitedClient
	baseURL    string
	baseHost   string
	found      map[string]*DiscoveredEndpoint
	outOfScope []string
	log        func(string)
}

// NewDiscovery creates a new endpoint discovery engine.
func NewDiscovery(client *RateLimitedClient, baseURL string, outOfScope []string, logFn func(string)) *Discovery {
	parsed, _ := url.Parse(baseURL)
	host := ""
	if parsed != nil {
		host = parsed.Hostname()
	}
	return &Discovery{
		client:     client,
		baseURL:    strings.TrimRight(baseURL, "/"),
		baseHost:   host,
		found:      make(map[string]*DiscoveredEndpoint),
		outOfScope: outOfScope,
		log:        logFn,
	}
}

// Run executes the full discovery pipeline and returns all found endpoints.
func (d *Discovery) Run() []*DiscoveredEndpoint {
	d.log("[RECON] Starting endpoint discovery against " + d.baseURL)

	// Phase 1: Probe the root
	d.probeURL(d.baseURL, "root")

	// Phase 2: robots.txt
	d.parseRobots()

	// Phase 3: Common paths brute force
	d.bruteforcePaths()

	// Phase 4: API schema discovery
	d.discoverAPISchema()

	// Phase 5: Crawl discovered pages for links
	d.crawlForLinks()

	result := make([]*DiscoveredEndpoint, 0, len(d.found))
	for _, ep := range d.found {
		result = append(result, ep)
	}

	// Sort by URL for determinism
	sort.Slice(result, func(i, j int) bool {
		return result[i].URL < result[j].URL
	})

	d.log(fmt.Sprintf("[RECON] Discovery complete: found %d live endpoints", len(result)))
	return result
}

func (d *Discovery) probeURL(targetURL, source string) *DiscoveredEndpoint {
	if !IsInScope(targetURL, d.baseHost, d.outOfScope) {
		return nil
	}
	if _, exists := d.found[targetURL]; exists {
		return d.found[targetURL]
	}

	resp, err := d.client.Get(targetURL)
	if err != nil {
		return nil
	}

	// Only record live endpoints (not 404, not connection errors)
	if resp.StatusCode == 404 || resp.StatusCode == 0 {
		return nil
	}

	parsed, _ := url.Parse(targetURL)
	params := make([]string, 0)
	if parsed != nil {
		for k := range parsed.Query() {
			params = append(params, k)
		}
	}

	ep := &DiscoveredEndpoint{
		URL:         targetURL,
		Method:      "GET",
		StatusCode:  resp.StatusCode,
		ContentType: resp.Headers.Get("Content-Type"),
		HasParams:   len(params) > 0,
		Params:      params,
		Source:       source,
	}
	d.found[targetURL] = ep
	d.log(fmt.Sprintf("[RECON] Found: %s [%d] (%s)", targetURL, resp.StatusCode, source))
	return ep
}

func (d *Discovery) parseRobots() {
	robotsURL := d.baseURL + "/robots.txt"
	resp, err := d.client.Get(robotsURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}

	body := string(resp.Body)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				if path != "" && path != "/" && !strings.Contains(path, "*") {
					d.probeURL(d.baseURL+path, "robots")
				}
			}
		}
		if strings.HasPrefix(line, "Sitemap:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				sitemapURL := strings.TrimSpace(parts[1])
				if strings.HasPrefix(sitemapURL, "http") {
					d.probeURL(sitemapURL, "sitemap-ref")
				}
			}
		}
	}
	d.log(fmt.Sprintf("[RECON] Parsed robots.txt: extracted paths"))
}

func (d *Discovery) bruteforcePaths() {
	// Common paths that real applications expose
	paths := []string{
		"/", "/api", "/api/v1", "/api/v2", "/api/v3",
		"/graphql", "/graphiql",
		"/swagger.json", "/swagger/", "/swagger-ui/",
		"/openapi.json", "/api-docs", "/docs",
		"/health", "/healthz", "/health/live", "/health/ready",
		"/status", "/info", "/version", "/metrics",
		"/login", "/register", "/signup", "/auth", "/oauth",
		"/admin", "/admin/login", "/dashboard",
		"/user", "/users", "/profile", "/account",
		"/search", "/config", "/settings",
		"/.env", "/.git/HEAD", "/.git/config",
		"/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
		"/server-status", "/server-info",
		"/debug", "/debug/pprof", "/debug/vars",
		"/actuator", "/actuator/health", "/actuator/env",
		"/console", "/trace", "/heapdump",
		"/sitemap.xml", "/crossdomain.xml",
		"/api/users", "/api/user", "/api/admin",
		"/api/v1/users", "/api/v1/user",
		"/api/v1/items", "/api/v1/orders", "/api/v1/products",
		"/api/v1/config", "/api/v1/settings",
		"/api/v1/health", "/api/v1/status",
		"/internal", "/private", "/secret",
		"/backup", "/dump", "/export",
		"/test", "/dev", "/staging",
		"/phpinfo.php", "/info.php",
		"/cgi-bin/", "/fcgi-bin/",
		"/.well-known/security.txt",
		"/.well-known/openid-configuration",
		"/favicon.ico",
		"/tokens", "/api/tokens", "/api/v1/tokens",
		"/reset-password", "/forgot-password",
	}

	d.log(fmt.Sprintf("[RECON] Probing %d common paths...", len(paths)))
	for _, path := range paths {
		if d.client.BudgetRemaining() < 20 {
			d.log("[RECON] Reserving budget for vulnerability testing, stopping path brute force")
			break
		}
		d.probeURL(d.baseURL+path, "bruteforce")
	}
}

func (d *Discovery) discoverAPISchema() {
	// Check for OpenAPI/Swagger schemas
	schemaPaths := []string{
		"/swagger.json", "/openapi.json", "/api-docs",
		"/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
		"/api/swagger.json", "/api/openapi.json",
		"/docs/openapi.json",
	}

	for _, path := range schemaPaths {
		fullURL := d.baseURL + path
		resp, err := d.client.Get(fullURL)
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		ct := strings.ToLower(resp.Headers.Get("Content-Type"))
		if strings.Contains(ct, "json") || strings.Contains(string(resp.Body), "\"paths\"") {
			d.log(fmt.Sprintf("[RECON] Found API schema at %s — extracting endpoints", path))
			d.extractPathsFromSchema(string(resp.Body))
			break
		}
	}
}

func (d *Discovery) extractPathsFromSchema(body string) {
	// Simple regex extraction of paths from OpenAPI/Swagger JSON
	// Looks for "paths" -> { "/some/path": ... }
	pathRegex := regexp.MustCompile(`"(/[a-zA-Z0-9_\-/{}\.]+)"`)
	matches := pathRegex.FindAllStringSubmatch(body, 100)

	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		path := m[1]
		// Skip non-path strings
		if !strings.HasPrefix(path, "/") {
			continue
		}
		// Replace path params {id} with test values
		paramPath := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "1")
		if seen[paramPath] {
			continue
		}
		seen[paramPath] = true
		d.probeURL(d.baseURL+paramPath, "api-schema")
	}
}

func (d *Discovery) crawlForLinks() {
	// Crawl HTML pages for additional links
	linkRegex := regexp.MustCompile(`(?:href|src|action)=["']([^"']+)["']`)
	apiRegex := regexp.MustCompile(`["']((?:/api/|/v[0-9]+/)[^"'\s]+)["']`)

	pagesToCrawl := make([]string, 0)
	for _, ep := range d.found {
		if strings.Contains(ep.ContentType, "html") || strings.Contains(ep.ContentType, "json") {
			pagesToCrawl = append(pagesToCrawl, ep.URL)
		}
	}

	for _, pageURL := range pagesToCrawl {
		if d.client.BudgetRemaining() < 20 {
			break
		}

		resp, err := d.client.Get(pageURL)
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		body := string(resp.Body)

		// Extract href/src links
		matches := linkRegex.FindAllStringSubmatch(body, 50)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			link := m[1]
			resolved := resolveURL(d.baseURL, pageURL, link)
			if resolved != "" {
				d.probeURL(resolved, "crawl")
			}
		}

		// Extract API-like paths from JS/JSON
		apiMatches := apiRegex.FindAllStringSubmatch(body, 50)
		for _, m := range apiMatches {
			if len(m) < 2 {
				continue
			}
			d.probeURL(d.baseURL+m[1], "crawl-api")
		}
	}
}

func resolveURL(baseURL, pageURL, link string) string {
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return link
	}
	if strings.HasPrefix(link, "//") {
		return "https:" + link
	}
	if strings.HasPrefix(link, "/") {
		parsed, err := url.Parse(baseURL)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, link)
	}
	if strings.HasPrefix(link, "#") || strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "javascript:") {
		return ""
	}
	// Relative URL
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// DiscoverEndpointsForMethod attempts to find what HTTP methods an endpoint accepts.
func (d *Discovery) DiscoverEndpointsForMethod(ep *DiscoveredEndpoint) []string {
	methods := []string{"GET"}

	// Try OPTIONS to discover allowed methods
	req, err := http.NewRequest("OPTIONS", ep.URL, nil)
	if err != nil {
		return methods
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return methods
	}

	allow := resp.Headers.Get("Allow")
	if allow != "" {
		parts := strings.Split(allow, ",")
		methods = make([]string, 0, len(parts))
		for _, m := range parts {
			methods = append(methods, strings.TrimSpace(m))
		}
		return methods
	}

	// Try POST, PUT, DELETE, PATCH
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		req, err := http.NewRequest(method, ep.URL, strings.NewReader("{}"))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != 405 && resp.StatusCode != 404 {
			methods = append(methods, method)
		}
	}

	return methods
}
