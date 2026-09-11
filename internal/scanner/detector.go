package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// VulnType identifies a class of vulnerability.
type VulnType string

const (
	VulnBOLA              VulnType = "BOLA/IDOR"
	VulnSQLi              VulnType = "SQL_INJECTION"
	VulnXSS               VulnType = "REFLECTED_XSS"
	VulnSSRF              VulnType = "SSRF"
	VulnOpenRedirect      VulnType = "OPEN_REDIRECT"
	VulnInfoDisclosure    VulnType = "INFORMATION_DISCLOSURE"
	VulnPathTraversal     VulnType = "PATH_TRAVERSAL"
	VulnCORSMisconfig     VulnType = "CORS_MISCONFIGURATION"
	VulnMissingHeaders    VulnType = "MISSING_SECURITY_HEADERS"
	VulnDebugEndpoint     VulnType = "DEBUG_ENDPOINT_EXPOSED"
	VulnSensitiveFile     VulnType = "SENSITIVE_FILE_EXPOSED"
	VulnVerbTampering     VulnType = "HTTP_VERB_TAMPERING"
	VulnHostHeader        VulnType = "HOST_HEADER_INJECTION"
	VulnCRLFInjection     VulnType = "CRLF_INJECTION"
	VulnCommandInjection  VulnType = "COMMAND_INJECTION"
	VulnTimingOracle      VulnType = "TIMING_SIDE_CHANNEL"
)

// Finding represents a confirmed vulnerability with proof data.
type Finding struct {
	Type        VulnType
	Severity    string // "Critical", "High", "Medium", "Low", "Info"
	Title       string
	Description string
	Endpoint    string
	Evidence    []CapturedResponse // The actual HTTP requests/responses proving the vuln
	Confidence  float64            // 0.0 - 1.0
	CWE         string
	CVSS        float64
	Remediation string
}

// Detector runs vulnerability checks against discovered endpoints.
type Detector struct {
	client   *RateLimitedClient
	baseURL  string
	baseHost string
	findings []Finding
	log      func(string)
}

// NewDetector creates a vulnerability detection engine.
func NewDetector(client *RateLimitedClient, baseURL string, logFn func(string)) *Detector {
	parsed, _ := url.Parse(baseURL)
	host := ""
	if parsed != nil {
		host = parsed.Hostname()
	}
	return &Detector{
		client:   client,
		baseURL:  strings.TrimRight(baseURL, "/"),
		baseHost: host,
		findings: make([]Finding, 0),
		log:      logFn,
	}
}

// RunAll executes all detection modules against the given endpoints.
func (d *Detector) RunAll(endpoints []*DiscoveredEndpoint) []Finding {
	d.log(fmt.Sprintf("[DETECT] Running vulnerability detection against %d endpoints", len(endpoints)))

	for _, ep := range endpoints {
		if d.client.BudgetRemaining() < 5 {
			d.log("[DETECT] Budget low, stopping detection")
			break
		}

		d.checkInfoDisclosure(ep)
		d.checkSecurityHeaders(ep)
		d.checkCORS(ep)
		d.checkBOLA(ep)
		d.checkSQLInjection(ep)
		d.checkXSS(ep)
		d.checkPathTraversal(ep)
		d.checkOpenRedirect(ep)
		d.checkSSRF(ep)
		d.checkHostHeaderInjection(ep)
		d.checkVerbTampering(ep)
		d.checkTimingOracle(ep)
		d.checkCommandInjection(ep)
	}

	d.log(fmt.Sprintf("[DETECT] Detection complete: %d vulnerabilities found", len(d.findings)))
	return d.findings
}

func (d *Detector) addFinding(f Finding) {
	d.findings = append(d.findings, f)
	d.log(fmt.Sprintf("[VULN] [%s] %s: %s — %s", f.Severity, f.Type, f.Title, f.Endpoint))
}

// --- Information Disclosure ---

func (d *Detector) checkInfoDisclosure(ep *DiscoveredEndpoint) {
	body := ""
	resp, err := d.client.Get(ep.URL)
	if err != nil {
		return
	}
	body = strings.ToLower(string(resp.Body))

	// Check for sensitive data patterns
	sensitivePatterns := []struct {
		pattern string
		title   string
		desc    string
	}{
		{"stack trace", "Stack Trace Exposed", "Application exposes internal stack traces to users"},
		{"traceback (most recent", "Python Traceback Exposed", "Python application exposes debug tracebacks"},
		{"at java.", "Java Stack Trace Exposed", "Java application exposes internal stack traces"},
		{"panic:", "Go Panic Trace Exposed", "Go application exposes panic stack traces"},
		{"phpinfo()", "PHPInfo Page Exposed", "PHP info page reveals server configuration"},
		{"db_password", "Database Credentials Exposed", "Database credentials visible in response"},
		{"api_key", "API Key Exposed", "API key leaked in response body"},
		{"secret_key", "Secret Key Exposed", "Application secret key leaked in response"},
		{"password", "Password Field in Response", "Password data present in API response"},
		{"internal server error", "Verbose Error Messages", "Application returns verbose error messages"},
	}

	for _, sp := range sensitivePatterns {
		if strings.Contains(body, sp.pattern) {
			d.addFinding(Finding{
				Type:        VulnInfoDisclosure,
				Severity:    "Medium",
				Title:       sp.title,
				Description: sp.desc,
				Endpoint:    ep.URL,
				Evidence:    []CapturedResponse{*resp},
				Confidence:  0.8,
				CWE:         "CWE-200",
				CVSS:        5.3,
				Remediation: "Disable verbose error messages and debug output in production.",
			})
			break // One info disclosure finding per endpoint
		}
	}

	// Check for sensitive file paths
	sensitiveFiles := map[string]string{
		"/.env":            "Environment file with secrets",
		"/.git/HEAD":       "Git repository metadata",
		"/.git/config":     "Git configuration with potential remote URLs",
		"/wp-config.php":   "WordPress configuration",
		"/config.php":      "PHP configuration file",
		"/backup.sql":      "SQL database backup",
		"/dump.sql":        "SQL database dump",
		"/.htpasswd":       "Apache password file",
		"/.htaccess":       "Apache configuration",
		"/server-status":   "Apache server status page",
		"/debug/pprof":     "Go pprof debug endpoint",
		"/actuator/env":    "Spring Boot environment variables",
		"/trace":           "Spring Boot trace endpoint",
		"/heapdump":        "JVM heap dump endpoint",
	}

	for path, desc := range sensitiveFiles {
		if ep.URL == d.baseURL+path && ep.StatusCode == 200 {
			sev := "High"
			if strings.Contains(path, ".git") || strings.Contains(path, ".env") {
				sev = "Critical"
			}
			d.addFinding(Finding{
				Type:        VulnSensitiveFile,
				Severity:    sev,
				Title:       "Sensitive File Accessible: " + path,
				Description: desc,
				Endpoint:    ep.URL,
				Evidence:    []CapturedResponse{*resp},
				Confidence:  0.95,
				CWE:         "CWE-538",
				CVSS:        7.5,
				Remediation: fmt.Sprintf("Block access to %s in web server configuration.", path),
			})
		}
	}

	// Debug endpoints
	debugPaths := []string{"/debug", "/debug/pprof", "/debug/vars", "/actuator", "/console", "/graphiql"}
	for _, dp := range debugPaths {
		if ep.URL == d.baseURL+dp && ep.StatusCode == 200 {
			d.addFinding(Finding{
				Type:        VulnDebugEndpoint,
				Severity:    "High",
				Title:       "Debug Endpoint Exposed: " + dp,
				Description: "Debug/diagnostic endpoint is publicly accessible",
				Endpoint:    ep.URL,
				Evidence:    []CapturedResponse{*resp},
				Confidence:  0.9,
				CWE:         "CWE-489",
				CVSS:        7.5,
				Remediation: "Disable or restrict access to debug endpoints in production.",
			})
		}
	}
}

// --- Security Headers ---

func (d *Detector) checkSecurityHeaders(ep *DiscoveredEndpoint) {
	if ep.StatusCode != 200 || !strings.Contains(ep.ContentType, "html") {
		return
	}

	resp, err := d.client.Get(ep.URL)
	if err != nil {
		return
	}

	missing := make([]string, 0)
	important := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":          "",
		"Strict-Transport-Security": "",
		"Content-Security-Policy":   "",
		"X-XSS-Protection":         "",
	}

	for header := range important {
		if resp.Headers.Get(header) == "" {
			missing = append(missing, header)
		}
	}

	if len(missing) >= 3 {
		d.addFinding(Finding{
			Type:        VulnMissingHeaders,
			Severity:    "Low",
			Title:       fmt.Sprintf("Missing %d Security Headers", len(missing)),
			Description: fmt.Sprintf("Missing: %s", strings.Join(missing, ", ")),
			Endpoint:    ep.URL,
			Evidence:    []CapturedResponse{*resp},
			Confidence:  1.0,
			CWE:         "CWE-693",
			CVSS:        3.7,
			Remediation: "Add security headers: " + strings.Join(missing, ", "),
		})
	}
}

// --- CORS Misconfiguration ---

func (d *Detector) checkCORS(ep *DiscoveredEndpoint) {
	if !strings.Contains(ep.ContentType, "json") && !strings.Contains(ep.URL, "/api") {
		return
	}

	// Test with arbitrary origin
	req, err := http.NewRequest("GET", ep.URL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", "https://evil-attacker.com")
	resp, err := d.client.Do(req)
	if err != nil {
		return
	}

	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	acac := resp.Headers.Get("Access-Control-Allow-Credentials")

	if acao == "*" && strings.EqualFold(acac, "true") {
		d.addFinding(Finding{
			Type:        VulnCORSMisconfig,
			Severity:    "High",
			Title:       "CORS Allows All Origins with Credentials",
			Description: "API returns Access-Control-Allow-Origin: * with Allow-Credentials: true",
			Endpoint:    ep.URL,
			Evidence:    []CapturedResponse{*resp},
			Confidence:  0.95,
			CWE:         "CWE-942",
			CVSS:        8.1,
			Remediation: "Configure CORS to only allow trusted origins. Never use * with credentials.",
		})
	} else if acao == "https://evil-attacker.com" {
		d.addFinding(Finding{
			Type:        VulnCORSMisconfig,
			Severity:    "High",
			Title:       "CORS Reflects Arbitrary Origin",
			Description: "API reflects arbitrary Origin header in Access-Control-Allow-Origin",
			Endpoint:    ep.URL,
			Evidence:    []CapturedResponse{*resp},
			Confidence:  0.95,
			CWE:         "CWE-942",
			CVSS:        8.1,
			Remediation: "Whitelist specific trusted origins instead of reflecting the Origin header.",
		})
	}
}

// --- BOLA / IDOR ---

func (d *Detector) checkBOLA(ep *DiscoveredEndpoint) {
	// BOLA/IDOR: Try accessing resources with different or no auth
	// Look for API endpoints with IDs in the path
	idRegex := regexp.MustCompile(`(/[a-zA-Z]+/)\d+(/|$)`)
	if !idRegex.MatchString(ep.URL) {
		return
	}

	// Get baseline response (with auth)
	baseResp, err := d.client.Get(ep.URL)
	if err != nil || baseResp.StatusCode != 200 {
		return
	}

	// Try incrementing the numeric ID
	modified := idRegex.ReplaceAllStringFunc(ep.URL, func(match string) string {
		parts := idRegex.FindStringSubmatch(match)
		if len(parts) > 1 {
			return parts[1] + "9999" + strings.TrimLeft(match[len(parts[1]):], "0123456789")
		}
		return match
	})

	if modified == ep.URL {
		return
	}

	modResp, err := d.client.Get(modified)
	if err != nil {
		return
	}

	// If we can access another user's resource (200 with different ID)
	if modResp.StatusCode == 200 && len(modResp.Body) > 10 {
		// Try without auth header
		req, _ := http.NewRequest("GET", ep.URL, nil)
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		noAuthResp, err := d.client.Do(req)

		if err == nil && noAuthResp.StatusCode == 200 {
			d.addFinding(Finding{
				Type:        VulnBOLA,
				Severity:    "Critical",
				Title:       "Broken Object Level Authorization (BOLA/IDOR)",
				Description: fmt.Sprintf("Resource accessible without proper authorization. Original: %s, Modified ID: %s both return 200 with data.", ep.URL, modified),
				Endpoint:    ep.URL,
				Evidence:    []CapturedResponse{*baseResp, *modResp, *noAuthResp},
				Confidence:  0.85,
				CWE:         "CWE-639",
				CVSS:        9.1,
				Remediation: "Implement proper authorization checks. Verify the requesting user owns or has permission to access the requested resource.",
			})
		} else if modResp.StatusCode == 200 {
			d.addFinding(Finding{
				Type:        VulnBOLA,
				Severity:    "High",
				Title:       "Potential IDOR — Cross-Object Access",
				Description: fmt.Sprintf("Enumerated ID returns data: %s (original) and %s (modified) both return 200", ep.URL, modified),
				Endpoint:    ep.URL,
				Evidence:    []CapturedResponse{*baseResp, *modResp},
				Confidence:  0.7,
				CWE:         "CWE-639",
				CVSS:        7.5,
				Remediation: "Implement proper authorization checks on object access.",
			})
		}
	}
}

// --- SQL Injection ---

func (d *Detector) checkSQLInjection(ep *DiscoveredEndpoint) {
	if !ep.HasParams && !strings.Contains(ep.URL, "/api") {
		return
	}

	sqlPayloads := []struct {
		payload  string
		errorSig []string
	}{
		{"'", []string{"sql", "syntax error", "mysql", "postgres", "sqlite", "oracle", "unterminated", "unexpected"}},
		{"' OR '1'='1", []string{"sql", "syntax", "error"}},
		{"1 AND 1=1", nil},
		{"1 AND 1=2", nil},
		{"'; WAITFOR DELAY '0:0:1'--", nil},
		{"1; SELECT 1--", []string{"sql", "syntax", "error", "command"}},
	}

	// Get baseline
	baseResp, err := d.client.Get(ep.URL)
	if err != nil {
		return
	}

	for _, p := range sqlPayloads {
		if d.client.BudgetRemaining() < 5 {
			return
		}

		testURL := ep.URL
		parsed, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}

		// Inject into existing params or as query param
		q := parsed.Query()
		if len(q) > 0 {
			for key := range q {
				q.Set(key, p.payload)
				break // Test first param
			}
			parsed.RawQuery = q.Encode()
			testURL = parsed.String()
		} else {
			// Try appending to path
			if strings.Contains(ep.URL, "/api/") {
				testURL = ep.URL + "?id=" + url.QueryEscape(p.payload)
			} else {
				continue
			}
		}

		resp, err := d.client.Get(testURL)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(string(resp.Body))

		// Check for SQL error signatures
		if p.errorSig != nil {
			for _, sig := range p.errorSig {
				if strings.Contains(bodyLower, sig) && !strings.Contains(strings.ToLower(string(baseResp.Body)), sig) {
					d.addFinding(Finding{
						Type:        VulnSQLi,
						Severity:    "Critical",
						Title:       "SQL Injection — Error Based",
						Description: fmt.Sprintf("SQL error triggered with payload: %s. Error signature '%s' found in response.", p.payload, sig),
						Endpoint:    ep.URL,
						Evidence:    []CapturedResponse{*baseResp, *resp},
						Confidence:  0.9,
						CWE:         "CWE-89",
						CVSS:        9.8,
						Remediation: "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
					})
					return // One SQLi finding per endpoint
				}
			}
		}

		// Boolean-based blind: compare response lengths for 1=1 vs 1=2
		if p.payload == "1 AND 1=1" {
			trueResp := resp
			// Now try 1=2
			falseURL := strings.Replace(testURL, url.QueryEscape("1 AND 1=1"), url.QueryEscape("1 AND 1=2"), 1)
			falseResp, err := d.client.Get(falseURL)
			if err != nil {
				continue
			}

			lenDiff := len(trueResp.Body) - len(falseResp.Body)
			if lenDiff < 0 {
				lenDiff = -lenDiff
			}
			// Significant difference in response size suggests blind SQLi
			if lenDiff > 50 && trueResp.StatusCode == 200 && falseResp.StatusCode == 200 {
				d.addFinding(Finding{
					Type:        VulnSQLi,
					Severity:    "Critical",
					Title:       "SQL Injection — Boolean Blind",
					Description: fmt.Sprintf("Boolean-based blind SQL injection detected. Response size diff: %d bytes between TRUE and FALSE conditions.", lenDiff),
					Endpoint:    ep.URL,
					Evidence:    []CapturedResponse{*trueResp, *falseResp},
					Confidence:  0.75,
					CWE:         "CWE-89",
					CVSS:        9.8,
					Remediation: "Use parameterized queries. Validate and sanitize all user input.",
				})
				return
			}
		}
	}
}

// --- Reflected XSS ---

func (d *Detector) checkXSS(ep *DiscoveredEndpoint) {
	if !strings.Contains(ep.ContentType, "html") && !ep.HasParams {
		return
	}

	xssPayloads := []string{
		"<script>alert('DOGE-XSS')</script>",
		"<img src=x onerror=alert('DOGE')>",
		"\"><script>alert(1)</script>",
		"'><script>alert(1)</script>",
		"javascript:alert(1)",
	}

	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return
	}

	q := parsed.Query()
	if len(q) == 0 {
		// Try common param names
		for _, param := range []string{"q", "search", "query", "input", "name", "value", "url", "redirect", "page"} {
			q.Set(param, xssPayloads[0])
			parsed.RawQuery = q.Encode()
			resp, err := d.client.Get(parsed.String())
			if err != nil {
				continue
			}
			if strings.Contains(string(resp.Body), xssPayloads[0]) {
				d.addFinding(Finding{
					Type:        VulnXSS,
					Severity:    "High",
					Title:       fmt.Sprintf("Reflected XSS via '%s' parameter", param),
					Description: "User input is reflected in the response without sanitization.",
					Endpoint:    ep.URL,
					Evidence:    []CapturedResponse{*resp},
					Confidence:  0.9,
					CWE:         "CWE-79",
					CVSS:        6.1,
					Remediation: "Sanitize and encode all user input before reflecting in HTML output.",
				})
				return
			}
			q.Del(param)
		}
		return
	}

	for param := range q {
		for _, payload := range xssPayloads {
			if d.client.BudgetRemaining() < 5 {
				return
			}
			q.Set(param, payload)
			parsed.RawQuery = q.Encode()
			resp, err := d.client.Get(parsed.String())
			if err != nil {
				continue
			}
			if strings.Contains(string(resp.Body), payload) {
				d.addFinding(Finding{
					Type:        VulnXSS,
					Severity:    "High",
					Title:       fmt.Sprintf("Reflected XSS via '%s' parameter", param),
					Description: fmt.Sprintf("Payload '%s' reflected unescaped in response body.", payload),
					Endpoint:    ep.URL,
					Evidence:    []CapturedResponse{*resp},
					Confidence:  0.9,
					CWE:         "CWE-79",
					CVSS:        6.1,
					Remediation: "Encode user input. Use Content-Security-Policy headers.",
				})
				return
			}
		}
		q.Set(param, q.Get(param)) // restore
	}
}

// --- Path Traversal ---

func (d *Detector) checkPathTraversal(ep *DiscoveredEndpoint) {
	if !ep.HasParams {
		return
	}

	traversalPayloads := []struct {
		payload string
		detect  []string
	}{
		{"../../../etc/passwd", []string{"root:", "daemon:", "nobody:"}},
		{"..\\..\\..\\windows\\win.ini", []string{"[fonts]", "[extensions]"}},
		{"....//....//....//etc/passwd", []string{"root:", "daemon:"}},
		{"/etc/passwd", []string{"root:", "daemon:"}},
	}

	parsed, _ := url.Parse(ep.URL)
	q := parsed.Query()

	for param := range q {
		for _, tp := range traversalPayloads {
			q.Set(param, tp.payload)
			parsed.RawQuery = q.Encode()
			resp, err := d.client.Get(parsed.String())
			if err != nil {
				continue
			}
			bodyLower := strings.ToLower(string(resp.Body))
			for _, sig := range tp.detect {
				if strings.Contains(bodyLower, strings.ToLower(sig)) {
					d.addFinding(Finding{
						Type:        VulnPathTraversal,
						Severity:    "Critical",
						Title:       "Path Traversal — Local File Read",
						Description: fmt.Sprintf("Path traversal via '%s' parameter. Payload '%s' returned file contents.", param, tp.payload),
						Endpoint:    ep.URL,
						Evidence:    []CapturedResponse{*resp},
						Confidence:  0.95,
						CWE:         "CWE-22",
						CVSS:        9.1,
						Remediation: "Validate file paths. Use allowlists. Never pass user input directly to filesystem functions.",
					})
					return
				}
			}
		}
		q.Set(param, q.Get(param))
	}
}

// --- Open Redirect ---

func (d *Detector) checkOpenRedirect(ep *DiscoveredEndpoint) {
	parsed, _ := url.Parse(ep.URL)
	q := parsed.Query()

	redirectParams := []string{"url", "redirect", "redirect_url", "redirect_uri", "next", "return", "returnTo", "goto", "target", "rurl", "dest", "destination", "continue"}

	for _, param := range redirectParams {
		if d.client.BudgetRemaining() < 3 {
			return
		}

		q.Set(param, "https://evil-attacker.com")
		parsed.RawQuery = q.Encode()

		req, _ := http.NewRequest("GET", parsed.String(), nil)
		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}

		loc := resp.Headers.Get("Location")
		if (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307) &&
			strings.Contains(loc, "evil-attacker.com") {
			d.addFinding(Finding{
				Type:        VulnOpenRedirect,
				Severity:    "Medium",
				Title:       fmt.Sprintf("Open Redirect via '%s' parameter", param),
				Description: fmt.Sprintf("Server redirects to attacker-controlled URL: Location: %s", loc),
				Endpoint:    ep.URL,
				Evidence:    []CapturedResponse{*resp},
				Confidence:  0.95,
				CWE:         "CWE-601",
				CVSS:        6.1,
				Remediation: "Validate redirect URLs against an allowlist of trusted domains.",
			})
			return
		}

		q.Del(param)
	}
}

// --- SSRF ---

func (d *Detector) checkSSRF(ep *DiscoveredEndpoint) {
	if !ep.HasParams {
		return
	}

	parsed, _ := url.Parse(ep.URL)
	q := parsed.Query()

	ssrfTargets := []struct {
		url    string
		detect string
	}{
		{"http://169.254.169.254/latest/meta-data/", "ami-id"},
		{"http://127.0.0.1:80/", ""},
		{"http://[::1]/", ""},
		{"http://0177.0.0.1/", ""},
	}

	urlParams := []string{"url", "uri", "path", "src", "source", "href", "link", "fetch", "proxy", "callback"}

	for _, param := range urlParams {
		if _, exists := q[param]; !exists {
			continue
		}
		for _, target := range ssrfTargets {
			if d.client.BudgetRemaining() < 3 {
				return
			}
			q.Set(param, target.url)
			parsed.RawQuery = q.Encode()
			resp, err := d.client.Get(parsed.String())
			if err != nil {
				continue
			}
			body := string(resp.Body)
			if target.detect != "" && strings.Contains(body, target.detect) {
				d.addFinding(Finding{
					Type:        VulnSSRF,
					Severity:    "Critical",
					Title:       "Server-Side Request Forgery (SSRF)",
					Description: fmt.Sprintf("SSRF via '%s' parameter. Fetched internal URL: %s", param, target.url),
					Endpoint:    ep.URL,
					Evidence:    []CapturedResponse{*resp},
					Confidence:  0.9,
					CWE:         "CWE-918",
					CVSS:        9.1,
					Remediation: "Validate and sanitize URLs. Block requests to internal IP ranges.",
				})
				return
			}
		}
		q.Set(param, q.Get(param))
	}
}

// --- Host Header Injection ---

func (d *Detector) checkHostHeaderInjection(ep *DiscoveredEndpoint) {
	if ep.StatusCode != 200 {
		return
	}

	req, _ := http.NewRequest("GET", ep.URL, nil)
	req.Host = "evil-attacker.com"
	resp, err := d.client.Do(req)
	if err != nil {
		return
	}

	body := string(resp.Body)
	if strings.Contains(body, "evil-attacker.com") {
		d.addFinding(Finding{
			Type:        VulnHostHeader,
			Severity:    "Medium",
			Title:       "Host Header Injection",
			Description: "Application reflects the Host header in response body. This can enable cache poisoning or password reset poisoning.",
			Endpoint:    ep.URL,
			Evidence:    []CapturedResponse{*resp},
			Confidence:  0.85,
			CWE:         "CWE-644",
			CVSS:        6.1,
			Remediation: "Validate the Host header against a whitelist. Don't reflect it in output.",
		})
	}
}

// --- HTTP Verb Tampering ---

func (d *Detector) checkVerbTampering(ep *DiscoveredEndpoint) {
	if ep.StatusCode != 403 && ep.StatusCode != 401 {
		return
	}

	// If original method returns 403, try different methods
	methods := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"}
	for _, method := range methods {
		req, _ := http.NewRequest(method, ep.URL, nil)
		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			d.addFinding(Finding{
				Type:        VulnVerbTampering,
				Severity:    "Medium",
				Title:       fmt.Sprintf("HTTP Verb Tampering Bypass (GET→%s)", method),
				Description: fmt.Sprintf("Endpoint returns 403 for GET but 200 for %s method, potentially bypassing auth.", method),
				Endpoint:    ep.URL,
				Evidence:    []CapturedResponse{*resp},
				Confidence:  0.8,
				CWE:         "CWE-650",
				CVSS:        5.3,
				Remediation: "Implement authentication/authorization checks for all HTTP methods.",
			})
			return
		}
	}
}

// --- Timing Side Channel ---

func (d *Detector) checkTimingOracle(ep *DiscoveredEndpoint) {
	if !strings.Contains(ep.URL, "login") && !strings.Contains(ep.URL, "auth") &&
		!strings.Contains(ep.URL, "token") && !strings.Contains(ep.URL, "verify") &&
		!strings.Contains(ep.URL, "reset") {
		return
	}

	// Send valid-looking vs invalid-looking inputs and compare timing
	validUser := "admin"
	invalidUser := "xyznonexistent999"

	var validTimes, invalidTimes []time.Duration
	runs := 3

	for i := 0; i < runs; i++ {
		if d.client.BudgetRemaining() < 5 {
			return
		}

		resp1, err := d.client.Post(ep.URL, "application/json",
			fmt.Sprintf(`{"username":"%s","password":"wrongpassword123"}`, validUser))
		if err != nil {
			return
		}
		validTimes = append(validTimes, resp1.Duration)

		resp2, err := d.client.Post(ep.URL, "application/json",
			fmt.Sprintf(`{"username":"%s","password":"wrongpassword123"}`, invalidUser))
		if err != nil {
			return
		}
		invalidTimes = append(invalidTimes, resp2.Duration)
	}

	avgValid := avgDuration(validTimes)
	avgInvalid := avgDuration(invalidTimes)

	diff := avgValid - avgInvalid
	if diff < 0 {
		diff = -diff
	}

	// If there's a >50ms consistent difference, potential timing oracle
	if diff > 50*time.Millisecond {
		d.addFinding(Finding{
			Type:     VulnTimingOracle,
			Severity: "Medium",
			Title:    "Timing Side-Channel on Authentication",
			Description: fmt.Sprintf("Consistent timing difference: valid user=%.1fms, invalid user=%.1fms (diff=%.1fms). May allow username enumeration.",
				float64(avgValid)/float64(time.Millisecond),
				float64(avgInvalid)/float64(time.Millisecond),
				float64(diff)/float64(time.Millisecond)),
			Endpoint:    ep.URL,
			Confidence:  0.7,
			CWE:         "CWE-208",
			CVSS:        5.3,
			Remediation: "Use constant-time comparison for authentication. Return identical responses for valid/invalid usernames.",
		})
	}
}

func avgDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum / time.Duration(len(ds))
}

// --- Command Injection ---

func (d *Detector) checkCommandInjection(ep *DiscoveredEndpoint) {
	if !ep.HasParams {
		return
	}

	parsed, _ := url.Parse(ep.URL)
	q := parsed.Query()

	// Safe canary payloads — these don't execute harmful commands
	payloads := []struct {
		inject string
		detect []string
	}{
		{"; echo DOGE_CANARY_12345", []string{"DOGE_CANARY_12345"}},
		{"| echo DOGE_CANARY_12345", []string{"DOGE_CANARY_12345"}},
		{"$(echo DOGE_CANARY_12345)", []string{"DOGE_CANARY_12345"}},
		{"`echo DOGE_CANARY_12345`", []string{"DOGE_CANARY_12345"}},
	}

	for param := range q {
		orig := q.Get(param)
		for _, p := range payloads {
			if d.client.BudgetRemaining() < 3 {
				return
			}
			q.Set(param, orig+p.inject)
			parsed.RawQuery = q.Encode()
			resp, err := d.client.Get(parsed.String())
			if err != nil {
				continue
			}
			body := string(resp.Body)
			for _, sig := range p.detect {
				if strings.Contains(body, sig) {
					d.addFinding(Finding{
						Type:        VulnCommandInjection,
						Severity:    "Critical",
						Title:       fmt.Sprintf("OS Command Injection via '%s' parameter", param),
						Description: fmt.Sprintf("Injected command canary detected in response. Payload: %s", p.inject),
						Endpoint:    ep.URL,
						Evidence:    []CapturedResponse{*resp},
						Confidence:  0.9,
						CWE:         "CWE-78",
						CVSS:        9.8,
						Remediation: "Never pass user input to shell commands. Use safe APIs. Sanitize all input.",
					})
					return
				}
			}
		}
		q.Set(param, orig)
	}
}
