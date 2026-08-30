// Package httpresponse implements a parser for HTTP response output.
//
// Handles output from curl -I, curl -v, wget --server-response, and any
// captured text that begins with an HTTP status line (HTTP/1.x or HTTP/2).
//
// Produces http_probe and technology_detection observations.
package httpresponse

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Parser converts HTTP response text into observations.
type Parser struct{}

// New creates a new HTTP response parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "httpresponse" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like HTTP response output.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	// Don't claim XML or JSON files.
	if ext == ".xml" || ext == ".json" || ext == ".jsonl" {
		return false
	}

	// Filename heuristic: curl/wget capture.
	if (strings.Contains(name, "curl") || strings.Contains(name, "wget")) && (ext == ".txt" || ext == ".log") {
		return true
	}

	// Content detection: HTTP status line.
	if len(header) > 0 {
		s := string(header)
		if strings.HasPrefix(s, "HTTP/") {
			return true
		}
		// curl -v prefixes with < or >
		if strings.Contains(s, "< HTTP/") || strings.Contains(s, "> HTTP/") {
			return true
		}
	}

	return false
}

var (
	statusLineRe = regexp.MustCompile(`(?:^|[<>]\s*)HTTP/[\d.]+\s+(\d{3})\b(.*)`)
	headerLineRe = regexp.MustCompile(`^([A-Za-z][\w-]*)\s*:\s*(.+)`)
	htmlTitleRe  = regexp.MustCompile(`(?i)<title[^>]*>\s*(.+?)\s*</title>`)
	scriptSrcRe  = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	urlRegex     = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

// securityHeaders are headers that indicate security configuration.
var securityHeaders = map[string]bool{
	"strict-transport-security": true,
	"x-frame-options":           true,
	"x-content-type-options":    true,
	"content-security-policy":   true,
	"x-xss-protection":          true,
	"referrer-policy":            true,
	"permissions-policy":         true,
	"access-control-allow-origin": true,
}

// Parse reads HTTP response text and produces observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var observations []domain.RawObservation
	now := time.Now().UTC()

	// State for current response block.
	var statusCode int
	var headers map[string]string
	var bodyLines []string
	inBody := false
	headersDone := false

	flush := func() {
		if statusCode == 0 && len(headers) == 0 {
			return
		}

		obs := p.buildHTTPProbeObs(statusCode, headers, bodyLines, artifact.FileName, now)
		if obs != nil {
			observations = append(observations, *obs)
		}

		// Technology detection from Server/X-Powered-By.
		techObs := p.extractTechnologies(headers, artifact.FileName, now)
		observations = append(observations, techObs...)

		// Extract JS/HTML evidence from body.
		if len(bodyLines) > 0 {
			body := strings.Join(bodyLines, "\n")
			htmlObs := p.extractFromHTML(body, artifact.FileName, now)
			observations = append(observations, htmlObs...)
		}

		// Reset.
		statusCode = 0
		headers = nil
		bodyLines = nil
		inBody = false
		headersDone = false
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Strip curl -v prefixes.
		if strings.HasPrefix(trimmed, "< ") {
			trimmed = trimmed[2:]
		} else if strings.HasPrefix(trimmed, "> ") {
			// Request line, skip.
			continue
		} else if strings.HasPrefix(trimmed, "* ") {
			// curl info line, skip.
			continue
		}

		// Check for HTTP status line (start of new response).
		if m := statusLineRe.FindStringSubmatch(trimmed); m != nil {
			// Flush previous response.
			flush()

			code, _ := strconv.Atoi(m[1])
			statusCode = code
			headers = make(map[string]string)
			continue
		}

		// If we haven't seen a status line yet, check for raw headers.
		if headers == nil && !inBody {
			// Try header line without prior status.
			if m := headerLineRe.FindStringSubmatch(trimmed); m != nil {
				headers = make(map[string]string)
				headers[strings.ToLower(m[1])] = strings.TrimSpace(m[2])
				continue
			}
			// Accumulate as potential body.
			bodyLines = append(bodyLines, line)
			continue
		}

		// Empty line = end of headers, start of body.
		if trimmed == "" && !headersDone && headers != nil {
			headersDone = true
			inBody = true
			continue
		}

		// Parse header.
		if !headersDone && headers != nil {
			if m := headerLineRe.FindStringSubmatch(trimmed); m != nil {
				headers[strings.ToLower(m[1])] = strings.TrimSpace(m[2])
				continue
			}
		}

		// Body content.
		if inBody {
			bodyLines = append(bodyLines, line)
		}
	}

	// Flush last response.
	flush()

	// If no HTTP response was found but body has HTML, try to extract from HTML.
	if len(observations) == 0 && len(bodyLines) > 0 {
		body := strings.Join(bodyLines, "\n")
		htmlObs := p.extractFromHTML(body, artifact.FileName, now)
		observations = append(observations, htmlObs...)
	}

	return observations, scanner.Err()
}

func (p *Parser) buildHTTPProbeObs(statusCode int, headers map[string]string, bodyLines []string, filename string, now time.Time) *domain.RawObservation {
	data := map[string]any{}

	if statusCode > 0 {
		data["status_code"] = statusCode
	}

	// Extract URL from filename or Host header.
	if host, ok := headers["host"]; ok {
		scheme := "https"
		if statusCode > 0 && statusCode < 400 {
			scheme = "https"
		}
		data["url"] = scheme + "://" + host
		data["host"] = host
	}

	// Server.
	if server, ok := headers["server"]; ok {
		data["webserver"] = server
	}

	// Content-Type.
	if ct, ok := headers["content-type"]; ok {
		data["content_type"] = ct
	}

	// Security headers.
	secHeaders := map[string]string{}
	for name, value := range headers {
		if securityHeaders[name] {
			secHeaders[name] = value
		}
	}
	if len(secHeaders) > 0 {
		data["security_headers"] = secHeaders
	}

	// Cookies.
	if cookie, ok := headers["set-cookie"]; ok {
		data["cookies"] = cookie
	}

	// Location (redirects).
	if loc, ok := headers["location"]; ok {
		data["redirect_location"] = loc
	}

	// Title from body.
	if len(bodyLines) > 0 {
		body := strings.Join(bodyLines, "\n")
		if m := htmlTitleRe.FindStringSubmatch(body); m != nil {
			data["title"] = strings.TrimSpace(m[1])
		}
	}

	if len(data) == 0 {
		return nil
	}

	rawParts := []string{}
	if statusCode > 0 {
		rawParts = append(rawParts, fmt.Sprintf("HTTP %d", statusCode))
	}
	for k, v := range headers {
		rawParts = append(rawParts, k+": "+v)
	}

	return &domain.RawObservation{
		Type:       domain.ObservationHTTPProbe,
		SourceTool: detectHTTPTool(filename),
		Data:       data,
		RawValue:   strings.Join(rawParts, "\n"),
		ObservedAt: now,
	}
}

func (p *Parser) extractTechnologies(headers map[string]string, filename string, now time.Time) []domain.RawObservation {
	var obs []domain.RawObservation
	tool := detectHTTPTool(filename)

	addTech := func(tech, source string) {
		obs = append(obs, domain.RawObservation{
			Type:       domain.ObservationTechnologyDetect,
			SourceTool: tool,
			Data: map[string]any{
				"technology": tech,
				"source":     source,
			},
			RawValue:   tech,
			ObservedAt: now,
		})
	}

	if server, ok := headers["server"]; ok && server != "" {
		addTech(server, "server_header")
	}
	if powered, ok := headers["x-powered-by"]; ok && powered != "" {
		addTech(powered, "x-powered-by")
	}
	if via, ok := headers["via"]; ok && via != "" {
		addTech(via, "via_header")
	}

	return obs
}

func (p *Parser) extractFromHTML(body, filename string, now time.Time) []domain.RawObservation {
	var obs []domain.RawObservation
	tool := detectHTTPTool(filename)

	// Title.
	if m := htmlTitleRe.FindStringSubmatch(body); m != nil {
		title := strings.TrimSpace(m[1])
		if title != "" {
			obs = append(obs, domain.RawObservation{
				Type:       domain.ObservationHTTPProbe,
				SourceTool: tool,
				Data: map[string]any{
					"title": title,
				},
				RawValue:   "title: " + title,
				ObservedAt: now,
			})
		}
	}

	// Script sources.
	matches := scriptSrcRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		src := m[1]
		obs = append(obs, domain.RawObservation{
			Type:       domain.ObservationJavaScriptAnalysis,
			SourceTool: tool,
			Data: map[string]any{
				"url":    src,
				"source": "html_script_tag",
			},
			RawValue:   src,
			ObservedAt: now,
		})
	}

	return obs
}

func detectHTTPTool(filename string) string {
	lower := strings.ToLower(filename)
	switch {
	case strings.Contains(lower, "curl"):
		return "curl"
	case strings.Contains(lower, "wget"):
		return "wget"
	default:
		return "http"
	}
}
