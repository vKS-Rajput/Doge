package whitebox

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Language identifies the programming language of a source file.
type Language string

const (
	LangGo         Language = "go"
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangPHP        Language = "php"
	LangUnknown    Language = "unknown"
)

// RouteHandler represents a discovered route/endpoint handler in source code.
type RouteHandler struct {
	Path       string   `json:"path"`
	Method     string   `json:"method"`
	LineNumber int      `json:"line_number"`
	SourceFile string   `json:"source_file"`
	Parameters []string `json:"parameters"`
	Function   string   `json:"function"`
}

// SourceOccurrence records where an untrusted user input enters the program.
type SourceOccurrence struct {
	Parameter  string   `json:"parameter"`
	SourceType string   `json:"source_type"` // query, body, header, param
	LineNumber int      `json:"line_number"`
	SourceFile string   `json:"source_file"`
	Variable   string   `json:"variable"`
}

// ASTParser extracts route declarations and user input sources from source files.
type ASTParser struct{}

// NewASTParser creates a new static AST and pattern parser.
func NewASTParser() *ASTParser {
	return &ASTParser{}
}

// DetectLanguage identifies file language based on file extension.
func (p *ASTParser) DetectLanguage(filename string) Language {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".go":
		return LangGo
	case ".py":
		return LangPython
	case ".js", ".mjs", ".cjs":
		return LangJavaScript
	case ".ts", ".tsx":
		return LangTypeScript
	case ".php":
		return LangPHP
	default:
		return LangUnknown
	}
}

// ParseFile inspects a single source file and extracts routes and input sources.
func (p *ASTParser) ParseFile(filePath string) ([]RouteHandler, []SourceOccurrence, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading file %s: %w", filePath, err)
	}

	lang := p.DetectLanguage(filePath)
	return p.ParseContent(string(content), filePath, lang)
}

// ParseContent extracts routes and source occurrences from string content.
func (p *ASTParser) ParseContent(content, filename string, lang Language) ([]RouteHandler, []SourceOccurrence, error) {
	var routes []RouteHandler
	var sources []SourceOccurrence

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	// Regex patterns for route handlers
	goRouteRegex := regexp.MustCompile(`(?:HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH)\s*\(\s*["']([^"']+)["']`)
	pyRouteRegex := regexp.MustCompile(`@(?:app|router|blueprint)\.(?:route|get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	jsRouteRegex := regexp.MustCompile(`(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)

	// Regex patterns for input sources
	goParamRegex := regexp.MustCompile(`(?:r\.URL\.Query\(\)\.Get|r\.FormValue|r\.Header\.Get|chi\.URLParam|mux\.Vars)\s*\(\s*["']([^"']+)["']\s*\)`)
	pyParamRegex := regexp.MustCompile(`(?:request\.(?:args|form|headers|json)\.get\s*\(\s*|request\.(?:args|form)\[)\s*["']([^"']+)["']`)
	jsParamRegex := regexp.MustCompile(`(?:req\.(?:query|body|params|headers)\.([a-zA-Z0-9_]+)|req\.(?:query|body|params)\[["']([^"']+)["']\])`)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 1. Match Route Handlers
		var matchedPath string
		if matches := goRouteRegex.FindStringSubmatch(line); len(matches) > 1 {
			matchedPath = matches[1]
		} else if matches := pyRouteRegex.FindStringSubmatch(line); len(matches) > 1 {
			matchedPath = matches[1]
		} else if matches := jsRouteRegex.FindStringSubmatch(line); len(matches) > 1 {
			matchedPath = matches[1]
		}

		if matchedPath != "" {
			method := "ANY"
			lineUpper := strings.ToUpper(line)
			for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
				if strings.Contains(lineUpper, m) {
					method = m
					break
				}
			}
			routes = append(routes, RouteHandler{
				Path:       matchedPath,
				Method:     method,
				LineNumber: lineNum,
				SourceFile: filename,
			})
		}

		// 2. Match User Input Sources
		if matches := goParamRegex.FindStringSubmatch(line); len(matches) > 1 {
			sources = append(sources, SourceOccurrence{
				Parameter:  matches[1],
				SourceType: "query_or_form",
				LineNumber: lineNum,
				SourceFile: filename,
			})
		} else if matches := pyParamRegex.FindStringSubmatch(line); len(matches) > 1 {
			sources = append(sources, SourceOccurrence{
				Parameter:  matches[1],
				SourceType: "query_or_form",
				LineNumber: lineNum,
				SourceFile: filename,
			})
		} else if matches := jsParamRegex.FindStringSubmatch(line); len(matches) > 1 {
			paramName := matches[1]
			if paramName == "" && len(matches) > 2 {
				paramName = matches[2]
			}
			if paramName != "" {
				sources = append(sources, SourceOccurrence{
					Parameter:  paramName,
					SourceType: "request_field",
					LineNumber: lineNum,
					SourceFile: filename,
				})
			}
		}
	}

	return routes, sources, nil
}
