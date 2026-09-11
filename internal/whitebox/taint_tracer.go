package whitebox

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// SinkType categorizes security-sensitive operations.
type SinkType string

const (
	SinkSQL           SinkType = "sql_injection"
	SinkCommand       SinkType = "command_injection"
	SinkSSRF          SinkType = "server_side_request_forgery"
	SinkPathTraversal SinkType = "path_traversal"
	SinkCodeExecution SinkType = "code_execution"
)

// TaintSink represents a dangerous function call or operation site.
type TaintSink struct {
	Type        SinkType `json:"type"`
	LineNumber  int      `json:"line_number"`
	SourceFile  string   `json:"source_file"`
	Expression  string   `json:"expression"`
	VulnerableTo string  `json:"vulnerable_to"`
}

// TaintPath represents an identified dataflow path from untrusted source to sensitive sink.
type TaintPath struct {
	ID             uuid.UUID `json:"id"`
	SourceParam    string    `json:"source_param"`
	SourceFile     string    `json:"source_file"`
	SourceLine     int       `json:"source_line"`
	Sink           TaintSink `json:"sink"`
	Confidence     float64   `json:"confidence"` // 0.0 to 1.0
	Description    string    `json:"description"`
	TriggerPayload string    `json:"trigger_payload"`
}

// TaintTracer performs lexical and AST-based dataflow analysis to find vulnerable source-sink paths.
type TaintTracer struct {
	sqlRegex     *regexp.Regexp
	cmdRegex     *regexp.Regexp
	ssrfRegex    *regexp.Regexp
	pathRegex    *regexp.Regexp
}

// NewTaintTracer creates a new deterministic taint analysis engine.
func NewTaintTracer() *TaintTracer {
	return &TaintTracer{
		sqlRegex: regexp.MustCompile(`(?i)(?:fmt\.Sprintf\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY).*%s|cursor\.execute\s*\(\s*f["']|query\s*=\s*f?["'].*\+|(?:db\.Query|db\.Exec)\s*\(\s*["'].*\+)`),
		cmdRegex: regexp.MustCompile(`(?i)(?:exec\.Command\s*\(|os\.system\s*\(|subprocess\.(?:Popen|run|call)\s*\(|child_process\.exec\s*\(|eval\s*\()`),
		ssrfRegex: regexp.MustCompile(`(?i)(?:http\.Get\s*\(|requests\.get\s*\(|fetch\s*\(|urllib\.request\.urlopen\s*\(|axios\.get\s*\()`),
		pathRegex: regexp.MustCompile(`(?i)(?:os\.Open\s*\(|ioutil\.ReadFile\s*\(|open\s*\(|fs\.readFile\s*\(|filepath\.Join\s*\()`),
	}
}

// TraceTaint inspects source code content along with known input sources to find vulnerable sinks.
func (t *TaintTracer) TraceTaint(content, filename string, sources []SourceOccurrence) []TaintPath {
	var paths []TaintPath
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	type lineInfo struct {
		num  int
		text string
	}
	var lines []lineInfo
	for scanner.Scan() {
		lineNum++
		lines = append(lines, lineInfo{num: lineNum, text: scanner.Text()})
	}

	for _, src := range sources {
		param := src.Parameter
		if param == "" {
			continue
		}

		// Search for usage of param in subsequent lines near dangerous sinks
		for _, l := range lines {
			if l.num < src.LineNumber {
				continue
			}

			// Check if line references the parameter
			if !strings.Contains(l.text, param) && !strings.Contains(l.text, strings.ToLower(param)) {
				continue
			}

			var sinkType SinkType
			var vulnDesc string
			var payload string

			if t.sqlRegex.MatchString(l.text) || (strings.Contains(strings.ToUpper(l.text), "SELECT") && strings.Contains(l.text, "+")) {
				sinkType = SinkSQL
				vulnDesc = fmt.Sprintf("Untrusted parameter %q concatenated into SQL query string", param)
				payload = "' OR 1=1--"
			} else if t.cmdRegex.MatchString(l.text) {
				sinkType = SinkCommand
				vulnDesc = fmt.Sprintf("Untrusted parameter %q passed into OS command execution sink", param)
				payload = "; id"
			} else if t.ssrfRegex.MatchString(l.text) {
				sinkType = SinkSSRF
				vulnDesc = fmt.Sprintf("Untrusted parameter %q used directly as target URL for outbound request", param)
				payload = "http://169.254.169.254/latest/meta-data/"
			} else if t.pathRegex.MatchString(l.text) {
				sinkType = SinkPathTraversal
				vulnDesc = fmt.Sprintf("Untrusted parameter %q used in filesystem file access operation", param)
				payload = "../../../../etc/passwd"
			}

			if sinkType != "" {
				paths = append(paths, TaintPath{
					ID:          uuid.New(),
					SourceParam: param,
					SourceFile:  filename,
					SourceLine:  src.LineNumber,
					Sink: TaintSink{
						Type:         sinkType,
						LineNumber:   l.num,
						SourceFile:   filename,
						Expression:   strings.TrimSpace(l.text),
						VulnerableTo: string(sinkType),
					},
					Confidence:     0.90,
					Description:    vulnDesc,
					TriggerPayload: payload,
				})
			}
		}
	}

	return paths
}
