package scheduler

// ToolDefinition describes how the scheduler interacts with
// an external reconnaissance tool.
//
// The registry is the scheduler's knowledge of what tools exist,
// how they produce output, and how to capture it.
type ToolDefinition struct {
	// Name is the canonical tool name (e.g., "nmap").
	Name string `json:"name"`

	// Binary is the executable name (e.g., "nmap").
	Binary string `json:"binary"`

	// OutputFormat is the expected output format.
	OutputFormat string `json:"output_format"` // "json", "xml", "jsonl"

	// Parser is the registered parser name.
	Parser string `json:"parser"`

	// CaptureMode determines how output is captured.
	CaptureMode CaptureMode `json:"capture_mode"`

	// OutputFlag is the flag to redirect output.
	// For CaptureFlag mode, this is the flag prefix (e.g., "-oX").
	OutputFlag string `json:"output_flag,omitempty"`

	// DefaultFlags are always included when running this tool.
	DefaultFlags []string `json:"default_flags,omitempty"`

	// Category classifies the tool for policy decisions.
	Category ToolCategory `json:"category"`
}

// CaptureMode determines how the scheduler captures tool output.
type CaptureMode string

const (
	// CaptureStdout captures output from stdout.
	// Used by tools that output JSON/JSONL to stdout (httpx, nuclei, katana).
	CaptureStdout CaptureMode = "stdout"

	// CaptureFlag captures output written to a file via a flag.
	// Used by tools that write to files (nmap -oX, ffuf -o).
	CaptureFlag CaptureMode = "flag"
)

// ToolCategory classifies tools for policy decisions.
type ToolCategory string

const (
	CategoryRecon     ToolCategory = "recon"     // nmap
	CategoryWebEnum   ToolCategory = "web_enum"  // httpx, katana
	CategoryDNS       ToolCategory = "dns"       // dnsx, subfinder
	CategoryFuzzing   ToolCategory = "fuzzing"   // ffuf
	CategoryScanning  ToolCategory = "scanning"  // nuclei
)

// ToolRegistry maintains the set of known tools.
type ToolRegistry struct {
	tools map[string]ToolDefinition
}

// NewToolRegistry creates a registry with the 7 built-in tools.
func NewToolRegistry() *ToolRegistry {
	r := &ToolRegistry{
		tools: make(map[string]ToolDefinition),
	}
	r.registerBuiltins()
	return r
}

// Get returns a tool definition by name.
func (r *ToolRegistry) Get(name string) (ToolDefinition, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// Register adds a tool definition to the registry.
func (r *ToolRegistry) Register(def ToolDefinition) {
	r.tools[def.Name] = def
}

// All returns all registered tool definitions.
func (r *ToolRegistry) All() []ToolDefinition {
	defs := make([]ToolDefinition, 0, len(r.tools))
	for _, d := range r.tools {
		defs = append(defs, d)
	}
	return defs
}

// Names returns all registered tool names.
func (r *ToolRegistry) Names() []string {
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	return names
}

func (r *ToolRegistry) registerBuiltins() {
	// nmap: port/service discovery via XML output.
	r.Register(ToolDefinition{
		Name:         "nmap",
		Binary:       "nmap",
		OutputFormat: "xml",
		Parser:       "nmap",
		CaptureMode:  CaptureFlag,
		OutputFlag:   "-oX",
		DefaultFlags: []string{"-sCV"},
		Category:     CategoryRecon,
	})

	// subfinder: subdomain enumeration via JSON stdout.
	r.Register(ToolDefinition{
		Name:         "subfinder",
		Binary:       "subfinder",
		OutputFormat: "json",
		Parser:       "subfinder",
		CaptureMode:  CaptureStdout,
		DefaultFlags: []string{"-oJ"},
		Category:     CategoryDNS,
	})

	// httpx: HTTP probing via JSON stdout.
	r.Register(ToolDefinition{
		Name:         "httpx",
		Binary:       "httpx",
		OutputFormat: "json",
		Parser:       "httpx",
		CaptureMode:  CaptureStdout,
		DefaultFlags: []string{"-json"},
		Category:     CategoryWebEnum,
	})

	// dnsx: DNS enumeration via JSON stdout.
	r.Register(ToolDefinition{
		Name:         "dnsx",
		Binary:       "dnsx",
		OutputFormat: "json",
		Parser:       "dnsx",
		CaptureMode:  CaptureStdout,
		DefaultFlags: []string{"-json"},
		Category:     CategoryDNS,
	})

	// katana: web crawling via JSONL stdout.
	r.Register(ToolDefinition{
		Name:         "katana",
		Binary:       "katana",
		OutputFormat: "jsonl",
		Parser:       "katana",
		CaptureMode:  CaptureStdout,
		DefaultFlags: []string{"-jsonl"},
		Category:     CategoryWebEnum,
	})

	// ffuf: directory fuzzing via JSON output file.
	r.Register(ToolDefinition{
		Name:         "ffuf",
		Binary:       "ffuf",
		OutputFormat: "json",
		Parser:       "ffuf",
		CaptureMode:  CaptureFlag,
		OutputFlag:   "-o",
		DefaultFlags: []string{"-of", "json"},
		Category:     CategoryFuzzing,
	})

	// nuclei: vulnerability scanning via JSONL stdout.
	r.Register(ToolDefinition{
		Name:         "nuclei",
		Binary:       "nuclei",
		OutputFormat: "jsonl",
		Parser:       "nuclei",
		CaptureMode:  CaptureStdout,
		DefaultFlags: []string{"-jsonl"},
		Category:     CategoryScanning,
	})
}
