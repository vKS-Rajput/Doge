package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// WorkspaceConfig models .doge/workspace.toml
type WorkspaceConfig struct {
	Name        string    `toml:"name"`
	Target      string    `toml:"target"`
	CreatedAt   time.Time `toml:"created_at"`
	Environment string    `toml:"environment"` // "wsl", "native", "hybrid"
	Scope       []string  `toml:"scope"`
	Description string    `toml:"description,omitempty"`
}

// PolicyConfig models .doge/policy.toml
type PolicyConfig struct {
	RiskCeiling                   float64  `toml:"risk_ceiling"`
	RequestBudget                 int      `toml:"request_budget"`
	MaxRequestsPerSecond          int      `toml:"max_requests_per_second"`
	StateChangingRequiresApproval bool     `toml:"state_changing_requires_approval"`
	AllowedMethods                []string `toml:"allowed_methods"`
	AllowedHosts                  []string `toml:"allowed_hosts"`
}

// Workspace represents an initialized DOGE project workspace on disk.
type Workspace struct {
	RootPath     string          `json:"root_path"`
	DogePath     string          `json:"doge_path"`
	Config       WorkspaceConfig `json:"config"`
	Policy       PolicyConfig    `json:"policy"`
	TargetsDir   string          `json:"targets_dir"`
	WorldDir     string          `json:"world_dir"`
	ResearchDir  string          `json:"research_dir"`
	EvidenceDir string          `json:"evidence_dir"`
	SessionsDir  string          `json:"sessions_dir"`
	ReportsDir   string          `json:"reports_dir"`
	LogsDir      string          `json:"logs_dir"`
}

// WorkspaceManager coordinates workspace creation, discovery, and persistence.
type WorkspaceManager struct{}

// NewWorkspaceManager creates a workspace manager.
func NewWorkspaceManager() *WorkspaceManager {
	return &WorkspaceManager{}
}

// Initialize creates the complete .doge/ directory layout and writes initial TOML configurations.
func (m *WorkspaceManager) Initialize(rootPath, name, target string, scope []string) (*Workspace, error) {
	if rootPath == "" {
		rootPath = "."
	}
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workspace root: %w", err)
	}

	dogeDir := filepath.Join(absRoot, ".doge")

	subdirs := []string{
		filepath.Join(dogeDir, "targets"),
		filepath.Join(dogeDir, "world", "observations"),
		filepath.Join(dogeDir, "world", "concepts"),
		filepath.Join(dogeDir, "research", "hypotheses"),
		filepath.Join(dogeDir, "research", "experiments"),
		filepath.Join(dogeDir, "research", "strategies"),
		filepath.Join(dogeDir, "evidence"),
		filepath.Join(dogeDir, "sessions"),
		filepath.Join(dogeDir, "reports"),
		filepath.Join(dogeDir, "benchmarks"),
		filepath.Join(dogeDir, "tools"),
		filepath.Join(dogeDir, "logs"),
	}

	for _, d := range subdirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", d, err)
		}
	}

	if len(scope) == 0 && target != "" {
		scope = []string{target}
	}

	cfg := WorkspaceConfig{
		Name:        name,
		Target:      target,
		CreatedAt:   time.Now().UTC(),
		Environment: "hybrid",
		Scope:       scope,
		Description: fmt.Sprintf("DOGE security research workspace for %s", target),
	}

	pol := PolicyConfig{
		RiskCeiling:                   0.60,
		RequestBudget:                 5000,
		MaxRequestsPerSecond:          20,
		StateChangingRequiresApproval: true,
		AllowedMethods:                []string{"GET", "HEAD", "OPTIONS", "POST"},
		AllowedHosts:                  scope,
	}

	// Write workspace.toml
	cfgBytes, err := toml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize workspace.toml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dogeDir, "workspace.toml"), cfgBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed to write workspace.toml: %w", err)
	}

	// Write policy.toml
	polBytes, err := toml.Marshal(pol)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize policy.toml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dogeDir, "policy.toml"), polBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed to write policy.toml: %w", err)
	}

	return &Workspace{
		RootPath:     absRoot,
		DogePath:     dogeDir,
		Config:       cfg,
		Policy:       pol,
		TargetsDir:   filepath.Join(dogeDir, "targets"),
		WorldDir:     filepath.Join(dogeDir, "world"),
		ResearchDir:  filepath.Join(dogeDir, "research"),
		EvidenceDir: filepath.Join(dogeDir, "evidence"),
		SessionsDir:  filepath.Join(dogeDir, "sessions"),
		ReportsDir:   filepath.Join(dogeDir, "reports"),
		LogsDir:      filepath.Join(dogeDir, "logs"),
	}, nil
}

// Load loads and verifies an existing DOGE workspace from disk.
func (m *WorkspaceManager) Load(rootPath string) (*Workspace, error) {
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workspace root: %w", err)
	}

	dogeDir := filepath.Join(absRoot, ".doge")
	cfgPath := filepath.Join(dogeDir, "workspace.toml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("no DOGE workspace found at %s (missing .doge/workspace.toml)", absRoot)
	}

	cfgBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read workspace.toml: %w", err)
	}
	var cfg WorkspaceConfig
	if err := toml.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse workspace.toml: %w", err)
	}

	var pol PolicyConfig
	polPath := filepath.Join(dogeDir, "policy.toml")
	if polBytes, err := os.ReadFile(polPath); err == nil {
		_ = toml.Unmarshal(polBytes, &pol)
	}

	return &Workspace{
		RootPath:     absRoot,
		DogePath:     dogeDir,
		Config:       cfg,
		Policy:       pol,
		TargetsDir:   filepath.Join(dogeDir, "targets"),
		WorldDir:     filepath.Join(dogeDir, "world"),
		ResearchDir:  filepath.Join(dogeDir, "research"),
		EvidenceDir: filepath.Join(dogeDir, "evidence"),
		SessionsDir:  filepath.Join(dogeDir, "sessions"),
		ReportsDir:   filepath.Join(dogeDir, "reports"),
		LogsDir:      filepath.Join(dogeDir, "logs"),
	}, nil
}
