package desktop

// CommandItem defines a conceptual command available in the Command Palette (Ctrl+Shift+P).
type CommandItem struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Shortcut    string `json:"shortcut,omitempty"`
	Description string `json:"description"`
}

// GetCommandCatalog returns the full set of conceptual commands.
func GetCommandCatalog() []CommandItem {
	return []CommandItem{
		{
			ID:          "mission.start",
			Title:       "Start Autonomous Research Mission",
			Category:    "Research",
			Shortcut:    "F5",
			Description: "Initiate continuous autonomous research on target",
		},
		{
			ID:          "mission.pause",
			Title:       "Pause Research Mission",
			Category:    "Research",
			Shortcut:    "F6",
			Description: "Suspend active research loop and hold state",
		},
		{
			ID:          "mission.stop",
			Title:       "Stop Research Mission",
			Category:    "Research",
			Shortcut:    "Shift+F5",
			Description: "Terminate active research and finalize evidence",
		},
		{
			ID:          "mission.new",
			Title:       "Create New Research Mission...",
			Category:    "Mission",
			Shortcut:    "Ctrl+N",
			Description: "Configure target scope, request budget, and policy",
		},
		{
			ID:          "view.worldmodel",
			Title:       "Open World Model Graph",
			Category:    "Navigation",
			Shortcut:    "Ctrl+G",
			Description: "Switch to interactive 2D/3D World Model visualization",
		},
		{
			ID:          "view.terminal",
			Title:       "Open WSL Laboratory Terminal",
			Category:    "Navigation",
			Shortcut:    "`",
			Description: "Access research-aware Linux bash shell in WSL2",
		},
		{
			ID:          "view.findings",
			Title:       "Inspect Proven Findings",
			Category:    "Navigation",
			Shortcut:    "Ctrl+F",
			Description: "View cryptographically verified security vulnerabilities",
		},
		{
			ID:          "view.evidence",
			Title:       "Inspect Cryptographic Evidence",
			Category:    "Navigation",
			Shortcut:    "Ctrl+E",
			Description: "View Merkle roots, SHA-256 chains, and replay proofs",
		},
		{
			ID:          "view.toggle_mode",
			Title:       "Toggle Operator / Scientist Mode",
			Category:    "Perspective",
			Shortcut:    "Tab",
			Description: "Switch cockpit perspective between tactical and epistemic",
		},
		{
			ID:          "lab.environment",
			Title:       "Open Environment & Toolchain Center",
			Category:    "Laboratory",
			Shortcut:    "Ctrl+L",
			Description: "Inspect WSL status, Kali health, and installed tools",
		},
		{
			ID:          "report.export_sarif",
			Title:       "Export Findings to OASIS SARIF v2.1.0",
			Category:    "Export",
			Shortcut:    "Ctrl+Shift+S",
			Description: "Generate CI/CD compatible SARIF security report",
		},
	}
}
