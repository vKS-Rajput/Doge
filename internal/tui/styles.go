// Package tui provides the interactive Research Cockpit.
//
// The TUI is a PRESENTATION LAYER. It consumes the App Service
// and an event stream. It never accesses the database directly,
// never mutates evidence, and never blocks the Event Bus.
//
// Architecture:
//
//	App Service → Query API → TUI (read-only rendering)
//	Event Bus → EventSink (bounded channel) → Live Feed
//
// The TUI cannot crash the security pipeline. If the TUI dies,
// doge continues watching and processing.
package tui

import "github.com/charmbracelet/lipgloss"

// --- Color Palette ---

var (
	// Base colors.
	colorBg       = lipgloss.Color("#1a1b26")
	colorFg       = lipgloss.Color("#c0caf5")
	colorDim      = lipgloss.Color("#565f89")
	colorBorder   = lipgloss.Color("#3b4261")
	colorAccent   = lipgloss.Color("#7aa2f7")

	// Priority colors.
	colorCritical = lipgloss.Color("#f7768e")
	colorHigh     = lipgloss.Color("#ff9e64")
	colorMedium   = lipgloss.Color("#e0af68")
	colorLow      = lipgloss.Color("#9ece6a")
	colorInfo     = lipgloss.Color("#7dcfff")

	// Status colors.
	colorSuccess  = lipgloss.Color("#9ece6a")
	colorWarning  = lipgloss.Color("#e0af68")
	colorError    = lipgloss.Color("#f7768e")
)

// --- Pane Styles ---

var (
	// PaneStyle is the base style for all panes.
	PaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	// FocusedPaneStyle highlights the active pane.
	FocusedPaneStyle = PaneStyle.
				BorderForeground(colorAccent)

	// HeaderStyle for pane titles.
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			MarginBottom(1)

	// TitleBarStyle for the top title bar.
	TitleBarStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorFg).
			Background(lipgloss.Color("#24283b")).
			Padding(0, 1).
			Width(80)

	// StatusBarStyle for the bottom status bar.
	StatusBarStyle = lipgloss.NewStyle().
			Foreground(colorDim).
			Background(lipgloss.Color("#24283b")).
			Padding(0, 1)

	// InputStyle for the command input.
	InputStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), true, false, false, false).
			BorderForeground(colorBorder).
			Padding(0, 1)
)

// --- Text Styles ---

var (
	DimText      = lipgloss.NewStyle().Foreground(colorDim)
	BrightText   = lipgloss.NewStyle().Foreground(colorFg)
	AccentText   = lipgloss.NewStyle().Foreground(colorAccent)
	SuccessText  = lipgloss.NewStyle().Foreground(colorSuccess)
	WarningText  = lipgloss.NewStyle().Foreground(colorWarning)
	ErrorText    = lipgloss.NewStyle().Foreground(colorError)

	CriticalText = lipgloss.NewStyle().Foreground(colorCritical).Bold(true)
	HighText     = lipgloss.NewStyle().Foreground(colorHigh).Bold(true)
	MediumText   = lipgloss.NewStyle().Foreground(colorMedium)
	LowText      = lipgloss.NewStyle().Foreground(colorLow)
	InfoText     = lipgloss.NewStyle().Foreground(colorInfo)
)

// PriorityStyle returns the style for a given priority string.
func PriorityStyle(priority string) lipgloss.Style {
	switch priority {
	case "critical":
		return CriticalText
	case "high":
		return HighText
	case "medium":
		return MediumText
	case "low":
		return LowText
	default:
		return InfoText
	}
}
