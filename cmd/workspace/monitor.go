package main

import (
	"database/sql"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/coverage"
	"github.com/vKS-Rajput/doge/internal/journal"
	"github.com/vKS-Rajput/doge/internal/learning"
	"github.com/vKS-Rajput/doge/internal/session"
)

// ─── Monitor State Machine ─────────────────────────────────────────
// Phase 1: RUNNING only. Phase 2 adds GATE, WAITING, ERROR.

type monitorState int

const (
	stateRunning monitorState = iota
	// Phase 2:
	// stateGate
	// stateWaiting
	// stateError
)

// ─── Color Palette (Tokyo Night) ────────────────────────────────────

var (
	mColorBg      = lipgloss.Color("#1a1b26")
	mColorFg      = lipgloss.Color("#c0caf5")
	mColorDim     = lipgloss.Color("#565f89")
	mColorBorder  = lipgloss.Color("#3b4261")
	mColorAccent  = lipgloss.Color("#7aa2f7")
	mColorSuccess = lipgloss.Color("#9ece6a")
	mColorWarning = lipgloss.Color("#e0af68")
	mColorError   = lipgloss.Color("#f7768e")
	mColorHigh    = lipgloss.Color("#ff9e64")
	mColorInfo    = lipgloss.Color("#7dcfff")
	mColorSurface = lipgloss.Color("#24283b")
)

// ─── Styles ─────────────────────────────────────────────────────────

func panelStyle(width int) lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(mColorBorder).
		Padding(0, 1).
		Width(width)
}

func headerPanelStyle(width int) lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(mColorAccent).
		Padding(0, 1).
		Width(width).
		Bold(true)
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(mColorAccent)

	dimStyle = lipgloss.NewStyle().
			Foreground(mColorDim)

	brightStyle = lipgloss.NewStyle().
			Foreground(mColorFg)

	successStyle = lipgloss.NewStyle().
			Foreground(mColorSuccess)

	warningStyle = lipgloss.NewStyle().
			Foreground(mColorWarning)

	errorStyle = lipgloss.NewStyle().
			Foreground(mColorError)

	accentStyle = lipgloss.NewStyle().
			Foreground(mColorAccent).
			Bold(true)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(mColorDim).
			Padding(0, 1)
)

// ─── Bubble Tea Model ───────────────────────────────────────────────

type monitorModel struct {
	wsPath    string
	width     int
	height    int
	state     monitorState
	quitting  bool
	lastError error

	// Data (refreshed every tick).
	sessionState *session.PersistedState
	sessionAlive bool
	entries      []journal.Execution
	covReport    *coverage.Report
	patternCount int
	outcomeCount int
	eventCount   int
	patternList  []learning.ResearchPattern
	projectID    uuid.UUID

	// DB kept open for the monitor lifetime.
	db *sql.DB
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func newMonitorModel(wsPath string) monitorModel {
	m := monitorModel{
		wsPath: wsPath,
		state:  stateRunning,
		width:  80,
		height: 24,
	}

	// Open DB once.
	dbPath := filepath.Join(wsPath, ".doge", "workspace.db")
	db, _ := sql.Open("sqlite", dbPath)
	m.db = db

	// Initial data load.
	m.refresh()
	return m
}

func (m *monitorModel) refresh() {
	// Load session state.
	m.sessionState, _ = session.LoadState(m.wsPath)
	m.sessionAlive = session.IsSessionRunning(m.wsPath)

	if m.db == nil {
		return
	}

	// Get project ID.
	m.projectID = getProjectID(m.sessionState, m.db)

	// Journal.
	jStore := journal.NewStore(m.db)
	jStore.EnsureTable()
	m.entries, _ = jStore.Recent(m.projectID, 8)

	// Coverage.
	covEngine := coverage.NewEngine(m.db)
	m.covReport, _ = covEngine.Analyze(m.projectID)

	// Learning.
	mem := learning.NewMemory(m.db)
	mem.EnsureTable()
	m.patternCount = mem.PatternCount()
	m.outcomeCount = mem.OutcomeCount()
	m.eventCount = mem.EventCount()
	if m.patternCount > 0 {
		m.patternList, _ = mem.AllPatterns()
	}
}

// ─── tea.Model implementation ───────────────────────────────────────

func (m monitorModel) Init() tea.Cmd {
	return tickCmd()
}

func (m monitorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}
		// Phase 2: handle 1-4, A/R/D/V for gate decisions.

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		m.refresh()
		return m, tickCmd()
	}

	return m, nil
}

func (m monitorModel) View() string {
	if m.quitting {
		return "\n  🐕 DOGE Monitor closed.\n\n"
	}

	// Panel width = terminal width minus some margin, capped.
	pw := m.width - 2
	if pw < 40 {
		pw = 40
	}
	if pw > 100 {
		pw = 100
	}

	var sections []string

	// ── Header ──
	sections = append(sections, m.renderHeader(pw))

	// ── Live Activity ──
	sections = append(sections, m.renderActivity(pw))

	// ── Coverage ──
	sections = append(sections, m.renderCoverage(pw))

	// ── Investigate Next ──
	sections = append(sections, m.renderGaps(pw))

	// ── Research Memory ──
	sections = append(sections, m.renderMemory(pw))

	// ── Status Bar ──
	sections = append(sections, m.renderStatusBar(pw))

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// ─── Panel Renderers ────────────────────────────────────────────────

func (m monitorModel) renderHeader(w int) string {
	var b strings.Builder

	left := "  🐕 DOGE MONITOR"

	var right string
	if m.sessionState != nil {
		mode := strings.ToUpper(m.sessionState.Mode)
		if mode == "" {
			mode = "RESEARCH"
		}
		right = dimStyle.Render(mode)
	}

	// Second line: target + status + runtime.
	var line2 strings.Builder
	if m.sessionState != nil {
		line2.WriteString("  Target: ")
		line2.WriteString(accentStyle.Render(m.sessionState.Target))
		line2.WriteString("    ")

		if m.sessionAlive {
			line2.WriteString(successStyle.Render("● ACTIVE"))
		} else {
			line2.WriteString(warningStyle.Render("○ IDLE"))
		}

		if !m.sessionState.StartedAt.IsZero() {
			line2.WriteString("    ")
			line2.WriteString(dimStyle.Render(formatDuration(time.Since(m.sessionState.StartedAt))))
		}
	} else {
		line2.WriteString("  No active session")
		line2.WriteString(dimStyle.Render("  — Start with: doge work --target <target> --env <env>"))
	}

	// Pad the header line.
	headerLine := titleStyle.Render(left)
	innerW := w - 4 // Account for border + padding.
	gap := innerW - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	headerLine += strings.Repeat(" ", gap) + right

	b.WriteString(headerLine)
	b.WriteString("\n")
	b.WriteString(line2.String())

	return headerPanelStyle(w).Render(b.String())
}

func (m monitorModel) renderActivity(w int) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("  LIVE ACTIVITY"))
	b.WriteString("\n")

	if len(m.entries) == 0 {
		b.WriteString(dimStyle.Render("  No commands recorded yet."))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  Use 'doge work' to start investigating."))
	} else {
		for _, e := range m.entries {
			ts := dimStyle.Render(e.IngestedAt.Format("15:04:05"))
			cmd := e.Command
			if cmd == "" {
				cmd = e.Tool
			}
			if len(cmd) > 45 {
				cmd = cmd[:42] + "..."
			}

			var status string
			if e.ExitCode == 0 {
				status = successStyle.Render("✓")
			} else {
				status = errorStyle.Render(fmt.Sprintf("⚠ exit %d", e.ExitCode))
			}

			line := fmt.Sprintf("  %s  %s %s", ts, status, brightStyle.Render(cmd))
			if e.Observations > 0 {
				line += dimStyle.Render(fmt.Sprintf(" → %d obs", e.Observations))
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	return panelStyle(w).Render(b.String())
}

func (m monitorModel) renderCoverage(w int) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("  COVERAGE"))
	b.WriteString("\n")

	if m.covReport == nil {
		b.WriteString(dimStyle.Render("  No coverage data yet."))
	} else {
		for _, c := range m.covReport.Categories {
			name := categoryDisplayName(c.Category)
			pct := int(math.Round(c.Score * 100))
			bar := renderProgressBar(c.Score, 12)
			padding := strings.Repeat(" ", max(1, 16-len(name)))
			b.WriteString(fmt.Sprintf("  %s%s%s %3d%%\n", brightStyle.Render(name), padding, bar, pct))
		}

		b.WriteString("\n")
		totalPct := int(math.Round(m.covReport.TotalScore * 100))
		summary := fmt.Sprintf("  Overall: %d%%  │  Obs: %d  │  Entities: %d",
			totalPct, m.covReport.TotalObservations, m.covReport.TotalEntities)
		b.WriteString(accentStyle.Render(summary))
	}

	return panelStyle(w).Render(b.String())
}

func (m monitorModel) renderGaps(w int) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("  🔥 INVESTIGATE NEXT"))
	b.WriteString("\n")

	if m.covReport == nil {
		b.WriteString(dimStyle.Render("  Start investigating to see gaps."))
		return panelStyle(w).Render(b.String())
	}

	gapNum := 0
	for _, c := range m.covReport.Categories {
		if c.Score >= 0.8 || gapNum >= 3 {
			continue
		}
		gapNum++
		name := categoryDisplayName(c.Category)
		pct := int(math.Round(c.Score * 100))

		var priorityStr string
		if c.Score < 0.2 {
			priorityStr = errorStyle.Render("🔴 CRITICAL")
		} else if c.Score < 0.5 {
			priorityStr = warningStyle.Render("🟡 HIGH")
		} else {
			priorityStr = successStyle.Render("🟢 MEDIUM")
		}

		b.WriteString(fmt.Sprintf("  #%d  %s (%d%%)  %s\n",
			gapNum, brightStyle.Render(name), pct, priorityStr))

		suggestions := categorySuggestions(c.Category, c.Score)
		if len(suggestions) > 0 {
			b.WriteString(fmt.Sprintf("      %s\n", dimStyle.Render("→ "+suggestions[0])))
		}
	}

	if gapNum == 0 {
		b.WriteString(successStyle.Render("  ✅ All categories above 80%."))
	}

	return panelStyle(w).Render(b.String())
}

func (m monitorModel) renderMemory(w int) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("  🧠 RESEARCH MEMORY"))
	b.WriteString("\n")

	summary := fmt.Sprintf("  Patterns: %d   │   Outcomes: %d   │   Events: %d",
		m.patternCount, m.outcomeCount, m.eventCount)
	b.WriteString(brightStyle.Render(summary))

	if len(m.patternList) > 0 {
		b.WriteString("\n")
		shown := 0
		for _, p := range m.patternList {
			if shown >= 2 || p.Confidence < 0.2 {
				continue
			}
			shown++
			b.WriteString(fmt.Sprintf("\n  • %s\n", brightStyle.Render(p.Description)))
			b.WriteString(fmt.Sprintf("    %s",
				dimStyle.Render(fmt.Sprintf("Confidence: %.0f%% | Seen: %d times", p.Confidence*100, p.Occurrences))))
		}
	}

	return panelStyle(w).Render(b.String())
}

func (m monitorModel) renderStatusBar(w int) string {
	ts := time.Now().Format("15:04:05")
	return statusBarStyle.Render(
		fmt.Sprintf("  Updated: %s   │   q to quit", ts),
	)
}

// ─── Helpers ────────────────────────────────────────────────────────

func renderProgressBar(score float64, width int) string {
	filled := int(math.Round(score * float64(width)))
	if filled > width {
		filled = width
	}

	var barColor lipgloss.Color
	switch {
	case score < 0.2:
		barColor = mColorError
	case score < 0.5:
		barColor = mColorHigh
	case score < 0.8:
		barColor = mColorWarning
	default:
		barColor = mColorSuccess
	}

	filledStyle := lipgloss.NewStyle().Foreground(barColor)
	emptyStyle := lipgloss.NewStyle().Foreground(mColorDim)

	return filledStyle.Render(strings.Repeat("█", filled)) +
		emptyStyle.Render(strings.Repeat("░", width-filled))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─── Command ────────────────────────────────────────────────────────

func newMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor [workspace]",
		Short: "Live investigation dashboard — coverage, gaps, activity, approvals",
		Long: `Open the unified DOGE monitor.

Combines everything you need into one screen:
  • Live command activity
  • Coverage bars
  • Investigation gaps and priorities
  • Learned research patterns
  • Session health
  • Pending approvals (interactive)

Refreshes automatically. Leave it open while you work in 'doge work'.

No separate approvals, logs, runtime, or coverage terminals needed.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wsPath := "."
			if len(args) > 0 {
				wsPath = args[0]
			}
			absPath, _ := filepath.Abs(wsPath)

			model := newMonitorModel(absPath)
			p := tea.NewProgram(model, tea.WithAltScreen())
			_, err := p.Run()
			if model.db != nil {
				model.db.Close()
			}
			return err
		},
	}
	return cmd
}

func getProjectID(state *session.PersistedState, db *sql.DB) uuid.UUID {
	// Try to get the default project ID from the database.
	var id string
	err := db.QueryRow(`SELECT id FROM projects LIMIT 1`).Scan(&id)
	if err == nil {
		parsed, _ := uuid.Parse(id)
		return parsed
	}
	return uuid.Nil
}
