package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vKS-Rajput/doge/internal/app"
	"github.com/vKS-Rajput/doge/internal/memory"
)

// Pane identifies which pane has focus.
type Pane int

const (
	PaneLiveFeed Pane = iota
	PaneResearch
	PanePipeline
	PaneAttention
	PaneWorkspace
	PaneInput
)

// Model is the top-level Bubble Tea model for the Research Cockpit.
//
// The TUI is a PRESENTATION LAYER:
//   - Queries data via App Service (never DB directly)
//   - Receives events via bounded EventSink (never blocks pipeline)
//   - Routes commands through existing application services
type Model struct {
	app  *app.App
	mem  *memory.Service
	sink *EventSink
	ctx  context.Context

	// Pane state.
	focus     Pane
	liveFeed  []FeedEvent
	research  *memory.InvestigationState
	attention []AttentionItem
	workspace *memory.WorkspaceSummary

	// Input.
	input     InputField
	lastCmd   string
	cmdResult string

	// Layout.
	width  int
	height int

	// Timing.
	lastRefresh time.Time
}

// AttentionItem is a prioritized item needing researcher attention.
type AttentionItem struct {
	Icon     string
	Priority string
	Title    string
	Source   string
}

// feedTickMsg triggers reading from the event sink.
type feedTickMsg struct{}

// refreshTickMsg triggers periodic data refresh.
type refreshTickMsg struct{}

// NewModel creates the cockpit model.
func NewModel(application *app.App, mem *memory.Service, sink *EventSink, ctx context.Context) Model {
	input := NewInputField()
	input.SetPlaceholder("ask, search, investigate, task, quit")
	input.Focus()

	return Model{
		app:      application,
		mem:      mem,
		sink:     sink,
		ctx:      ctx,
		focus:    PaneInput,
		liveFeed: []FeedEvent{},
		input:    input,
		width:    80,
		height:   24,
	}
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tickFeed(),
		tickRefresh(),
	)
}

func tickFeed() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return feedTickMsg{}
	})
}

func tickRefresh() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return refreshTickMsg{}
	})
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		key := msg.String()

		switch key {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "tab":
			m.focus = (m.focus + 1) % 6
			if m.focus == PaneInput {
				m.input.Focus()
			} else {
				m.input.Blur()
			}
		case "enter":
			if m.focus == PaneInput && m.input.Value() != "" {
				cmd := m.input.Value()
				m.input.SetValue("")
				result := m.executeCommand(cmd)
				if result == "EXIT" {
					return m, tea.Quit
				}
				m.lastCmd = cmd
				m.cmdResult = result
			}
		default:
			// Route to input field.
			if m.focus == PaneInput {
				if !m.input.HandleKey(key) {
					// Try inserting as rune.
					runes := msg.Runes
					for _, r := range runes {
						m.input.InsertRune(r)
					}
				}
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case feedTickMsg:
		m.drainSink()
		cmds = append(cmds, tickFeed())

	case refreshTickMsg:
		m.refreshData()
		cmds = append(cmds, tickRefresh())
	}

	return m, tea.Batch(cmds...)
}

// View renders the cockpit.
func (m Model) View() string {
	if m.width < 40 || m.height < 10 {
		return "Terminal too small. Resize to at least 80x24."
	}

	// Title bar.
	title := TitleBarStyle.Width(m.width).Render(
		"🐕 DOGE Research Cockpit                              v0.9.9")

	// Calculate pane dimensions.
	paneW := (m.width - 2) / 2
	paneH := (m.height - 8) / 2
	if paneH < 3 {
		paneH = 3
	}

	// Five panes.
	topLeft := m.renderLiveFeed(paneW, paneH)
	topRight := m.renderResearch(paneW, paneH)
	midLeft := m.renderPipeline(paneW, paneH)
	midRight := m.renderAttention(paneW, paneH)
	bottomFull := m.renderWorkspace(m.width-2, 4)

	topRow := lipgloss.JoinHorizontal(lipgloss.Top, topLeft, topRight)
	midRow := lipgloss.JoinHorizontal(lipgloss.Top, midLeft, midRight)
	panes := lipgloss.JoinVertical(lipgloss.Left, topRow, midRow, bottomFull)

	// Command input.
	inputBar := m.renderInput()

	// Status bar.
	status := StatusBarStyle.Width(m.width).Render(
		fmt.Sprintf(" Tab: pane | Enter: cmd | pipeline/approve/candidates/findings/report    %s",
			DimText.Render(time.Now().Format("15:04:05"))))

	return lipgloss.JoinVertical(lipgloss.Left,
		title, panes, inputBar, status)
}

// --- Pane renderers ---

func (m Model) renderLiveFeed(w, h int) string {
	style := PaneStyle.Width(w).Height(h)
	if m.focus == PaneLiveFeed {
		style = FocusedPaneStyle.Width(w).Height(h)
	}

	header := HeaderStyle.Render("📡 Live Events")
	var lines []string

	// Show most recent events (bottom of feed).
	start := 0
	maxLines := h - 2
	if maxLines < 1 {
		maxLines = 1
	}
	if len(m.liveFeed) > maxLines {
		start = len(m.liveFeed) - maxLines
	}

	for _, e := range m.liveFeed[start:] {
		ts := DimText.Render(e.Time.Format("15:04:05"))
		text := PriorityStyle(e.Priority).Render(fmt.Sprintf("%s %s", e.Icon, e.Text))
		lines = append(lines, fmt.Sprintf("%s %s", ts, text))
	}

	if len(lines) == 0 {
		lines = append(lines, DimText.Render("Waiting for events..."))
	}

	content := header + "\n" + strings.Join(lines, "\n")
	return style.Render(content)
}

func (m Model) renderResearch(w, h int) string {
	style := PaneStyle.Width(w).Height(h)
	if m.focus == PaneResearch {
		style = FocusedPaneStyle.Width(w).Height(h)
	}

	header := HeaderStyle.Render("🔬 Investigation")
	var lines []string

	if m.research != nil {
		inv := m.research.Investigation
		lines = append(lines, BrightText.Render(inv.Title))
		lines = append(lines, AccentText.Render(fmt.Sprintf("Status: %s", strings.ToUpper(string(inv.Status)))))
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("Hypotheses  %s",
			AccentText.Render(fmt.Sprintf("%d active / %d", m.research.Stats.HypothesesActive, m.research.Stats.HypothesesTotal))))
		lines = append(lines, fmt.Sprintf("Findings    %s",
			SuccessText.Render(fmt.Sprintf("%d", m.research.Stats.FindingsTotal))))
		lines = append(lines, fmt.Sprintf("Tasks       %s",
			WarningText.Render(fmt.Sprintf("%d pending / %d", m.research.Stats.TasksPending, m.research.Stats.TasksTotal))))
		lines = append(lines, fmt.Sprintf("Surfaces    %s",
			InfoText.Render(fmt.Sprintf("%d / %d tested", m.research.Stats.SurfacesTested, m.research.Stats.SurfacesTotal))))
	} else {
		lines = append(lines, DimText.Render("No active investigation"))
		lines = append(lines, DimText.Render(""))
		lines = append(lines, DimText.Render("Start one with:"))
		lines = append(lines, DimText.Render("investigate start \"Title\""))
	}

	content := header + "\n" + strings.Join(lines, "\n")
	return style.Render(content)
}

func (m Model) renderPipeline(w, h int) string {
	style := PaneStyle.Width(w).Height(h)
	if m.focus == PanePipeline {
		style = FocusedPaneStyle.Width(w).Height(h)
	}

	header := HeaderStyle.Render("🔬 Pipeline")
	var lines []string

	lines = append(lines, RenderTag(TagObserved)+" → "+
		RenderTag(TagCorrelated)+" → "+
		RenderTag(TagNovel))
	lines = append(lines, RenderTag(TagOpportunity)+" → "+
		RenderTag(TagHypothesis))
	lines = append(lines, RenderTag(TagAwaitingApproval))
	lines = append(lines, RenderTag(TagValidated)+" → "+
		RenderTag(TagCandidate))
	lines = append(lines, RenderTag(TagAwaitingConfirm))
	lines = append(lines, RenderTag(TagConfirmedFinding))

	content := header + "\n" + strings.Join(lines, "\n")
	return style.Render(content)
}

func (m Model) renderAttention(w, h int) string {
	style := PaneStyle.Width(w).Height(h)
	if m.focus == PaneAttention {
		style = FocusedPaneStyle.Width(w).Height(h)
	}

	header := HeaderStyle.Render("🔥 Attention")
	var lines []string

	if len(m.attention) > 0 {
		maxLines := h - 2
		if maxLines < 1 {
			maxLines = 1
		}
		for i, item := range m.attention {
			if i >= maxLines {
				break
			}
			text := PriorityStyle(item.Priority).Render(
				fmt.Sprintf("%s [%s] %s", item.Icon, strings.ToUpper(item.Priority), item.Title))
			lines = append(lines, text)
		}
	} else {
		lines = append(lines, DimText.Render("Nothing requires attention"))
	}

	content := header + "\n" + strings.Join(lines, "\n")
	return style.Render(content)
}

func (m Model) renderWorkspace(w, h int) string {
	style := PaneStyle.Width(w).Height(h)
	if m.focus == PaneWorkspace {
		style = FocusedPaneStyle.Width(w).Height(h)
	}

	header := HeaderStyle.Render("📊 Workspace")
	var lines []string

	if m.workspace != nil {
		lines = append(lines, fmt.Sprintf("Entities       %s", AccentText.Render(fmt.Sprintf("%d", m.workspace.EntityCount))))
		lines = append(lines, fmt.Sprintf("Relations      %s", AccentText.Render(fmt.Sprintf("%d", m.workspace.RelationshipCount))))
		lines = append(lines, fmt.Sprintf("Observations   %s", AccentText.Render(fmt.Sprintf("%d", m.workspace.ObservationCount))))
		lines = append(lines, fmt.Sprintf("Insights       %s", AccentText.Render(fmt.Sprintf("%d", m.workspace.InsightCount))))
		lines = append(lines, fmt.Sprintf("Tasks          %s", AccentText.Render(fmt.Sprintf("%d", m.workspace.TaskCount))))
		lines = append(lines, fmt.Sprintf("Investigations %s", AccentText.Render(fmt.Sprintf("%d", m.workspace.InvestigationCount))))
	} else {
		lines = append(lines, DimText.Render("Loading..."))
	}

	content := header + "\n" + strings.Join(lines, "\n")
	return style.Render(content)
}

func (m Model) renderInput() string {
	style := InputStyle.Width(m.width - 4)

	prompt := AccentText.Render("> ")
	input := prompt + m.input.View()

	if m.cmdResult != "" {
		input += "\n" + DimText.Render(m.cmdResult)
	}

	return style.Render(input)
}

// --- Data operations ---

func (m *Model) drainSink() {
	for {
		select {
		case event := <-m.sink.Channel():
			m.liveFeed = append(m.liveFeed, event)
			// Keep feed bounded.
			if len(m.liveFeed) > 100 {
				m.liveFeed = m.liveFeed[len(m.liveFeed)-100:]
			}
			// Build attention from high-priority events.
			if event.Priority == "high" || event.Priority == "critical" {
				m.attention = append([]AttentionItem{{
					Icon:     event.Icon,
					Priority: event.Priority,
					Title:    event.Text,
					Source:   "live",
				}}, m.attention...)
				if len(m.attention) > 20 {
					m.attention = m.attention[:20]
				}
			}
		default:
			return
		}
	}
}

func (m *Model) refreshData() {
	// Refresh investigation state via App Service.
	if m.mem != nil {
		inv, err := m.mem.ActiveInvestigation(m.ctx, m.app.DefaultProjectID)
		if err == nil && inv != nil {
			state, err := m.mem.GetInvestigationState(m.ctx, inv.ID)
			if err == nil {
				m.research = state
			}
		}

		ws, err := m.mem.GetWorkspaceSummary(m.ctx, m.app.DefaultProjectID)
		if err == nil {
			m.workspace = ws
		}
	}

	m.lastRefresh = time.Now()
}

// --- Command execution (routes through App Service) ---

func (m *Model) executeCommand(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	switch parts[0] {
	case "quit", "q", "exit":
		return "EXIT"
	case "ask":
		if len(parts) < 2 {
			return "Usage: ask <question>"
		}
		question := strings.Join(parts[1:], " ")
		return fmt.Sprintf("Run: doge ask \"%s\"", question)
	case "search":
		if len(parts) < 2 {
			return "Usage: search <query>"
		}
		query := strings.Join(parts[1:], " ")
		results, err := m.app.Search(m.ctx, query, 5)
		if err != nil {
			return fmt.Sprintf("Error: %s", err)
		}
		if len(results) == 0 {
			return "No results found."
		}
		var lines []string
		for _, r := range results {
			lines = append(lines, fmt.Sprintf("  %s: %s", r.Type, r.Title))
		}
		return strings.Join(lines, "\n")
	case "investigate":
		if len(parts) < 2 {
			return "Commands: status, hypothesize, surface, conclude"
		}
		return fmt.Sprintf("Run: doge investigate %s", strings.Join(parts[1:], " "))
	case "pipeline":
		return "Pipeline: observations → correlations → surface → novelty → opportunity → reasoning → [APPROVAL] → validation → re-evaluation → [CONFIRMATION] → finding → report"
	case "approve":
		if len(parts) < 2 {
			return "Usage: approve <hypothesis-id>"
		}
		return fmt.Sprintf("Run: doge approve %s", parts[1])
	case "deny":
		if len(parts) < 2 {
			return "Usage: deny <hypothesis-id>"
		}
		return fmt.Sprintf("Run: doge deny %s", parts[1])
	case "confirm":
		if len(parts) < 2 {
			return "Usage: confirm <candidate-id>"
		}
		return fmt.Sprintf("Run: doge confirm %s", parts[1])
	case "reject":
		if len(parts) < 2 {
			return "Usage: reject <candidate-id>"
		}
		return fmt.Sprintf("Run: doge reject %s", parts[1])
	case "candidates":
		return "Run: doge candidates list"
	case "findings":
		return "Run: doge findings list"
	case "report":
		return "Run: doge report generate"
	case "help":
		return "Commands: ask, search, investigate, pipeline, approve, deny, confirm, reject, candidates, findings, report, quit"
	default:
		return fmt.Sprintf("Unknown command: %s. Type 'help' for commands.", parts[0])
	}
}
