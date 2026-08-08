package watch

import (
	"context"
	"sync"
	"time"
)

// ChangeEvent represents a single file processing result.
type ChangeEvent struct {
	FilePath     string
	FileName     string
	Observations int
	Duplicates   int
	ParserUsed   string
	IsDuplicate  bool
	Duration     time.Duration
	Timestamp    time.Time
}

// ChangeSummary aggregates multiple ChangeEvents into a single
// logical change window. This prevents 10 rapid file writes
// from producing 10 noisy notifications.
type ChangeSummary struct {
	// Counts.
	Files        int `json:"files"`
	Observations int `json:"observations"`
	Duplicates   int `json:"duplicates"`

	// Semantic items (notable changes).
	Items []ChangeItem `json:"items"`

	// Timing.
	WindowStart time.Time     `json:"window_start"`
	WindowEnd   time.Time     `json:"window_end"`
	Duration    time.Duration `json:"duration"`

	// Source events.
	Events []ChangeEvent `json:"-"`
}

// ChangeItem represents a single notable semantic change.
type ChangeItem struct {
	Type     ChangeItemType `json:"type"`
	Category string         `json:"category"` // entity type, insight category, etc.
	Value    string         `json:"value"`     // the actual thing that changed
	Priority string         `json:"priority"`  // "high", "medium", "low", "info"
}

// ChangeItemType classifies what kind of semantic change occurred.
type ChangeItemType string

const (
	ChangeAdded    ChangeItemType = "added"
	ChangeRemoved  ChangeItemType = "removed"
	ChangeModified ChangeItemType = "modified"
)

// Aggregator batches rapid file events into logical change windows.
//
// When a tool writes a file multiple times in quick succession,
// the aggregator collects all events within the window duration
// and produces a single ChangeSummary.
type Aggregator struct {
	window  time.Duration
	display *Display
	trigger *TriggerPolicy

	mu      sync.Mutex
	pending []ChangeEvent
	timer   *time.Timer
	ctx     context.Context
}

// NewAggregator creates a new event aggregator.
func NewAggregator(window time.Duration, display *Display, trigger *TriggerPolicy) *Aggregator {
	return &Aggregator{
		window:  window,
		display: display,
		trigger: trigger,
	}
}

// Start initializes the aggregator context.
func (a *Aggregator) Start(ctx context.Context) {
	a.ctx = ctx
}

// Add adds a change event to the current aggregation window.
// If this is the first event, it starts the window timer.
// Subsequent events within the window extend the timer.
func (a *Aggregator) Add(event ChangeEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pending = append(a.pending, event)

	// Reset or start the flush timer.
	if a.timer != nil {
		a.timer.Stop()
	}
	a.timer = time.AfterFunc(a.window, a.flush)
}

// Flush forces immediate processing of pending events.
// Called during graceful shutdown.
func (a *Aggregator) Flush() {
	a.flush()
}

func (a *Aggregator) flush() {
	a.mu.Lock()
	if len(a.pending) == 0 {
		a.mu.Unlock()
		return
	}

	events := make([]ChangeEvent, len(a.pending))
	copy(events, a.pending)
	a.pending = a.pending[:0]
	a.mu.Unlock()

	// Build summary.
	summary := a.buildSummary(events)

	// Display the summary.
	a.display.ChangeSummary(summary)

	// Evaluate AI trigger policy.
	if a.trigger != nil {
		result := a.trigger.Evaluate(summary)
		if result.ShouldSuggest {
			a.display.AITriggered(result.Reason)
		}
	}
}

func (a *Aggregator) buildSummary(events []ChangeEvent) ChangeSummary {
	summary := ChangeSummary{
		Events:      events,
		WindowStart: events[0].Timestamp,
		WindowEnd:   events[len(events)-1].Timestamp,
	}

	for _, e := range events {
		if e.IsDuplicate {
			summary.Duplicates++
			continue
		}
		summary.Files++
		summary.Observations += e.Observations
		summary.Duplicates += e.Duplicates
		summary.Duration += e.Duration
	}

	return summary
}
