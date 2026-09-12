package runtime

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventType categorizes runtime events.
type EventType string

const (
	EventRuntimeStarting       EventType = "runtime:starting"
	EventRuntimeReady          EventType = "runtime:ready"
	EventRuntimeResearching    EventType = "runtime:researching"
	EventRuntimePaused         EventType = "runtime:paused"
	EventRuntimeResumed        EventType = "runtime:resumed"
	EventRuntimeStopped        EventType = "runtime:stopped"
	EventWSLStatusChanged      EventType = "wsl:status_changed"
	EventProcessStarted        EventType = "process:started"
	EventProcessOutput         EventType = "process:output"
	EventProcessExited         EventType = "process:exited"
	EventToolDetected          EventType = "tool:detected"
	EventObservationIngested   EventType = "observation:ingested"
	EventHypothesisGenerated   EventType = "hypothesis:generated"
	EventExperimentSelected    EventType = "experiment:selected"
	EventExperimentExecuted    EventType = "experiment:executed"
	EventFindingProven         EventType = "finding:proven"
	EventProofSealed           EventType = "proof:sealed"
	EventGatePending           EventType = "gate:pending"
	EventGateResolved         EventType = "gate:resolved"
	EventCouncilUpdated        EventType = "council:updated"
)

// RuntimeEvent represents a structured, timestamped system event.
type RuntimeEvent struct {
	ID        uuid.UUID      `json:"id"`
	Type      EventType      `json:"type"`
	Source    string         `json:"source"`
	Message   string         `json:"message"`
	Data      map[string]any `json:"data,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// EventBroadcaster provides pub/sub distribution for runtime telemetry.
type EventBroadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan RuntimeEvent]struct{}
	history     []RuntimeEvent
	maxHistory  int
}

// NewEventBroadcaster creates an event broadcaster.
func NewEventBroadcaster(maxHistory int) *EventBroadcaster {
	if maxHistory <= 0 {
		maxHistory = 1000
	}
	return &EventBroadcaster{
		subscribers: make(map[chan RuntimeEvent]struct{}),
		history:     make([]RuntimeEvent, 0, maxHistory),
		maxHistory:  maxHistory,
	}
}

// Subscribe creates a buffered event channel that receives broadcast events.
func (b *EventBroadcaster) Subscribe(bufferSize int) chan RuntimeEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	if bufferSize <= 0 {
		bufferSize = 64
	}
	ch := make(chan RuntimeEvent, bufferSize)
	b.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes an event channel.
func (b *EventBroadcaster) Unsubscribe(ch chan RuntimeEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// Broadcast dispatches an event to all subscribers and stores it in history.
func (b *EventBroadcaster) Broadcast(eventType EventType, source, message string, data map[string]any) RuntimeEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	event := RuntimeEvent{
		ID:        uuid.New(),
		Type:      eventType,
		Source:    source,
		Message:   message,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	// Add to history
	if len(b.history) >= b.maxHistory {
		b.history = b.history[1:]
	}
	b.history = append(b.history, event)

	// Non-blocking dispatch to subscribers
	for ch := range b.subscribers {
		select {
		case ch <- event:
		default:
			// Buffer full, skip to avoid blocking other subscribers
		}
	}

	return event
}

// History returns a copy of the event history.
func (b *EventBroadcaster) History() []RuntimeEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	res := make([]RuntimeEvent, len(b.history))
	copy(res, b.history)
	return res
}
