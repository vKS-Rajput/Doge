package tui

import (
	"time"
)

// EventSinkSize is the bounded buffer size for the TUI event sink.
// If the buffer is full, new events are dropped (never block the pipeline).
const EventSinkSize = 256

// FeedEvent is a single entry in the live feed.
type FeedEvent struct {
	Time     time.Time
	Icon     string
	Text     string
	Priority string // "critical", "high", "medium", "low", "info"
}

// EventSink is a bounded, non-blocking channel for delivering
// events from the watch pipeline to the TUI.
//
// Key rule: the TUI must NEVER block the security pipeline.
// If the sink is full, events are silently dropped.
type EventSink struct {
	ch chan FeedEvent
}

// NewEventSink creates a bounded event sink.
func NewEventSink() *EventSink {
	return &EventSink{
		ch: make(chan FeedEvent, EventSinkSize),
	}
}

// Send attempts to deliver an event. Non-blocking.
// If the buffer is full, the event is dropped.
func (s *EventSink) Send(event FeedEvent) {
	select {
	case s.ch <- event:
	default:
		// Buffer full — drop the event.
		// The TUI is a presentation layer; dropping UI events
		// is acceptable. The evidence pipeline is unaffected.
	}
}

// Channel returns the receive-only channel for the TUI to consume.
func (s *EventSink) Channel() <-chan FeedEvent {
	return s.ch
}
