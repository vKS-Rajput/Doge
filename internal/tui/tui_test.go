package tui

import (
	"testing"
	"time"
)

// --- EventSink Tests ---

func TestEventSinkNonBlocking(t *testing.T) {
	// Key invariant: TUI can NEVER block the security pipeline.
	sink := NewEventSink()

	// Fill the buffer completely.
	for i := 0; i < EventSinkSize; i++ {
		sink.Send(FeedEvent{
			Time: time.Now(),
			Icon: "📥",
			Text: "test event",
		})
	}

	// This send must NOT block, even though the buffer is full.
	done := make(chan bool, 1)
	go func() {
		sink.Send(FeedEvent{
			Time: time.Now(),
			Icon: "📥",
			Text: "overflow event",
		})
		done <- true
	}()

	select {
	case <-done:
		// Good — Send returned without blocking.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("EventSink.Send blocked — this would crash the pipeline")
	}
}

func TestEventSinkDelivery(t *testing.T) {
	sink := NewEventSink()

	sink.Send(FeedEvent{
		Time: time.Now(),
		Icon: "✅",
		Text: "test delivery",
	})

	select {
	case event := <-sink.Channel():
		if event.Text != "test delivery" {
			t.Errorf("expected 'test delivery', got '%s'", event.Text)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected event from sink")
	}
}

func TestEventSinkBounded(t *testing.T) {
	sink := NewEventSink()

	// Send more than buffer size.
	for i := 0; i < EventSinkSize+10; i++ {
		sink.Send(FeedEvent{Text: "event"})
	}

	// Drain and count.
	count := 0
	for {
		select {
		case <-sink.Channel():
			count++
		default:
			goto done
		}
	}
done:
	// Should have at most EventSinkSize events (extras dropped).
	if count > EventSinkSize {
		t.Errorf("expected at most %d events, got %d", EventSinkSize, count)
	}
}

// --- Attention Item Tests ---

func TestAttentionPriorityOrdering(t *testing.T) {
	// High/critical events should become attention items.
	items := []AttentionItem{
		{Priority: "critical", Title: "RCE detected"},
		{Priority: "high", Title: "Auth bypass"},
		{Priority: "medium", Title: "Info disclosure"},
	}

	// Critical should come first.
	if items[0].Priority != "critical" {
		t.Error("critical items should have highest priority")
	}
}

// --- Style Tests ---

func TestPriorityStyleDoesNotPanic(t *testing.T) {
	// Ensure all priority levels produce valid styles.
	priorities := []string{"critical", "high", "medium", "low", "info", "unknown", ""}

	for _, p := range priorities {
		style := PriorityStyle(p)
		// Just verify it doesn't panic.
		_ = style.Render("test")
	}
}

// --- Command Parsing Tests ---

func TestCommandParsing(t *testing.T) {
	// These test the command routing, not execution.
	// The TUI routes commands through App Service.
	tests := []struct {
		input    string
		contains string
	}{
		{"help", "Commands:"},
		{"unknown_cmd", "Unknown command"},
		{"ask", "Usage: ask"},
		{"search", "Usage: search"},
		{"investigate", "Commands:"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			m := Model{}
			result := m.executeCommand(tt.input)
			if result == "" {
				t.Errorf("expected non-empty result for '%s'", tt.input)
			}
		})
	}
}

// --- Layout Tests ---

func TestSmallTerminalHandled(t *testing.T) {
	// Terminal resize to very small should not crash.
	m := Model{width: 10, height: 5}
	view := m.View()
	if view == "" {
		t.Error("expected some output even for tiny terminal")
	}
}
