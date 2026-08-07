package bus

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/logging"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// newTestBus creates a bus with a small queue for testing.
func newTestBus(queueSize int) *Bus {
	return New(Options{
		QueueSize: queueSize,
		Logger:    logging.NewNop(),
	})
}

func TestSubscribeAndPublish(t *testing.T) {
	b := newTestBus(16)
	b.Start()
	defer b.Drain()

	received := make(chan events.Event, 1)
	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		received <- e
		return nil
	})

	evt := events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
		Value:     "admin.example.com",
		Type:      "subdomain",
	}
	b.Publish(context.Background(), evt)

	select {
	case got := <-received:
		ec, ok := got.(events.EntityCreated)
		if !ok {
			t.Fatalf("expected EntityCreated, got %T", got)
		}
		if ec.Value != "admin.example.com" {
			t.Errorf("Value = %q, want 'admin.example.com'", ec.Value)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event delivery")
	}
}

func TestMultipleSubscribersReceiveEvent(t *testing.T) {
	b := newTestBus(16)
	b.Start()
	defer b.Drain()

	var count atomic.Int32
	for i := 0; i < 3; i++ {
		b.Subscribe(events.TopicObservationCreated, func(ctx context.Context, e events.Event) error {
			count.Add(1)
			return nil
		})
	}

	b.Publish(context.Background(), events.ObservationCreated{
		BaseEvent: events.NewBaseEvent(),
	})

	// Wait for delivery.
	time.Sleep(50 * time.Millisecond)

	if got := count.Load(); got != 3 {
		t.Errorf("expected 3 handlers called, got %d", got)
	}
}

func TestTopicIsolation(t *testing.T) {
	b := newTestBus(16)
	b.Start()
	defer b.Drain()

	entityCalled := make(chan struct{}, 1)
	observationCalled := make(chan struct{}, 1)

	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		entityCalled <- struct{}{}
		return nil
	})
	b.Subscribe(events.TopicObservationCreated, func(ctx context.Context, e events.Event) error {
		observationCalled <- struct{}{}
		return nil
	})

	// Publish only to entity topic.
	b.Publish(context.Background(), events.EntityCreated{
		BaseEvent: events.NewBaseEvent(),
	})

	select {
	case <-entityCalled:
		// Expected.
	case <-time.After(time.Second):
		t.Fatal("entity handler not called")
	}

	// Observation handler should NOT have been called.
	select {
	case <-observationCalled:
		t.Fatal("observation handler should not be called for entity event")
	case <-time.After(50 * time.Millisecond):
		// Expected — not called.
	}
}

func TestUnsubscribe(t *testing.T) {
	b := newTestBus(16)
	b.Start()
	defer b.Drain()

	var count atomic.Int32
	subID := b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		count.Add(1)
		return nil
	})

	// Publish first event — should be received.
	b.Publish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})
	time.Sleep(50 * time.Millisecond)

	if got := count.Load(); got != 1 {
		t.Fatalf("expected 1 call before unsubscribe, got %d", got)
	}

	// Unsubscribe.
	removed := b.Unsubscribe(subID)
	if !removed {
		t.Fatal("Unsubscribe should return true")
	}

	// Publish second event — should NOT be received.
	b.Publish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})
	time.Sleep(50 * time.Millisecond)

	if got := count.Load(); got != 1 {
		t.Errorf("expected 1 call after unsubscribe, got %d", got)
	}
}

func TestUnsubscribe_NonexistentID(t *testing.T) {
	b := newTestBus(16)

	removed := b.Unsubscribe("nonexistent-id")
	if removed {
		t.Error("Unsubscribe should return false for unknown ID")
	}
}

func TestHandlerError_DoesNotStopPipeline(t *testing.T) {
	// This is the dead-letter invariant: one handler's failure
	// must never stop other handlers from being called.
	b := newTestBus(16)
	b.Start()
	defer b.Drain()

	var secondCalled atomic.Bool

	// First handler errors.
	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		return errors.New("handler failure")
	})

	// Second handler should still be called.
	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		secondCalled.Store(true)
		return nil
	})

	b.Publish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})
	time.Sleep(50 * time.Millisecond)

	if !secondCalled.Load() {
		t.Error("second handler should be called even if first handler errored")
	}

	_, _, errs := b.Stats()
	if errs != 1 {
		t.Errorf("expected 1 error in stats, got %d", errs)
	}
}

func TestHandlerPanic_DoesNotCrashDispatcher(t *testing.T) {
	// Invariant: a panicking handler must never crash the bus.
	b := newTestBus(16)
	b.Start()
	defer b.Drain()

	var secondCalled atomic.Bool

	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		panic("handler panic!")
	})

	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		secondCalled.Store(true)
		return nil
	})

	b.Publish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})
	time.Sleep(50 * time.Millisecond)

	if !secondCalled.Load() {
		t.Error("second handler should be called even if first handler panicked")
	}
}

func TestDrain_ProcessesRemainingEvents(t *testing.T) {
	b := newTestBus(64)
	b.Start()

	var count atomic.Int32

	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		count.Add(1)
		return nil
	})

	// Publish multiple events.
	for i := 0; i < 10; i++ {
		b.Publish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})
	}

	// Drain should process all 10.
	b.Drain()

	if got := count.Load(); got != 10 {
		t.Errorf("expected 10 events processed after Drain, got %d", got)
	}
}

func TestStats(t *testing.T) {
	b := newTestBus(16)
	b.Start()

	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		return nil
	})
	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		return errors.New("fail")
	})

	b.Publish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})

	b.Drain()

	published, delivered, errs := b.Stats()
	if published != 1 {
		t.Errorf("published = %d, want 1", published)
	}
	if delivered != 2 {
		t.Errorf("delivered = %d, want 2 (two subscribers)", delivered)
	}
	if errs != 1 {
		t.Errorf("errors = %d, want 1", errs)
	}
}

func TestTryPublish_FullQueue(t *testing.T) {
	b := newTestBus(1) // Tiny queue.
	// Don't start the bus — no consumer, so queue will fill.

	// First should succeed (queue has 1 slot).
	ok := b.TryPublish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})
	if !ok {
		t.Error("first TryPublish should succeed")
	}

	// Second should fail (queue full, no consumer).
	ok = b.TryPublish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})
	if ok {
		t.Error("second TryPublish should fail (queue full)")
	}
}

func TestConcurrentPublish(t *testing.T) {
	b := newTestBus(256)
	b.Start()

	var count atomic.Int32
	b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
		count.Add(1)
		return nil
	})

	// Publish from multiple goroutines concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Publish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})
		}()
	}
	wg.Wait()

	b.Drain()

	if got := count.Load(); got != 20 {
		t.Errorf("expected 20 events delivered, got %d", got)
	}
}

func TestStartPanicsOnDoubleCall(t *testing.T) {
	b := newTestBus(16)
	b.Start()
	defer b.Drain()

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on double Start()")
		}
	}()

	b.Start() // Should panic.
}

func TestNoSubscribers_EventDroppedSilently(t *testing.T) {
	b := newTestBus(16)
	b.Start()

	// Publish with no subscribers — should not error or panic.
	b.Publish(context.Background(), events.EntityCreated{BaseEvent: events.NewBaseEvent()})

	b.Drain()

	published, delivered, _ := b.Stats()
	if published != 1 {
		t.Errorf("published = %d, want 1", published)
	}
	if delivered != 0 {
		t.Errorf("delivered = %d, want 0 (no subscribers)", delivered)
	}
}
