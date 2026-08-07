// Package bus provides an in-process, channel-based pub/sub event bus.
//
// The Event Bus is the async backbone of the workspace. All communication
// on the write path flows through it:
//
//	File Watcher → Event Bus → Artifact Store → Event Bus → Parser →
//	Event Bus → Observation Engine → Event Bus → Knowledge Graph → ...
//
// Modules never call each other directly. They publish events and
// subscribe to topics. The Event Bus is the traffic controller.
//
// Design:
//   - A single bounded channel serves as the event queue (backpressure)
//   - A single dispatch goroutine reads events and fans out to subscribers
//   - Events are delivered in publish order within a topic
//   - Failed handlers are logged (dead-letter) but don't stop the pipeline
//   - Drain() blocks until the queue is empty and all handlers complete
//
// Usage:
//
//	b := bus.New(bus.Options{QueueSize: 256, Logger: logger})
//	b.Start()
//
//	subID := b.Subscribe(events.TopicEntityCreated, func(ctx context.Context, e events.Event) error {
//	    entity := e.(events.EntityCreated)
//	    // handle ...
//	    return nil
//	})
//
//	b.Publish(ctx, events.EntityCreated{...})
//
//	b.Unsubscribe(subID)
//	b.Drain() // Wait for all pending events
package bus

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/events"
)

// Handler processes an event. Handlers should complete quickly.
// Long-running work should be dispatched to a separate goroutine
// by the handler itself.
//
// If a handler returns an error, the error is logged (dead-letter)
// and dispatch continues to the next subscriber. One handler's
// failure never blocks another handler or stops the pipeline.
type Handler func(ctx context.Context, event events.Event) error

// SubscriptionID uniquely identifies a subscription. Used to
// unsubscribe later.
type SubscriptionID string

// Options configures the Event Bus.
type Options struct {
	// QueueSize is the capacity of the internal event channel.
	// When the queue is full, Publish blocks until space is available
	// (backpressure). Default: 256.
	QueueSize int

	// Logger is used for dead-letter logging and operational messages.
	// If nil, a no-op logger is used.
	Logger *slog.Logger
}

// Bus is the in-process pub/sub event backbone.
type Bus struct {
	mu            sync.RWMutex
	subscriptions map[events.Topic][]subscription
	queue         chan envelope
	logger        *slog.Logger
	done          chan struct{}       // Signals the dispatch goroutine to drain and stop.
	stopped       chan struct{}       // Closed when the dispatch goroutine exits.
	started       atomic.Bool

	// Stats
	published  atomic.Int64
	delivered  atomic.Int64
	errors     atomic.Int64
}

// subscription pairs a handler with its unique ID.
type subscription struct {
	id      SubscriptionID
	handler Handler
}

// envelope wraps an event with its publish context for the dispatch queue.
type envelope struct {
	ctx   context.Context
	event events.Event
}

// New creates a new Event Bus. Call [Start] to begin processing events.
func New(opts Options) *Bus {
	if opts.QueueSize < 1 {
		opts.QueueSize = 256
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Bus{
		subscriptions: make(map[events.Topic][]subscription),
		queue:         make(chan envelope, opts.QueueSize),
		logger:        logger,
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}
}

// Start begins the dispatch goroutine. Must be called exactly once
// before publishing events. Panics if called more than once.
func (b *Bus) Start() {
	if !b.started.CompareAndSwap(false, true) {
		panic("bus: Start called more than once")
	}

	go b.dispatch()
	b.logger.Info("event bus started", "queue_size", cap(b.queue))
}

// Subscribe registers a handler for a specific event topic.
// Returns a [SubscriptionID] that can be used to unsubscribe later.
//
// Multiple handlers can subscribe to the same topic. All handlers
// for a topic are called in subscription order when an event is
// published to that topic.
func (b *Bus) Subscribe(topic events.Topic, handler Handler) SubscriptionID {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := SubscriptionID(uuid.New().String())
	b.subscriptions[topic] = append(b.subscriptions[topic], subscription{
		id:      id,
		handler: handler,
	})

	b.logger.Debug("subscription added",
		"topic", string(topic),
		"subscription_id", string(id),
	)

	return id
}

// Unsubscribe removes a previously registered handler.
// Returns true if the subscription was found and removed.
func (b *Bus) Unsubscribe(id SubscriptionID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	for topic, subs := range b.subscriptions {
		for i, s := range subs {
			if s.id == id {
				b.subscriptions[topic] = append(subs[:i], subs[i+1:]...)
				b.logger.Debug("subscription removed",
					"topic", string(topic),
					"subscription_id", string(id),
				)
				return true
			}
		}
	}
	return false
}

// Publish sends an event to the dispatch queue. The event will be
// delivered to all handlers subscribed to its topic.
//
// If the queue is full, Publish blocks until space is available.
// This is intentional backpressure: it slows down producers when
// consumers can't keep up.
//
// Publish is safe to call from multiple goroutines concurrently.
func (b *Bus) Publish(ctx context.Context, event events.Event) {
	b.queue <- envelope{ctx: ctx, event: event}
	b.published.Add(1)
}

// TryPublish attempts to send an event without blocking.
// Returns false if the queue is full and the event was dropped.
// Use this for non-critical events where dropping is acceptable.
func (b *Bus) TryPublish(ctx context.Context, event events.Event) bool {
	select {
	case b.queue <- envelope{ctx: ctx, event: event}:
		b.published.Add(1)
		return true
	default:
		b.logger.Warn("event dropped (queue full)",
			"topic", string(event.EventTopic()),
			"event_id", event.EventID().String(),
		)
		return false
	}
}

// Drain signals the dispatch goroutine to finish processing all
// pending events and then stop. Blocks until the queue is fully
// drained and all handlers have completed.
//
// After Drain returns, the Bus cannot be reused. Creating a new
// Bus is required if you need to restart event processing.
func (b *Bus) Drain() {
	b.logger.Info("draining event bus")
	close(b.done)
	<-b.stopped
	b.logger.Info("event bus drained",
		"total_published", b.published.Load(),
		"total_delivered", b.delivered.Load(),
		"total_errors", b.errors.Load(),
	)
}

// Stats returns event bus statistics.
func (b *Bus) Stats() (published, delivered, errors int64) {
	return b.published.Load(), b.delivered.Load(), b.errors.Load()
}

// QueueLen returns the number of events currently waiting in the queue.
func (b *Bus) QueueLen() int {
	return len(b.queue)
}

// dispatch is the single goroutine that reads from the queue and
// fans out events to subscribers. It runs until Drain() is called,
// at which point it processes remaining events before exiting.
func (b *Bus) dispatch() {
	defer close(b.stopped)

	for {
		select {
		case env := <-b.queue:
			b.deliverEvent(env)
		case <-b.done:
			// Drain: process any remaining events in the queue.
			b.drainRemaining()
			return
		}
	}
}

// drainRemaining processes all events left in the queue after
// the done signal is received.
func (b *Bus) drainRemaining() {
	for {
		select {
		case env := <-b.queue:
			b.deliverEvent(env)
		default:
			return // Queue is empty.
		}
	}
}

// deliverEvent fans out a single event to all subscribed handlers.
func (b *Bus) deliverEvent(env envelope) {
	topic := env.event.EventTopic()

	b.mu.RLock()
	subs := make([]subscription, len(b.subscriptions[topic]))
	copy(subs, b.subscriptions[topic])
	b.mu.RUnlock()

	for _, sub := range subs {
		if err := b.callHandler(env.ctx, sub, env.event); err != nil {
			b.errors.Add(1)
			b.logger.Error("handler failed (dead-letter)",
				"topic", string(topic),
				"event_id", env.event.EventID().String(),
				"subscription_id", string(sub.id),
				"error", err.Error(),
			)
		}
		b.delivered.Add(1)
	}
}

// callHandler invokes a single handler with panic recovery.
// If the handler panics, it's caught and returned as an error
// so it doesn't crash the dispatch goroutine.
func (b *Bus) callHandler(ctx context.Context, sub subscription, event events.Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler panicked: %v", r)
		}
	}()
	return sub.handler(ctx, event)
}
