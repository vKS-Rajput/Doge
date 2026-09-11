package desktop

import (
	"context"
	"sync"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/vKS-Rajput/doge/internal/runtime"
)

// EventsBridge subscribes to internal/runtime events and forwards them natively to Wails.
type EventsBridge struct {
	mu          sync.Mutex
	ctx         context.Context
	broadcaster *runtime.EventBroadcaster
	subChan     chan runtime.RuntimeEvent
	stopChan    chan struct{}
}

// NewEventsBridge creates a bridge between the Go runtime event bus and the Wails desktop frontend.
func NewEventsBridge(ctx context.Context, b *runtime.EventBroadcaster) *EventsBridge {
	return &EventsBridge{
		ctx:         ctx,
		broadcaster: b,
		stopChan:    make(chan struct{}),
	}
}

// Start begins forwarding events to the frontend.
func (b *EventsBridge) Start() {
	if b.broadcaster == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.subChan = b.broadcaster.Subscribe(256)

	go func() {
		for {
			select {
			case <-b.stopChan:
				return
			case evt, ok := <-b.subChan:
				if !ok {
					return
				}
				if b.ctx != nil {
					wailsRuntime.EventsEmit(b.ctx, "doge:event", evt)
				}
			}
		}
	}()
}

// Stop cleanly unsubscribes and terminates the forwarding loop.
func (b *EventsBridge) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()

	select {
	case <-b.stopChan:
		// already closed
	default:
		close(b.stopChan)
	}

	if b.broadcaster != nil && b.subChan != nil {
		b.broadcaster.Unsubscribe(b.subChan)
	}
}
