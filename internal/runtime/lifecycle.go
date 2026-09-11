package runtime

import (
	"fmt"
	"sync"
	"time"
)

// LifecycleState indicates the current machine status of DOGE Runtime.
type LifecycleState string

const (
	StateUninitialized LifecycleState = "UNINITIALIZED"
	StateStarting      LifecycleState = "STARTING"
	StateReady         LifecycleState = "READY"
	StateResearching   LifecycleState = "RESEARCHING"
	StatePaused        LifecycleState = "PAUSED"
	StateStopping      LifecycleState = "STOPPING"
	StateStopped       LifecycleState = "STOPPED"
)

// LifecycleManager manages thread-safe state machine transitions.
type LifecycleManager struct {
	mu          sync.RWMutex
	state       LifecycleState
	broadcaster *EventBroadcaster
	startedAt   time.Time
	pausedAt    time.Time
}

// NewLifecycleManager creates a lifecycle manager.
func NewLifecycleManager(b *EventBroadcaster) *LifecycleManager {
	return &LifecycleManager{
		state:       StateUninitialized,
		broadcaster: b,
	}
}

// GetState returns the current lifecycle state.
func (m *LifecycleManager) GetState() LifecycleState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// TransitionTo validates and performs a state transition.
func (m *LifecycleManager) TransitionTo(target LifecycleState, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.state

	if !isValidTransition(current, target) {
		return fmt.Errorf("invalid lifecycle transition from %s to %s", current, target)
	}

	m.state = target

	switch target {
	case StateStarting:
		m.startedAt = time.Now().UTC()
	case StatePaused:
		m.pausedAt = time.Now().UTC()
	case StateStopped:
		// Completed
	}

	if m.broadcaster != nil {
		var evtType EventType
		switch target {
		case StateStarting:
			evtType = EventRuntimeStarting
		case StateReady:
			evtType = EventRuntimeReady
		case StateResearching:
			evtType = EventRuntimeResearching
		case StatePaused:
			evtType = EventRuntimePaused
		case StateStopped:
			evtType = EventRuntimeStopped
		}
		if evtType != "" {
			m.broadcaster.Broadcast(evtType, "lifecycle", fmt.Sprintf("State transitioned from %s to %s (%s)", current, target, reason), map[string]any{
				"previous_state": string(current),
				"current_state":  string(target),
				"reason":         reason,
			})
		}
	}

	return nil
}

func isValidTransition(from, to LifecycleState) bool {
	if from == to {
		return true
	}
	switch from {
	case StateUninitialized:
		return to == StateStarting
	case StateStarting:
		return to == StateReady || to == StateStopped
	case StateReady:
		return to == StateResearching || to == StateStopping || to == StateStopped
	case StateResearching:
		return to == StatePaused || to == StateReady || to == StateStopping || to == StateStopped
	case StatePaused:
		return to == StateResearching || to == StateReady || to == StateStopping || to == StateStopped
	case StateStopping:
		return to == StateStopped
	case StateStopped:
		return to == StateStarting // allow restart
	default:
		return false
	}
}
