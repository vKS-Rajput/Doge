package scope

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ExecutionTicket represents an acquired permission to execute a single tool action.
type ExecutionTicket struct {
	Target       string
	Tool         string
	AcquiredAt   time.Time
	releasedOnce sync.Once
	releaseFn    func()
}

// Release releases the execution slot back to the concurrency pool.
func (t *ExecutionTicket) Release() {
	if t != nil && t.releaseFn != nil {
		t.releasedOnce.Do(t.releaseFn)
	}
}

// RuntimePolicy enforces active runtime rate limiting, concurrency throttling, and fail-closed scope gates.
type RuntimePolicy struct {
	mu          sync.RWMutex
	scopeEngine *ScopeEngine
	semaphore   chan struct{}
	rateTicker  *time.Ticker
	rateTokens  chan struct{}
	stopCh      chan struct{}
}

// NewRuntimePolicy creates a new runtime policy controller for an engagement.
func NewRuntimePolicy(scopeEngine *ScopeEngine) *RuntimePolicy {
	cfg := scopeEngine.Config()
	rateLimit := cfg.Rules.RateLimitPerSec
	if rateLimit <= 0 {
		rateLimit = 10
	}
	concurrency := cfg.Rules.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	p := &RuntimePolicy{
		scopeEngine: scopeEngine,
		semaphore:   make(chan struct{}, concurrency),
		rateTokens:  make(chan struct{}, rateLimit),
		stopCh:      make(chan struct{}),
	}

	// Pre-fill rate tokens
	for i := 0; i < rateLimit; i++ {
		p.rateTokens <- struct{}{}
	}

	// Token generator: replenishes tokens based on rate limit
	interval := time.Second / time.Duration(rateLimit)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	p.rateTicker = time.NewTicker(interval)
	ticker := p.rateTicker
	stopCh := p.stopCh

	go func() {
		for {
			select {
			case <-ticker.C:
				select {
				case p.rateTokens <- struct{}{}:
				default:
					// Token buffer full
				}
			case <-stopCh:
				return
			}
		}
	}()

	return p
}

// Stop shuts down the background rate limiter goroutine.
func (p *RuntimePolicy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rateTicker != nil {
		p.rateTicker.Stop()
		close(p.stopCh)
		p.rateTicker = nil
	}
}

// Acquire requests an authorized execution ticket, enforcing hard scope, prohibited checks, rate limits, and concurrency semaphores.
func (p *RuntimePolicy) Acquire(ctx context.Context, target, tool, actionType string) (*ExecutionTicket, error) {
	// 1. Hard Scope Validation (Fail-closed)
	allowed, reason, _ := p.scopeEngine.ValidateAction(target, tool, actionType)
	if !allowed {
		return nil, fmt.Errorf("runtime policy rejected: %s", reason)
	}

	// 2. Concurrency Semaphore (Blocks if max concurrent actions reached)
	select {
	case p.semaphore <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("timed out waiting for concurrency slot: %w", ctx.Err())
	}

	// 3. Rate Limit Token Bucket
	select {
	case <-p.rateTokens:
	case <-ctx.Done():
		// Release acquired concurrency slot if context cancelled
		<-p.semaphore
		return nil, fmt.Errorf("timed out waiting for rate limit token: %w", ctx.Err())
	}

	ticket := &ExecutionTicket{
		Target:     target,
		Tool:       tool,
		AcquiredAt: time.Now().UTC(),
		releaseFn: func() {
			select {
			case <-p.semaphore:
			default:
			}
		},
	}

	return ticket, nil
}
