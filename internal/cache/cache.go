// Package cache provides an in-memory LRU cache with TTL and
// event-driven invalidation support.
//
// The cache serves two primary use cases in the workspace:
//   - Prompt/response caching: avoid redundant LLM invocations
//     when the same question is asked against unchanged data
//   - Embedding caching: avoid re-computing embeddings for entities
//     that haven't changed
//
// Cache entries are automatically evicted when:
//   - The entry exceeds its TTL
//   - The cache reaches its maximum size (least-recently-used eviction)
//   - An explicit invalidation is triggered (e.g., by an entity.changed event)
//
// The cache is safe for concurrent access.
package cache

import (
	"sync"
	"time"
)

// entry is a single cached value with metadata.
type entry struct {
	value     any
	createdAt time.Time
	expiresAt time.Time
	hitCount  int
	lastHitAt time.Time

	// For LRU tracking: position in the access order.
	key string
}

// isExpired returns true if the entry has exceeded its TTL.
func (e *entry) isExpired(now time.Time) bool {
	if e.expiresAt.IsZero() {
		return false // No TTL set — never expires.
	}
	return now.After(e.expiresAt)
}

// Cache is a thread-safe, in-memory LRU cache with TTL support.
type Cache struct {
	mu         sync.RWMutex
	entries    map[string]*entry
	maxEntries int
	defaultTTL time.Duration

	// accessOrder tracks keys in least-recently-used order.
	// The most recently accessed key is at the end.
	accessOrder []string

	// Stats
	hits   int64
	misses int64
}

// Options configures cache behavior.
type Options struct {
	// MaxEntries is the maximum number of entries before LRU eviction.
	// Must be at least 1.
	MaxEntries int

	// DefaultTTL is the default time-to-live for entries.
	// Zero means entries never expire (only LRU eviction applies).
	DefaultTTL time.Duration
}

// New creates a new cache with the given options.
func New(opts Options) *Cache {
	if opts.MaxEntries < 1 {
		opts.MaxEntries = 1000
	}

	return &Cache{
		entries:     make(map[string]*entry, opts.MaxEntries),
		maxEntries:  opts.MaxEntries,
		defaultTTL:  opts.DefaultTTL,
		accessOrder: make([]string, 0, opts.MaxEntries),
	}
}

// Get retrieves a value from the cache. Returns the value and true if
// found and not expired; returns nil and false otherwise.
// Accessing an entry updates its position in the LRU order.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, exists := c.entries[key]
	if !exists {
		c.misses++
		return nil, false
	}

	if e.isExpired(time.Now()) {
		c.removeLocked(key)
		c.misses++
		return nil, false
	}

	// Update access metadata.
	now := time.Now()
	e.hitCount++
	e.lastHitAt = now
	c.hits++

	// Move to end of access order (most recently used).
	c.touchLocked(key)

	return e.value, true
}

// Set stores a value in the cache with the default TTL.
// If the cache is full, the least-recently-used entry is evicted.
func (c *Cache) Set(key string, value any) {
	c.SetWithTTL(key, value, c.defaultTTL)
}

// SetWithTTL stores a value in the cache with a specific TTL.
// A zero TTL means the entry never expires (only LRU eviction).
func (c *Cache) SetWithTTL(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = now.Add(ttl)
	}

	// If key already exists, update in place.
	if existing, exists := c.entries[key]; exists {
		existing.value = value
		existing.createdAt = now
		existing.expiresAt = expiresAt
		c.touchLocked(key)
		return
	}

	// Evict LRU entry if at capacity.
	if len(c.entries) >= c.maxEntries {
		c.evictLocked()
	}

	c.entries[key] = &entry{
		key:       key,
		value:     value,
		createdAt: now,
		expiresAt: expiresAt,
	}
	c.accessOrder = append(c.accessOrder, key)
}

// Delete removes a specific entry from the cache. Returns true if the
// entry existed.
func (c *Cache) Delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, exists := c.entries[key]
	if exists {
		c.removeLocked(key)
	}
	return exists
}

// Invalidate removes all entries whose keys have the given prefix.
// Returns the number of entries removed. Used for event-driven
// cache invalidation (e.g., when an entity changes, invalidate all
// cache entries related to that entity).
func (c *Cache) Invalidate(prefix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for key := range c.entries {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			c.removeLocked(key)
			removed++
		}
	}
	return removed
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*entry, c.maxEntries)
	c.accessOrder = c.accessOrder[:0]
}

// Len returns the number of entries currently in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Stats returns cache hit/miss statistics.
func (c *Cache) Stats() (hits, misses int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses
}

// evictLocked removes the least-recently-used entry.
// Caller must hold c.mu.
func (c *Cache) evictLocked() {
	if len(c.accessOrder) == 0 {
		return
	}

	// The front of accessOrder is the least-recently-used.
	// Skip entries that were already removed (possible after Invalidate).
	for len(c.accessOrder) > 0 {
		key := c.accessOrder[0]
		c.accessOrder = c.accessOrder[1:]
		if _, exists := c.entries[key]; exists {
			delete(c.entries, key)
			return
		}
	}
}

// removeLocked removes a specific key from entries and accessOrder.
// Caller must hold c.mu.
func (c *Cache) removeLocked(key string) {
	delete(c.entries, key)
	// Remove from accessOrder.
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}
}

// touchLocked moves a key to the end of the access order (most recently used).
// Caller must hold c.mu.
func (c *Cache) touchLocked(key string) {
	// Remove from current position.
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}
	// Add to end.
	c.accessOrder = append(c.accessOrder, key)
}
